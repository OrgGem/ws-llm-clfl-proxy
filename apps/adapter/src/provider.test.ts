import { describe, expect, it } from "vitest";
import { buildProviderPayload, CompletionAccumulator, ProviderStreamConverter } from "./provider.js";
import { SseParser } from "./sse.js";

describe("incremental SSE and provider conversion", () => {
  it("parses Anthropic tool events split at arbitrary chunk boundaries", () => {
    const parser = new SseParser();
    const converter = new ProviderStreamConverter("anthropic");
    const accumulator = new CompletionAccumulator();
    const raw = [
      'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":13}}}\n\n',
      'event: content_block_start\ndata: {"type":"content_block_start","index":4,"content_block":{"type":"tool_use","id":"call_1","name":"lookup","input":{}}}\n\n',
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":4,"delta":{"type":"input_json_delta","partial_json":"{\\"q\\":\\"weather\\"}"}}\n\n',
      'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}\n\n',
      'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ].join("");
    for (let index = 0; index < raw.length; index += 3) {
      for (const event of parser.push(raw.slice(index, index + 3))) {
        for (const update of converter.consume(event)) accumulator.add(update);
      }
    }
    for (const event of parser.finish()) for (const update of converter.consume(event)) accumulator.add(update);
    const result = accumulator.snapshot();
    expect(result.finishReason).toBe("tool_calls");
    expect(result.toolCalls).toEqual([{ id: "call_1", type: "function", function: { name: "lookup", arguments: '{"q":"weather"}' } }]);
    expect(result.usage).toEqual({ prompt_tokens: 13, completion_tokens: 5, total_tokens: 18 });
  });

  it("converts OpenAI usage-only chunks and ignores provider DONE until Gateway terminal", () => {
    const converter = new ProviderStreamConverter("openai");
    expect(converter.consume({ data: "[DONE]" })).toEqual([]);
    expect(converter.completed).toBe(true);
    const updates = converter.consume({ data: JSON.stringify({ choices: [], usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 } }) });
    expect(updates[0]?.usage).toEqual({ prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 });
    expect(converter.usage?.total_tokens).toBe(5);
  });

  it("converts OpenAI tool deltas without losing index or argument fragments", () => {
    const converter = new ProviderStreamConverter("openai");
    const accumulator = new CompletionAccumulator();
    for (const event of [
      { data: JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 2, id: "call_x", type: "function", function: { name: "search", arguments: "{\"q\":" } }] }, finish_reason: null }] }) },
      { data: JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 2, function: { arguments: "\"x\"}" } }] }, finish_reason: "tool_calls" }] }) },
    ]) for (const update of converter.consume(event)) accumulator.add(update);
    expect(accumulator.snapshot().toolCalls).toEqual([{ id: "call_x", type: "function", function: { name: "search", arguments: '{"q":"x"}' } }]);
    expect(accumulator.snapshot().finishReason).toBe("tool_calls");
  });

  it("maps Anthropic tool calls from OpenAI requests and rejects invalid tool JSON", () => {
    const payload = buildProviderPayload("anthropic", {
      model: "alias",
      messages: [
        { role: "system", content: "Be concise." },
        { role: "user", content: "Weather?" },
        { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "lookup", arguments: "{}" } }] },
        { role: "tool", tool_call_id: "call_1", content: "Sunny." },
      ],
      tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object", properties: {} } } }],
      tool_choice: "required",
    });
    expect(payload).toMatchObject({
      system: "Be concise.",
      messages: [
        { role: "user", content: "Weather?" },
        { role: "assistant", content: [{ type: "tool_use", id: "call_1", name: "lookup", input: {} }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "call_1", content: "Sunny." }] },
      ],
      tool_choice: { type: "any" },
    });
    expect(() => buildProviderPayload("anthropic", {
      model: "alias",
      messages: [{ role: "assistant", tool_calls: [{ id: "call_1", function: { name: "lookup", arguments: "{" } }] }],
    })).toThrow("valid JSON");
  });

  it("honors OpenAI tool_choice none by withholding Anthropic tools", () => {
    const payload = buildProviderPayload("anthropic", {
      model: "alias",
      messages: [{ role: "user", content: "Weather?" }],
      tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }],
      tool_choice: "none",
    });
    expect(payload).not.toHaveProperty("tools");
    expect(payload).not.toHaveProperty("tool_choice");
  });

  it("maps parallel_tool_calls false to Anthropic's parallel-use restriction", () => {
    const tools = [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }];
    const automatic = buildProviderPayload("anthropic", {
      model: "alias",
      messages: [{ role: "user", content: "Weather?" }],
      tools,
      parallel_tool_calls: false,
    });
    expect(automatic.tool_choice).toEqual({ type: "auto", disable_parallel_tool_use: true });

    const required = buildProviderPayload("anthropic", {
      model: "alias",
      messages: [{ role: "user", content: "Weather?" }],
      tools,
      tool_choice: "required",
      parallel_tool_calls: false,
    });
    expect(required.tool_choice).toEqual({ type: "any", disable_parallel_tool_use: true });
  });

  it("rejects unsupported Anthropic tool controls rather than dropping them", () => {
    expect(() => buildProviderPayload("anthropic", {
      model: "alias",
      messages: [{ role: "user", content: "Weather?" }],
      tools: [{ type: "function", function: { name: "lookup" } }],
      tool_choice: { type: "unsupported" },
    })).toThrow("Unsupported tool_choice");
    expect(() => buildProviderPayload("anthropic", {
      model: "alias",
      messages: [{ role: "user", content: "Weather?" }],
      parallel_tool_calls: "false",
    })).toThrow("parallel_tool_calls must be a boolean");
  });

  it("surfaces malformed provider frames as errors", () => {
    const converter = new ProviderStreamConverter("openai");
    expect(() => converter.consume({ data: "not-json" })).toThrow("malformed SSE JSON");
    expect(() => converter.consume({ data: JSON.stringify({ error: { message: "private prompt content" } }) })).toThrow("Provider stream returned an error");
    expect(() => converter.consume({ data: JSON.stringify({ error: { message: "private prompt content" } }) })).not.toThrow("private prompt content");
  });

  it("does not treat provider EOF as successful completion without the stream sentinel", () => {
    const openAi = new ProviderStreamConverter("openai");
    openAi.consume({ data: JSON.stringify({ choices: [{ index: 0, delta: { content: "partial" }, finish_reason: null }] }) });
    expect(openAi.completed).toBe(false);
    const anthropic = new ProviderStreamConverter("anthropic");
    anthropic.consume({ event: "message_delta", data: JSON.stringify({ type: "message_delta", delta: { stop_reason: "end_turn" } }) });
    expect(anthropic.completed).toBe(false);
    anthropic.consume({ event: "message_stop", data: JSON.stringify({ type: "message_stop" }) });
    expect(anthropic.completed).toBe(true);
  });

  it("bounds an SSE event made from many short data lines", () => {
    const parser = new SseParser(7);
    expect(() => parser.push("data: x\ndata: x\ndata: x\ndata: x\n"))
      .toThrow("configured buffer limit");
  });

  it("does not retain streamed completion output in the non-capturing accumulator", () => {
    const accumulator = new CompletionAccumulator(false);
    for (let index = 0; index < 50_000; index += 1) {
      accumulator.add({ index: 0, delta: { content: "response text", tool_calls: [{ index: 0, function: { arguments: "{}" } }] } });
    }
    expect(accumulator.snapshot()).toEqual({ content: "", refusal: "", toolCalls: [], finishReason: "stop" });
  });
});
