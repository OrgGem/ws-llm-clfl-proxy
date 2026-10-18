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
      'event: content_block_stop\ndata: {"type":"content_block_stop","index":4}\n\n',
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

  it("converts detailed OpenAI usage and requires all choice finishes before provider DONE completes", () => {
    const converter = new ProviderStreamConverter("openai");
    converter.consume({ data: JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }) });
    const updates = converter.consume({ data: JSON.stringify({
      choices: [],
      usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5, completion_tokens_details: { reasoning_tokens: 1 } },
    }) });
    expect(updates[0]?.usage).toEqual({
      prompt_tokens: 2,
      completion_tokens: 3,
      total_tokens: 5,
      completion_tokens_details: { reasoning_tokens: 1 },
    });
    expect(converter.usage?.total_tokens).toBe(5);
    expect(converter.consume({ data: "[DONE]" })).toEqual([]);
    expect(converter.completed).toBe(true);
  });

  it("accepts normal null-usage chunks and captures final detailed usage for buffered and streaming paths", () => {
    const raw = [
      'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}],"usage":null}\n\n',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}\n\n',
      'data: {"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6,"prompt_tokens_details":{"cached_tokens":1},"completion_tokens_details":{"reasoning_tokens":1}}}\n\n',
      "data: [DONE]\n\n",
    ].join("");

    for (const captureOutput of [true, false]) {
      const parser = new SseParser();
      const converter = new ProviderStreamConverter("openai");
      const accumulator = new CompletionAccumulator(captureOutput);
      let streamedText = "";
      for (let offset = 0; offset < raw.length; offset += 13) {
        for (const event of parser.push(raw.slice(offset, offset + 13))) {
          for (const update of converter.consume(event)) {
            accumulator.add(update);
            if (!captureOutput && typeof update.delta.content === "string") streamedText += update.delta.content;
          }
        }
      }
      for (const event of parser.finish()) {
        for (const update of converter.consume(event)) {
          accumulator.add(update);
          if (!captureOutput && typeof update.delta.content === "string") streamedText += update.delta.content;
        }
      }

      expect(converter.completed).toBe(true);
      expect(accumulator.snapshot().usage).toEqual({
        prompt_tokens: 4,
        completion_tokens: 2,
        total_tokens: 6,
        prompt_tokens_details: { cached_tokens: 1 },
        completion_tokens_details: { reasoning_tokens: 1 },
      });
      if (captureOutput) expect(accumulator.snapshot().content).toBe("Hello");
      else expect(streamedText).toBe("Hello");
    }
  });

  it("converts OpenAI tool deltas without losing index or argument fragments", () => {
    const converter = new ProviderStreamConverter("openai");
    const accumulator = new CompletionAccumulator();
    for (const event of [
      { data: JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 2, id: "call_x", type: "function", function: { name: "se", arguments: "{\"q\":" } }] }, finish_reason: null }] }) },
      { data: JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 2, function: { name: "arch", arguments: "\"x\"}" } }] }, finish_reason: "tool_calls" }] }) },
    ]) for (const update of converter.consume(event)) accumulator.add(update);
    expect(accumulator.snapshot().toolCalls).toEqual([{ id: "call_x", type: "function", function: { name: "search", arguments: '{"q":"x"}' } }]);
    expect(accumulator.snapshot().finishReason).toBe("tool_calls");
  });

  it("preserves interleaved reasoning, legacy function calls, refusal, logprobs, fingerprint and detailed usage", () => {
    const converter = new ProviderStreamConverter("openai", 2);
    const accumulator = new CompletionAccumulator();
    const events = [
      {
        choices: [
          { index: 1, delta: { content: "answer", reasoning_content: "because " }, logprobs: { content: [{ token: "answer", logprob: -0.25 }] }, finish_reason: null },
          { index: 0, delta: { function_call: { name: "legacy_", arguments: "{" } }, finish_reason: null },
        ],
        system_fingerprint: "fp_test",
      },
      {
        choices: [
          { index: 0, delta: { function_call: { name: "lookup", arguments: "}" } }, finish_reason: "function_call" },
          { index: 1, delta: { refusal: "blocked" }, logprobs: { refusal: [{ token: "blocked", logprob: -0.1 }] }, finish_reason: "stop" },
        ],
      },
      {
        choices: [],
        usage: {
          prompt_tokens: 6,
          completion_tokens: 4,
          total_tokens: 10,
          prompt_tokens_details: { cached_tokens: 2 },
          completion_tokens_details: { reasoning_tokens: 1, accepted_prediction_tokens: 2 },
        },
      },
    ];
    for (const payload of events) {
      for (const update of converter.consume({ data: JSON.stringify(payload) })) accumulator.add(update);
    }
    expect(converter.completed).toBe(false);
    converter.consume({ data: "[DONE]" });
    expect(converter.completed).toBe(true);
    expect(converter.systemFingerprint).toBe("fp_test");
    expect(accumulator.choiceIndices).toEqual([0, 1]);
    expect(accumulator.snapshot(0)).toMatchObject({
      finishReason: "function_call",
      functionCall: { name: "legacy_lookup", arguments: "{}" },
    });
    expect(accumulator.snapshot(1)).toMatchObject({
      content: "answer",
      reasoningContent: "because ",
      refusal: "blocked",
      finishReason: "stop",
      logprobs: {
        content: [{ token: "answer", logprob: -0.25 }],
        refusal: [{ token: "blocked", logprob: -0.1 }],
      },
      usage: {
        prompt_tokens_details: { cached_tokens: 2 },
        completion_tokens_details: { reasoning_tokens: 1, accepted_prediction_tokens: 2 },
      },
    });
  });

  it("requires one valid finish reason per requested choice before accepting DONE", () => {
    const converter = new ProviderStreamConverter("openai", 2);
    converter.consume({ data: JSON.stringify({ choices: [{ index: 1, delta: {}, finish_reason: "stop" }] }) });
    converter.consume({ data: "[DONE]" });
    expect(converter.completed).toBe(false);
  });

  it("rejects malformed choice, tool, and unsupported modality deltas instead of dropping them", () => {
    const invalidChoicePayloads = [
      { choices: [{ index: -1, delta: {}, finish_reason: "stop" }] },
      { choices: [{ index: 1.5, delta: {}, finish_reason: "stop" }] },
      { choices: [{ index: 1, delta: {}, finish_reason: "stop" }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: "0", function: { arguments: "{}" } }] }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { audio: { data: "..." } }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { content: { text: "not text" } }, finish_reason: null }] },
    ];
    for (const payload of invalidChoicePayloads) {
      expect(() => new ProviderStreamConverter("openai", 1).consume({ data: JSON.stringify(payload) })).toThrow("invalid stream event");
    }
    expect(() => new ProviderStreamConverter("anthropic", 2)).toThrow("choice count");
  });

  it("accepts OpenAI choice counts up to eight and rejects malformed counts and audio output requests", () => {
    const base = { model: "alias", messages: [{ role: "user", content: "hello" }] };
    expect(buildProviderPayload("openai", { ...base, n: 8, stream_options: { include_usage: false } })).toMatchObject({
      n: 8,
      stream_options: { include_usage: true },
    });
    expect(buildProviderPayload("openai", base).stream_options).toEqual({ include_usage: true });
    expect(buildProviderPayload("anthropic", { ...base, n: 1 })).toHaveProperty("messages");
    for (const n of [0, 9, 1.2, "2"]) {
      expect(() => buildProviderPayload("openai", { ...base, n })).toThrow("n must be an integer");
    }
    expect(() => buildProviderPayload("anthropic", { ...base, n: 2 })).toThrow("exactly one");
    expect(() => buildProviderPayload("openai", { ...base, stream_options: { include_usage: "yes" as unknown as boolean } })).toThrow("include_usage must be a boolean");
    expect(() => buildProviderPayload("openai", { ...base, modalities: ["text", "audio"] })).toThrow("text output only");
    expect(() => buildProviderPayload("openai", { ...base, messages: [{ role: "user", content: [{ type: "input_audio", input_audio: { data: "..." } }] }] })).toThrow("Audio message content");
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
    anthropic.consume({ event: "message_start", data: JSON.stringify({ type: "message_start", message: { usage: { input_tokens: 0 } } }) });
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
    expect(accumulator.snapshot()).toEqual({ content: "", refusal: "", reasoningContent: "", toolCalls: [], finishReason: "stop" });
  });
});
