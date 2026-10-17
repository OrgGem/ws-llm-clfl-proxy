import { randomUUID } from "node:crypto";
import type { SseEvent } from "./sse.js";

export type Provider = "openai" | "anthropic";

export interface OpenAiRequest {
  model: string;
  messages: unknown[];
  stream?: boolean;
  stream_options?: { include_usage?: boolean; [key: string]: unknown };
  [key: string]: unknown;
}

export interface ToolCallDelta {
  index: number;
  id?: string;
  type?: "function";
  function?: { name?: string; arguments?: string };
}

export interface ProviderDelta {
  index: number;
  delta: {
    content?: string;
    refusal?: string;
    tool_calls?: ToolCallDelta[];
  };
  finishReason?: string | null;
  usage?: OpenAiUsage;
}

export interface OpenAiUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

interface ToolState {
  id?: string;
  name?: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const asString = (value: unknown): string | undefined => typeof value === "string" ? value : undefined;
const MAX_TOOL_CALLS = 256;

function usageFromOpenAi(value: unknown): OpenAiUsage | undefined {
  if (!isRecord(value)) return undefined;
  const prompt = Number(value.prompt_tokens);
  const completion = Number(value.completion_tokens);
  if (!Number.isFinite(prompt) || !Number.isFinite(completion)) return undefined;
  const total = Number(value.total_tokens);
  return {
    prompt_tokens: prompt,
    completion_tokens: completion,
    total_tokens: Number.isFinite(total) ? total : prompt + completion,
  };
}

export class ProviderStreamConverter {
  private readonly tools = new Map<number, ToolState>();
  private readonly anthropicToolIndices = new Map<number, number>();
  private nextAnthropicToolIndex = 0;
  private openAiUsage: OpenAiUsage | undefined;
  private anthropicInputTokens = 0;
  private anthropicOutputTokens = 0;
  private completionSeen = false;

  constructor(private readonly provider: Provider) {}

  consume(event: SseEvent): ProviderDelta[] {
    if (event.data === "[DONE]") {
      if (this.provider === "openai") this.completionSeen = true;
      return [];
    }
    let payload: unknown;
    try {
      payload = JSON.parse(event.data);
    } catch {
      throw new Error("Provider returned malformed SSE JSON");
    }
    if (!isRecord(payload)) throw new Error("Provider returned an invalid SSE event");
    if (isRecord(payload.error)) {
      // Provider error bodies can echo prompt text, keys, or other sensitive input.
      throw new Error("Provider stream returned an error");
    }
    return this.provider === "openai" ? this.consumeOpenAi(payload) : this.consumeAnthropic(event.event ?? asString(payload.type), payload);
  }

  get usage(): OpenAiUsage | undefined {
    if (this.provider === "openai") return this.openAiUsage;
    if (this.anthropicInputTokens === 0 && this.anthropicOutputTokens === 0) return undefined;
    return {
      prompt_tokens: this.anthropicInputTokens,
      completion_tokens: this.anthropicOutputTokens,
      total_tokens: this.anthropicInputTokens + this.anthropicOutputTokens,
    };
  }

  get completed(): boolean {
    return this.completionSeen;
  }

  private consumeOpenAi(payload: Record<string, unknown>): ProviderDelta[] {
    const usage = usageFromOpenAi(payload.usage);
    if (usage) this.openAiUsage = usage;
    const choices = Array.isArray(payload.choices) ? payload.choices : [];
    if (choices.length > 1) throw new Error("Provider returned more than one completion choice");
    const result: ProviderDelta[] = [];
    for (const rawChoice of choices) {
      if (!isRecord(rawChoice)) continue;
      const index = Number.isInteger(rawChoice.index) ? Number(rawChoice.index) : 0;
      const rawDelta = isRecord(rawChoice.delta) ? rawChoice.delta : {};
      const delta: ProviderDelta["delta"] = {};
      if (typeof rawDelta.content === "string") delta.content = rawDelta.content;
      if (typeof rawDelta.refusal === "string") delta.refusal = rawDelta.refusal;
      if (Array.isArray(rawDelta.tool_calls)) {
        const toolCalls: ToolCallDelta[] = [];
        for (const rawTool of rawDelta.tool_calls) {
          if (!isRecord(rawTool)) continue;
          const toolIndex = Number.isInteger(rawTool.index) ? Number(rawTool.index) : 0;
          if (toolIndex < 0 || toolIndex >= MAX_TOOL_CALLS) throw new Error("Provider returned too many tool calls");
          const state = this.tools.get(toolIndex) ?? {};
          const callId = asString(rawTool.id);
          if (callId) state.id = callId;
          const rawFunction = isRecord(rawTool.function) ? rawTool.function : {};
          const name = asString(rawFunction.name);
          if (name) state.name = name;
          this.tools.set(toolIndex, state);
          const argumentsPart = asString(rawFunction.arguments);
          toolCalls.push({
            index: toolIndex,
            ...(callId ? { id: callId } : {}),
            type: "function",
            ...(name || argumentsPart !== undefined
              ? { function: { ...(name ? { name } : {}), ...(argumentsPart === undefined ? {} : { arguments: argumentsPart }) } }
              : {}),
          });
        }
        if (toolCalls.length > 0) delta.tool_calls = toolCalls;
      }
      const finishReason = rawChoice.finish_reason === null ? null : asString(rawChoice.finish_reason);
      if (Object.keys(delta).length > 0 || finishReason !== undefined) {
        result.push({ index, delta, ...(finishReason === undefined ? {} : { finishReason }), ...(usage ? { usage } : {}) });
      }
    }
    if (choices.length === 0 && usage) result.push({ index: 0, delta: {}, usage });
    return result;
  }

  private consumeAnthropic(eventName: string | undefined, payload: Record<string, unknown>): ProviderDelta[] {
    const result: ProviderDelta[] = [];
    switch (eventName) {
      case "message_start": {
        const message = isRecord(payload.message) ? payload.message : {};
        const usage = isRecord(message.usage) ? message.usage : {};
        const input = Number(usage.input_tokens);
        if (Number.isFinite(input)) this.anthropicInputTokens = input;
        break;
      }
      case "content_block_start": {
        const blockIndex = Number.isInteger(payload.index) ? Number(payload.index) : 0;
        const block = isRecord(payload.content_block) ? payload.content_block : {};
        if (block.type === "text" && typeof block.text === "string" && block.text.length > 0) {
          result.push({ index: 0, delta: { content: block.text } });
        } else if (block.type === "tool_use") {
          if (this.nextAnthropicToolIndex >= MAX_TOOL_CALLS) throw new Error("Provider returned too many tool calls");
          const toolIndex = this.nextAnthropicToolIndex++;
          const id = asString(block.id);
          const name = asString(block.name);
          this.anthropicToolIndices.set(blockIndex, toolIndex);
          this.tools.set(toolIndex, { ...(id ? { id } : {}), ...(name ? { name } : {}) });
          const initialInput = isRecord(block.input) ? block.input : undefined;
          const initialArguments = initialInput && Object.keys(initialInput).length > 0 ? JSON.stringify(initialInput) : undefined;
          result.push({
            index: 0,
            delta: {
              tool_calls: [{
                index: toolIndex,
                ...(id ? { id } : {}),
                type: "function",
                function: { ...(name ? { name } : {}), ...(initialArguments ? { arguments: initialArguments } : {}) },
              }],
            },
          });
        }
        break;
      }
      case "content_block_delta": {
        const blockIndex = Number.isInteger(payload.index) ? Number(payload.index) : 0;
        const delta = isRecord(payload.delta) ? payload.delta : {};
        if (delta.type === "text_delta" && typeof delta.text === "string") {
          result.push({ index: 0, delta: { content: delta.text } });
        } else if (delta.type === "input_json_delta" && typeof delta.partial_json === "string") {
          const toolIndex = this.anthropicToolIndices.get(blockIndex);
          if (toolIndex === undefined) throw new Error("Provider returned tool arguments before tool metadata");
          result.push({
            index: 0,
            delta: { tool_calls: [{ index: toolIndex, type: "function", function: { arguments: delta.partial_json } }] },
          });
        }
        break;
      }
      case "message_delta": {
        const delta = isRecord(payload.delta) ? payload.delta : {};
        const usage = isRecord(payload.usage) ? payload.usage : {};
        const output = Number(usage.output_tokens);
        if (Number.isFinite(output)) this.anthropicOutputTokens = output;
        const stop = asString(delta.stop_reason);
        const finishReason = stop === "end_turn" ? "stop" : stop === "tool_use" ? "tool_calls" : stop === "max_tokens" ? "length" : stop;
        if (finishReason !== undefined) result.push({ index: 0, delta: {}, finishReason, ...(this.usage ? { usage: this.usage } : {}) });
        break;
      }
      case "message_stop":
        this.completionSeen = true;
        break;
      case "error":
        throw new Error("Provider stream returned an error");
      default:
        break;
    }
    return result;
  }
}

export function buildProviderPayload(provider: Provider, request: OpenAiRequest): Record<string, unknown> {
  if (!Array.isArray(request.messages) || request.messages.length === 0) {
    throw new Error("messages must be a non-empty array");
  }
  if (request.n !== undefined && request.n !== 1) throw new Error("This adapter supports exactly one completion choice per request");
  if ("url" in request || "endpoint" in request) throw new Error("Provider endpoint fields cannot be selected by the request");
  if (provider === "openai") {
    const { model: _model, stream: _stream, ...payload } = request;
    return payload;
  }
  return buildAnthropicPayload(request);
}

function buildAnthropicPayload(request: OpenAiRequest): Record<string, unknown> {
  const requestedToolChoice = request.tool_choice;
  if (requestedToolChoice !== undefined && requestedToolChoice !== "none" && requestedToolChoice !== "auto" && requestedToolChoice !== "required"
    && !(isRecord(requestedToolChoice) && isRecord(requestedToolChoice.function) && typeof requestedToolChoice.function.name === "string")) {
    throw new Error("Unsupported tool_choice for Anthropic");
  }
  if (request.parallel_tool_calls !== undefined && typeof request.parallel_tool_calls !== "boolean") {
    throw new Error("parallel_tool_calls must be a boolean for Anthropic");
  }
  const systemParts: string[] = [];
  const messages: Array<{ role: "user" | "assistant"; content: string | Array<Record<string, unknown>> }> = [];
  for (const rawMessage of request.messages) {
    if (!isRecord(rawMessage) || typeof rawMessage.role !== "string") throw new Error("Each message must have a role");
    const role = rawMessage.role;
    const content = rawMessage.content;
    const text = typeof content === "string" ? content : content === null ? "" : undefined;
    if (role === "system" || role === "developer") {
      if (text === undefined) throw new Error("Anthropic system messages must be text");
      if (text) systemParts.push(text);
      continue;
    }
    if (role === "user") {
      if (text === undefined) throw new Error("Anthropic user messages must be text in this adapter version");
      messages.push({ role: "user", content: text });
      continue;
    }
    if (role === "tool") {
      const toolCallId = asString(rawMessage.tool_call_id);
      if (!toolCallId) throw new Error("Tool results require tool_call_id");
      messages.push({
        role: "user",
        content: [{ type: "tool_result", tool_use_id: toolCallId, content: text ?? JSON.stringify(content) }],
      });
      continue;
    }
    if (role === "assistant") {
      const blocks: Array<Record<string, unknown>> = [];
      if (text) blocks.push({ type: "text", text });
      const rawToolCalls = Array.isArray(rawMessage.tool_calls) ? rawMessage.tool_calls : [];
      for (const rawTool of rawToolCalls) {
        if (!isRecord(rawTool)) throw new Error("Invalid assistant tool call");
        const callId = asString(rawTool.id);
        const fn = isRecord(rawTool.function) ? rawTool.function : {};
        const name = asString(fn.name);
        if (!callId || !name) throw new Error("Assistant tool calls require id and function name");
        let input: unknown = {};
        const args = fn.arguments;
        if (typeof args === "string" && args.length > 0) {
          try {
            input = JSON.parse(args);
          } catch {
            throw new Error("Assistant tool call arguments must be valid JSON for Anthropic");
          }
        } else if (isRecord(args)) input = args;
        blocks.push({ type: "tool_use", id: callId, name, input });
      }
      messages.push({ role: "assistant", content: blocks.length > 0 ? blocks : "" });
      continue;
    }
    throw new Error("Unsupported message role for Anthropic");
  }

  const payload: Record<string, unknown> = {
    max_tokens: Number.isInteger(request.max_tokens) ? request.max_tokens : Number.isInteger(request.max_completion_tokens) ? request.max_completion_tokens : 1024,
    messages,
  };
  if (systemParts.length > 0) payload.system = systemParts.join("\n\n");
  for (const field of ["temperature", "top_p", "top_k", "metadata"] as const) {
    if (request[field] !== undefined) payload[field] = request[field];
  }
  if (request.stop !== undefined) payload.stop_sequences = Array.isArray(request.stop) ? request.stop : [request.stop];
  if (Array.isArray(request.tools) && request.tools.length > 0 && requestedToolChoice !== "none") {
    payload.tools = request.tools.map((tool) => {
      if (!isRecord(tool) || tool.type !== "function" || !isRecord(tool.function) || typeof tool.function.name !== "string") {
        throw new Error("Anthropic tools must use the OpenAI function tool shape");
      }
      return {
        name: tool.function.name,
        ...(typeof tool.function.description === "string" ? { description: tool.function.description } : {}),
        input_schema: isRecord(tool.function.parameters) ? tool.function.parameters : { type: "object", properties: {} },
      };
    });
    const parallelism = request.parallel_tool_calls === false ? { disable_parallel_tool_use: true } : {};
    if (requestedToolChoice === "auto") payload.tool_choice = { type: "auto", ...parallelism };
    else if (requestedToolChoice === "required") payload.tool_choice = { type: "any", ...parallelism };
    else if (isRecord(requestedToolChoice)) {
      payload.tool_choice = { type: "tool", name: (requestedToolChoice.function as Record<string, unknown>).name, ...parallelism };
    } else if (request.parallel_tool_calls === false) {
      payload.tool_choice = { type: "auto", disable_parallel_tool_use: true };
    }
  }
  return payload;
}

export interface CompletionAccumulatorState {
  content: string;
  refusal: string;
  toolCalls: Array<{ id?: string; type: "function"; function: { name?: string; arguments: string } }>;
  finishReason: string;
  usage?: OpenAiUsage;
}

export class CompletionAccumulator {
  private content = "";
  private refusal = "";
  private readonly tools = new Map<number, { id?: string; name?: string; arguments: string }>();
  private finishReason = "stop";
  private usageValue: OpenAiUsage | undefined;

  constructor(private readonly captureOutput = true) {}

  add(update: ProviderDelta): void {
    if (this.captureOutput) {
      if (typeof update.delta.content === "string") this.content += update.delta.content;
      if (typeof update.delta.refusal === "string") this.refusal += update.delta.refusal;
      for (const tool of update.delta.tool_calls ?? []) {
        const state = this.tools.get(tool.index) ?? { arguments: "" };
        if (tool.id) state.id = tool.id;
        if (tool.function?.name) state.name = tool.function.name;
        if (tool.function?.arguments) state.arguments += tool.function.arguments;
        this.tools.set(tool.index, state);
      }
    }
    if (update.finishReason) this.finishReason = update.finishReason;
    if (update.usage) this.usageValue = update.usage;
  }

  snapshot(): CompletionAccumulatorState {
    return {
      content: this.content,
      refusal: this.refusal,
      toolCalls: [...this.tools.entries()].sort(([a], [b]) => a - b).map(([, tool]) => ({
        ...(tool.id ? { id: tool.id } : {}),
        type: "function",
        function: { ...(tool.name ? { name: tool.name } : {}), arguments: tool.arguments },
      })),
      finishReason: this.finishReason,
      ...(this.usageValue ? { usage: this.usageValue } : {}),
    };
  }
}

export function createCompletionId(): string {
  return `chatcmpl-${randomUUID().replaceAll("-", "")}`;
}
