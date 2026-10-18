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

export interface LegacyFunctionCallDelta {
  name?: string;
  arguments?: string;
}

export interface ProviderDelta {
  index: number;
  delta: {
    content?: string;
    refusal?: string;
    reasoning_content?: string;
    tool_calls?: ToolCallDelta[];
    function_call?: LegacyFunctionCallDelta;
  };
  finishReason?: string | null;
  usage?: OpenAiUsage;
  logprobs?: unknown;
  systemFingerprint?: string;
}

export interface OpenAiTokenDetails {
  [key: string]: number;
}

export interface OpenAiUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  prompt_tokens_details?: OpenAiTokenDetails;
  completion_tokens_details?: OpenAiTokenDetails;
}

interface ToolState {
  id?: string;
  name?: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const asString = (value: unknown): string | undefined => typeof value === "string" ? value : undefined;
const MAX_TOOL_CALLS = 256;
const MAX_CHOICES = 8;

function invalidProviderStream(): never {
  throw new Error("Provider returned an invalid stream event");
}

function nonnegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function tokenDetails(value: unknown): OpenAiTokenDetails | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) invalidProviderStream();
  const result: OpenAiTokenDetails = {};
  for (const [name, count] of Object.entries(value)) {
    if (!name || !nonnegativeInteger(count)) invalidProviderStream();
    result[name] = count;
  }
  return result;
}

function usageFromOpenAi(value: unknown): OpenAiUsage {
  if (!isRecord(value) || !nonnegativeInteger(value.prompt_tokens) || !nonnegativeInteger(value.completion_tokens)) {
    invalidProviderStream();
  }
  const total = value.total_tokens;
  if (total !== undefined && !nonnegativeInteger(total)) invalidProviderStream();
  const promptDetails = tokenDetails(value.prompt_tokens_details);
  const completionDetails = tokenDetails(value.completion_tokens_details);
  const resolvedTotal = total ?? value.prompt_tokens + value.completion_tokens;
  if (!Number.isSafeInteger(resolvedTotal)) invalidProviderStream();
  return {
    prompt_tokens: value.prompt_tokens,
    completion_tokens: value.completion_tokens,
    total_tokens: total ?? value.prompt_tokens + value.completion_tokens,
    ...(promptDetails ? { prompt_tokens_details: promptDetails } : {}),
    ...(completionDetails ? { completion_tokens_details: completionDetails } : {}),
  };
}

function mergeLogprobs(previous: unknown, next: unknown): unknown {
  if (Array.isArray(previous) && Array.isArray(next)) return [...previous, ...next];
  if (isRecord(previous) && isRecord(next)) {
    const merged: Record<string, unknown> = { ...previous };
    for (const [key, value] of Object.entries(next)) {
      merged[key] = key in merged ? mergeLogprobs(merged[key], value) : value;
    }
    return merged;
  }
  return next;
}

export class ProviderStreamConverter {
  private readonly tools = new Map<number, Map<number, ToolState>>();
  private readonly finishReasons = new Map<number, string>();
  private readonly anthropicToolIndices = new Map<number, number>();
  private readonly anthropicBlocks = new Map<number, "text" | "tool_use">();
  private readonly closedAnthropicBlocks = new Set<number>();
  private nextAnthropicToolIndex = 0;
  private openAiUsage: OpenAiUsage | undefined;
  private anthropicInputTokens = 0;
  private anthropicOutputTokens = 0;
  private anthropicCacheReadTokens = 0;
  private anthropicCacheCreationTokens = 0;
  private anthropicUsageSeen = false;
  private anthropicMessageStarted = false;
  private anthropicFinishReason: string | undefined;
  private systemFingerprintValue: string | undefined;
  private completionSeen = false;

  constructor(private readonly provider: Provider, private readonly expectedChoices = 1) {
    if (!Number.isInteger(expectedChoices) || expectedChoices < 1 || expectedChoices > MAX_CHOICES ||
        (provider === "anthropic" && expectedChoices !== 1)) {
      throw new Error("Requested completion choice count is invalid for this provider");
    }
  }

  consume(event: SseEvent): ProviderDelta[] {
    if (event.data === "[DONE]") {
      if (this.provider !== "openai" || this.completionSeen) invalidProviderStream();
      this.completionSeen = true;
      return [];
    }
    if (this.completionSeen) invalidProviderStream();
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
    const type = asString(payload.type);
    if (event.event !== undefined && type !== undefined && event.event !== type) invalidProviderStream();
    const eventName = event.event ?? type;
    if (this.provider === "openai") return this.consumeOpenAi(payload);
    return this.consumeAnthropic(eventName, payload);
  }

  get usage(): OpenAiUsage | undefined {
    if (this.provider === "openai") return this.openAiUsage;
    if (!this.anthropicUsageSeen) return undefined;
    return {
      prompt_tokens: this.anthropicInputTokens,
      completion_tokens: this.anthropicOutputTokens,
      total_tokens: this.anthropicInputTokens + this.anthropicOutputTokens,
      ...((this.anthropicCacheReadTokens > 0 || this.anthropicCacheCreationTokens > 0) ? {
        prompt_tokens_details: {
          ...(this.anthropicCacheReadTokens > 0 ? { cached_tokens: this.anthropicCacheReadTokens } : {}),
          ...(this.anthropicCacheCreationTokens > 0 ? { cache_creation_tokens: this.anthropicCacheCreationTokens } : {}),
        },
      } : {}),
    };
  }

  get systemFingerprint(): string | undefined {
    return this.systemFingerprintValue;
  }

  get completed(): boolean {
    if (!this.completionSeen) return false;
    return this.provider === "openai"
      ? this.finishReasons.size === this.expectedChoices
      : this.anthropicFinishReason !== undefined;
  }

  private consumeOpenAi(payload: Record<string, unknown>): ProviderDelta[] {
    if (!Array.isArray(payload.choices)) invalidProviderStream();
    const usage = payload.usage === undefined || payload.usage === null ? undefined : usageFromOpenAi(payload.usage);
    if (usage) this.openAiUsage = usage;
    if (payload.system_fingerprint !== undefined && payload.system_fingerprint !== null) {
      if (typeof payload.system_fingerprint !== "string") invalidProviderStream();
      this.systemFingerprintValue = payload.system_fingerprint;
    }
    const choices = payload.choices;
    if (choices.length > this.expectedChoices) invalidProviderStream();
    if (choices.length === 0 && usage === undefined) invalidProviderStream();
    const result: ProviderDelta[] = [];
    const indexesInEvent = new Set<number>();
    for (const rawChoice of choices) {
      if (!isRecord(rawChoice) || !Number.isSafeInteger(rawChoice.index)) invalidProviderStream();
      const index = rawChoice.index as number;
      if (index < 0 || index >= this.expectedChoices || indexesInEvent.has(index) || this.finishReasons.has(index)) invalidProviderStream();
      indexesInEvent.add(index);
      if (rawChoice.finish_reason !== null && (typeof rawChoice.finish_reason !== "string" || rawChoice.finish_reason.length === 0)) {
        invalidProviderStream();
      }
      if (!isRecord(rawChoice.delta)) invalidProviderStream();
      const rawDelta = rawChoice.delta;
      const allowedDeltaKeys = new Set(["role", "content", "refusal", "reasoning_content", "tool_calls", "function_call"]);
      if (Object.keys(rawDelta).some((key) => !allowedDeltaKeys.has(key))) invalidProviderStream();
      if (rawDelta.role !== undefined && rawDelta.role !== "assistant") invalidProviderStream();
      if (rawDelta.tool_calls !== undefined && rawDelta.tool_calls !== null &&
          rawDelta.function_call !== undefined && rawDelta.function_call !== null) invalidProviderStream();
      const delta: ProviderDelta["delta"] = {};
      if (rawDelta.content !== undefined && rawDelta.content !== null) {
        if (typeof rawDelta.content !== "string") invalidProviderStream();
        delta.content = rawDelta.content;
      }
      if (rawDelta.refusal !== undefined && rawDelta.refusal !== null) {
        if (typeof rawDelta.refusal !== "string") invalidProviderStream();
        delta.refusal = rawDelta.refusal;
      }
      if (rawDelta.reasoning_content !== undefined && rawDelta.reasoning_content !== null) {
        if (typeof rawDelta.reasoning_content !== "string") invalidProviderStream();
        delta.reasoning_content = rawDelta.reasoning_content;
      }
      if (rawDelta.tool_calls !== undefined) {
        if (!Array.isArray(rawDelta.tool_calls) || rawDelta.tool_calls.length > MAX_TOOL_CALLS) invalidProviderStream();
        const toolCalls: ToolCallDelta[] = [];
        const toolIndexesInDelta = new Set<number>();
        for (const rawTool of rawDelta.tool_calls) {
          if (!isRecord(rawTool) || !Number.isSafeInteger(rawTool.index)) invalidProviderStream();
          const toolIndex = rawTool.index as number;
          if (toolIndex < 0 || toolIndex >= MAX_TOOL_CALLS || toolIndexesInDelta.has(toolIndex)) invalidProviderStream();
          toolIndexesInDelta.add(toolIndex);
          if (rawTool.type !== undefined && rawTool.type !== "function") invalidProviderStream();
          if (rawTool.function !== undefined && !isRecord(rawTool.function)) invalidProviderStream();
          const choiceTools = this.tools.get(index) ?? new Map<number, ToolState>();
          const state = choiceTools.get(toolIndex) ?? {};
          const callId = asString(rawTool.id);
          if (rawTool.id !== undefined && (callId === undefined || callId.length === 0)) invalidProviderStream();
          if (callId && state.id && state.id !== callId) invalidProviderStream();
          if (callId) state.id = callId;
          const rawFunction = isRecord(rawTool.function) ? rawTool.function : {};
          const name = asString(rawFunction.name);
          if (rawFunction.name !== undefined && (name === undefined || name.length === 0)) invalidProviderStream();
          if (Object.keys(rawTool).some((key) => !["index", "id", "type", "function"].includes(key)) ||
              Object.keys(rawFunction).some((key) => key !== "name" && key !== "arguments")) invalidProviderStream();
          if (name) state.name = (state.name ?? "") + name;
          const argumentsPart = asString(rawFunction.arguments);
          if (rawFunction.arguments !== undefined && argumentsPart === undefined) invalidProviderStream();
          choiceTools.set(toolIndex, state);
          this.tools.set(index, choiceTools);
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
      if (rawDelta.function_call !== undefined && rawDelta.function_call !== null) {
        if (!isRecord(rawDelta.function_call)) invalidProviderStream();
        const rawFunctionCall = rawDelta.function_call;
        const name = asString(rawFunctionCall.name);
        const argumentsPart = asString(rawFunctionCall.arguments);
        if ((rawFunctionCall.name !== undefined && name === undefined) ||
            (rawFunctionCall.arguments !== undefined && argumentsPart === undefined) ||
            Object.keys(rawFunctionCall).some((key) => key !== "name" && key !== "arguments") ||
            Object.keys(rawFunctionCall).length === 0) invalidProviderStream();
        delta.function_call = {
          ...(name === undefined ? {} : { name }),
          ...(argumentsPart === undefined ? {} : { arguments: argumentsPart }),
        };
      }
      const finishReason = rawChoice.finish_reason as string | null;
      if (finishReason !== null) this.finishReasons.set(index, finishReason);
      const rawLogprobs = rawChoice.logprobs;
      if (rawLogprobs !== undefined && rawLogprobs !== null && !isRecord(rawLogprobs)) invalidProviderStream();
      if (Object.keys(delta).length > 0 || finishReason !== null || usage || rawLogprobs !== undefined || this.systemFingerprintValue) {
        result.push({
          index,
          delta,
          ...(finishReason !== null ? { finishReason } : { finishReason: null }),
          ...(usage ? { usage } : {}),
          ...(rawLogprobs === undefined ? {} : { logprobs: rawLogprobs }),
          ...(this.systemFingerprintValue ? { systemFingerprint: this.systemFingerprintValue } : {}),
        });
      }
    }
    if (choices.length === 0 && usage) {
      result.push({
        index: 0,
        delta: {},
        usage,
        ...(this.systemFingerprintValue ? { systemFingerprint: this.systemFingerprintValue } : {}),
      });
    }
    return result;
  }

  private consumeAnthropic(eventName: string | undefined, payload: Record<string, unknown>): ProviderDelta[] {
    const result: ProviderDelta[] = [];
    switch (eventName) {
      case "message_start": {
        if (this.anthropicMessageStarted || this.completionSeen || !isRecord(payload.message)) invalidProviderStream();
        const message = payload.message;
        if (!isRecord(message.usage)) invalidProviderStream();
        const usage = message.usage;
        if (!nonnegativeInteger(usage.input_tokens)) invalidProviderStream();
        this.anthropicMessageStarted = true;
        this.anthropicUsageSeen = true;
        this.anthropicInputTokens = usage.input_tokens;
        this.anthropicCacheReadTokens = this.optionalUsageCount(usage.cache_read_input_tokens);
        this.anthropicCacheCreationTokens = this.optionalUsageCount(usage.cache_creation_input_tokens);
        break;
      }
      case "content_block_start": {
        if (!this.anthropicMessageStarted || this.anthropicFinishReason !== undefined || !isRecord(payload.content_block)) invalidProviderStream();
        const blockIndex = this.anthropicBlockIndex(payload.index);
        if (this.anthropicBlocks.has(blockIndex) || this.closedAnthropicBlocks.has(blockIndex)) invalidProviderStream();
        const block = payload.content_block;
        if (block.type === "text") {
          if (typeof block.text !== "string") invalidProviderStream();
          this.anthropicBlocks.set(blockIndex, "text");
          if (block.text.length > 0) result.push({ index: 0, delta: { content: block.text } });
        } else if (block.type === "tool_use") {
          if (this.nextAnthropicToolIndex >= MAX_TOOL_CALLS || typeof block.id !== "string" || block.id.length === 0 ||
              typeof block.name !== "string" || block.name.length === 0 || !isRecord(block.input)) invalidProviderStream();
          const toolIndex = this.nextAnthropicToolIndex++;
          const id = block.id;
          const name = block.name;
          this.anthropicBlocks.set(blockIndex, "tool_use");
          this.anthropicToolIndices.set(blockIndex, toolIndex);
          const choiceTools = this.tools.get(0) ?? new Map<number, ToolState>();
          choiceTools.set(toolIndex, { id, name });
          this.tools.set(0, choiceTools);
          const initialArguments = Object.keys(block.input).length > 0 ? JSON.stringify(block.input) : undefined;
          result.push({
            index: 0,
            delta: {
              tool_calls: [{
                index: toolIndex,
                id,
                type: "function",
                function: { name, ...(initialArguments ? { arguments: initialArguments } : {}) },
              }],
            },
          });
        } else invalidProviderStream();
        break;
      }
      case "content_block_delta": {
        if (!this.anthropicMessageStarted || this.anthropicFinishReason !== undefined || !isRecord(payload.delta)) invalidProviderStream();
        const blockIndex = this.anthropicBlockIndex(payload.index);
        const blockType = this.anthropicBlocks.get(blockIndex);
        if (!blockType || this.closedAnthropicBlocks.has(blockIndex)) invalidProviderStream();
        const delta = payload.delta;
        if (delta.type === "text_delta" && blockType === "text" && typeof delta.text === "string") {
          result.push({ index: 0, delta: { content: delta.text } });
        } else if (delta.type === "input_json_delta" && blockType === "tool_use" && typeof delta.partial_json === "string") {
          const toolIndex = this.anthropicToolIndices.get(blockIndex);
          if (toolIndex === undefined) invalidProviderStream();
          result.push({
            index: 0,
            delta: { tool_calls: [{ index: toolIndex, type: "function", function: { arguments: delta.partial_json } }] },
          });
        } else invalidProviderStream();
        break;
      }
      case "content_block_stop": {
        const blockIndex = this.anthropicBlockIndex(payload.index);
        if (!this.anthropicBlocks.has(blockIndex)) invalidProviderStream();
        this.anthropicBlocks.delete(blockIndex);
        this.closedAnthropicBlocks.add(blockIndex);
        break;
      }
      case "message_delta": {
        if (!this.anthropicMessageStarted || this.anthropicBlocks.size > 0 || this.anthropicFinishReason !== undefined ||
            !isRecord(payload.delta) || !("stop_reason" in payload.delta)) invalidProviderStream();
        const delta = payload.delta;
        if (delta.stop_reason !== null && (typeof delta.stop_reason !== "string" || delta.stop_reason.length === 0)) invalidProviderStream();
        if (payload.usage !== undefined) {
          if (!isRecord(payload.usage)) invalidProviderStream();
          if (payload.usage.output_tokens !== undefined) {
            if (!nonnegativeInteger(payload.usage.output_tokens)) invalidProviderStream();
            this.anthropicOutputTokens = payload.usage.output_tokens;
            this.anthropicUsageSeen = true;
          }
          if (payload.usage.cache_read_input_tokens !== undefined) {
            this.anthropicCacheReadTokens = this.requiredUsageCount(payload.usage.cache_read_input_tokens);
            this.anthropicUsageSeen = true;
          }
          if (payload.usage.cache_creation_input_tokens !== undefined) {
            this.anthropicCacheCreationTokens = this.requiredUsageCount(payload.usage.cache_creation_input_tokens);
            this.anthropicUsageSeen = true;
          }
        }
        const stop = asString(delta.stop_reason);
        if (stop) {
          const finishReason = stop === "end_turn" || stop === "stop_sequence" ? "stop" : stop === "tool_use" ? "tool_calls" : stop === "max_tokens" ? "length" : stop;
          this.anthropicFinishReason = finishReason;
          result.push({ index: 0, delta: {}, finishReason, ...(this.usage ? { usage: this.usage } : {}) });
        } else if (this.usage) result.push({ index: 0, delta: {}, usage: this.usage });
        break;
      }
      case "message_stop":
        if (!this.anthropicMessageStarted || this.anthropicBlocks.size > 0 || this.completionSeen) invalidProviderStream();
        this.completionSeen = true;
        break;
      case "ping":
        break;
      case "error":
        throw new Error("Provider stream returned an error");
      default:
        invalidProviderStream();
    }
    return result;
  }

  private anthropicBlockIndex(value: unknown): number {
    if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) >= MAX_TOOL_CALLS) invalidProviderStream();
    return value as number;
  }

  private optionalUsageCount(value: unknown): number {
    if (value === undefined || value === null) return 0;
    return this.requiredUsageCount(value);
  }

  private requiredUsageCount(value: unknown): number {
    if (!nonnegativeInteger(value)) invalidProviderStream();
    return value;
  }
}

export function buildProviderPayload(provider: Provider, request: OpenAiRequest): Record<string, unknown> {
  if (!Array.isArray(request.messages) || request.messages.length === 0) {
    throw new Error("messages must be a non-empty array");
  }
  if (request.n !== undefined && (!Number.isInteger(request.n) || (request.n as number) < 1 || (request.n as number) > MAX_CHOICES)) {
    throw new Error(`n must be an integer from 1 to ${MAX_CHOICES}`);
  }
  if (provider === "anthropic" && request.n !== undefined && request.n !== 1) {
    throw new Error("Anthropic supports exactly one completion choice per request");
  }
  if (request.stream_options !== undefined) {
    if (!isRecord(request.stream_options) ||
        (request.stream_options.include_usage !== undefined && typeof request.stream_options.include_usage !== "boolean")) {
      throw new Error("stream_options.include_usage must be a boolean");
    }
  }
  if (request.modalities !== undefined &&
      (!Array.isArray(request.modalities) || request.modalities.some((modality) => modality !== "text"))) {
    throw new Error("This adapter supports text output only");
  }
  if (request.audio !== undefined || request.audio_format !== undefined) {
    throw new Error("Audio output is not supported by this adapter");
  }
  if (containsAudioInput(request.messages)) {
    throw new Error("Audio message content is not supported by this adapter");
  }
  if ("url" in request || "endpoint" in request) throw new Error("Provider endpoint fields cannot be selected by the request");
  if (provider === "openai") {
    const { model: _model, stream: _stream, stream_options: requestStreamOptions, ...payload } = request;
    return {
      ...payload,
      // The adapter always consumes an upstream stream; ask OpenAI-compatible
      // providers for final usage even when the client did not request it.
      stream_options: { ...(requestStreamOptions ?? {}), include_usage: true },
    };
  }
  return buildAnthropicPayload(request);
}

function containsAudioInput(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsAudioInput);
  if (!isRecord(value)) return false;
  if (typeof value.type === "string" && value.type.toLowerCase().includes("audio")) return true;
  if ("input_audio" in value || "audio_url" in value) return true;
  return Object.values(value).some(containsAudioInput);
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
  reasoningContent: string;
  toolCalls: Array<{ id?: string; type: "function"; function: { name?: string; arguments: string } }>;
  functionCall?: { name?: string; arguments: string };
  finishReason: string;
  logprobs?: unknown;
  systemFingerprint?: string;
  usage?: OpenAiUsage;
}

interface ChoiceAccumulator {
  content: string;
  refusal: string;
  reasoningContent: string;
  tools: Map<number, { id?: string; name?: string; arguments: string }>;
  functionCall: { name: string; arguments: string };
  finishReason: string;
  logprobs?: unknown;
}

export class CompletionAccumulator {
  private readonly choices = new Map<number, ChoiceAccumulator>();
  private usageValue: OpenAiUsage | undefined;
  private systemFingerprintValue: string | undefined;

  constructor(private readonly captureOutput = true) {}

  add(update: ProviderDelta): void {
    const hasDelta = Object.keys(update.delta).length > 0;
    if (hasDelta || update.finishReason || update.logprobs !== undefined) {
      const choice = this.getChoice(update.index);
      if (update.finishReason) choice.finishReason = update.finishReason;
      if (this.captureOutput) {
        if (typeof update.delta.content === "string") choice.content += update.delta.content;
        if (typeof update.delta.refusal === "string") choice.refusal += update.delta.refusal;
        if (typeof update.delta.reasoning_content === "string") choice.reasoningContent += update.delta.reasoning_content;
        for (const tool of update.delta.tool_calls ?? []) {
          const state = choice.tools.get(tool.index) ?? { arguments: "" };
          if (tool.id) state.id = tool.id;
          if (tool.function?.name) state.name = (state.name ?? "") + tool.function.name;
          if (tool.function?.arguments) state.arguments += tool.function.arguments;
          choice.tools.set(tool.index, state);
        }
        const legacy = update.delta.function_call;
        if (legacy) {
          if (typeof legacy.name === "string") choice.functionCall.name += legacy.name;
          if (typeof legacy.arguments === "string") choice.functionCall.arguments += legacy.arguments;
        }
        if (update.logprobs !== undefined) {
          choice.logprobs = "logprobs" in choice ? mergeLogprobs(choice.logprobs, update.logprobs) : update.logprobs;
        }
      }
    }
    if (update.systemFingerprint !== undefined) this.systemFingerprintValue = update.systemFingerprint;
    if (update.usage) this.usageValue = update.usage;
  }

  get choiceIndices(): number[] {
    return [...this.choices.keys()].sort((a, b) => a - b);
  }

  get systemFingerprint(): string | undefined {
    return this.systemFingerprintValue;
  }

  snapshot(index = 0): CompletionAccumulatorState {
    const choice = this.choices.get(index) ?? this.newChoice();
    return {
      content: choice.content,
      refusal: choice.refusal,
      reasoningContent: choice.reasoningContent,
      toolCalls: [...choice.tools.entries()].sort(([a], [b]) => a - b).map(([, tool]) => ({
        ...(tool.id ? { id: tool.id } : {}),
        type: "function",
        function: { ...(tool.name ? { name: tool.name } : {}), arguments: tool.arguments },
      })),
      ...(choice.functionCall.name || choice.functionCall.arguments ? {
        functionCall: {
          ...(choice.functionCall.name ? { name: choice.functionCall.name } : {}),
          arguments: choice.functionCall.arguments,
        },
      } : {}),
      finishReason: choice.finishReason,
      ...("logprobs" in choice ? { logprobs: choice.logprobs } : {}),
      ...(this.systemFingerprintValue ? { systemFingerprint: this.systemFingerprintValue } : {}),
      ...(this.usageValue ? { usage: this.usageValue } : {}),
    };
  }

  private getChoice(index: number): ChoiceAccumulator {
    let choice = this.choices.get(index);
    if (!choice) {
      choice = this.newChoice();
      this.choices.set(index, choice);
    }
    return choice;
  }

  private newChoice(): ChoiceAccumulator {
    return {
      content: "",
      refusal: "",
      reasoningContent: "",
      tools: new Map(),
      functionCall: { name: "", arguments: "" },
      finishReason: "stop",
    };
  }
}

export function createCompletionId(): string {
  return `chatcmpl-${randomUUID().replaceAll("-", "")}`;
}
