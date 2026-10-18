import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import type { ResponseEndMessage } from "@ws-proxy/shared";
import { createCompletionId } from "./provider.js";
import type { GatewayCallbacks, GatewayRequestInput } from "./gateway.js";
import { GatewayOverloadedError, GatewayPayloadTooLargeError } from "./gateway.js";
import type { AdapterConfig } from "./types.js";
import type { GatewayExecutor } from "./server.js";
import { SseParser, type SseEvent } from "./sse.js";

const MAX_HTTP_BODY_BYTES = 1_048_576;
const MAX_SSE_EVENT_BYTES = 1_048_576;
const MAX_NON_STREAM_BYTES = 8 * 1024 * 1024;
const MAX_LOCAL_WRITE_WAIT_MS = 14_000;
const MAX_PROMPTS = 8;
const MAX_CHOICES = 64;

type Prompt = string | string[] | number[] | number[][];
interface Usage extends Record<string, unknown> {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}
type Logprobs = Record<string, unknown> | null;

interface LegacyChoiceState {
  index: number;
  text: string;
  logprobs: Logprobs | undefined;
  finishReason: string | null;
}

interface LegacyEventChoice {
  index: number;
  text: string;
  logprobs?: Logprobs;
  finishReason?: string | null;
}

interface LegacyEvent {
  choices: LegacyEventChoice[];
  usage?: Usage;
}

interface LegacyRequest {
  model: string;
  prompt: Prompt;
  stream: boolean;
  streamOptions?: { includeUsage: boolean };
  n: number;
  expectedChoices: number;
  payload: Record<string, unknown>;
}

/** Handles OpenAI's native legacy text completion API using the configured Gateway route. */
export async function handleLegacyCompletion(
  request: IncomingMessage,
  response: ServerResponse,
  config: AdapterConfig,
  gateway: GatewayExecutor,
): Promise<void> {
  if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
    sendJson(response, 415, apiError("invalid_request", "Content-Type must be application/json"));
    return;
  }

  let rawBody: unknown;
  try {
    rawBody = await readJsonBody(request);
  } catch (error) {
    sendJson(response, error instanceof BodyLimitError ? 413 : 400, apiError(
      "invalid_request",
      error instanceof BodyLimitError ? "Request body exceeds the 1 MiB limit" : "Request body must be valid JSON",
    ));
    return;
  }

  let input: LegacyRequest;
  try {
    input = validateLegacyRequest(rawBody);
  } catch (error) {
    sendJson(response, 400, apiError("invalid_request", safeValidationMessage(error)));
    return;
  }

  const model = config.models.find((candidate) => candidate.id === input.model);
  if (!model) {
    sendJson(response, 404, apiError("model_not_found", "Model is not configured for this adapter"));
    return;
  }
  if (model.protocol !== "openai") {
    sendJson(response, 400, apiError("unsupported_operation", "Legacy Completions is available only for OpenAI-protocol models"));
    return;
  }
  const envelope = config.envelopes.find((candidate) => candidate.credentialId === model.credentialId);
  if (!envelope) {
    sendJson(response, 400, apiError("credential_invalid", "Model credential envelope is not available"));
    return;
  }
  if (envelope.exp <= Math.floor(Date.now() / 1000)) {
    sendJson(response, 401, apiError("credential_invalid", "Model credential envelope has expired"));
    return;
  }

  const id = createCompletionId().replace(/^chatcmpl-/, "cmpl-");
  const created = Math.floor(Date.now() / 1000);
  const converter = new LegacyCompletionConverter(input.expectedChoices, !input.stream);
  const parser = new SseParser(MAX_SSE_EVENT_BYTES);
  const abortController = new AbortController();
  const writer = new LegacyCompletionWriter(response, { id, created, model: model.id, stream: input.stream });
  let receivedBytes = 0;
  let callbackStarted = false;
  let usageEmitted = false;

  request.once("aborted", () => abortController.abort());
  response.once("close", () => {
    if (!response.writableEnded) abortController.abort();
  });

  const consumeEvents = async (events: SseEvent[]): Promise<void> => {
    for (const event of events) {
      if (Buffer.byteLength(event.data, "utf8") > MAX_SSE_EVENT_BYTES) {
        throw new Error("Provider SSE event exceeded the configured limit");
      }
      const update = converter.consume(event);
      if (input.stream) {
        const visibleChoices = update.choices
          .filter((choice) => choice.text.length > 0 || (choice.logprobs !== undefined && choice.logprobs !== null))
          .map((choice) => ({ ...choice, finishReason: null }));
        const visibleUsage = visibleChoices.length === 0 && input.streamOptions?.includeUsage ? update.usage : undefined;
        if (visibleChoices.length > 0 || visibleUsage) {
          await writer.emit(visibleChoices, visibleUsage);
          if (visibleUsage) usageEmitted = true;
        }
      }
    }
  };

  const callbacks: GatewayCallbacks = {
    onChunk: async (_seq, data) => {
      callbackStarted = true;
      if (!input.stream) {
        receivedBytes += Buffer.byteLength(data, "utf8");
        if (receivedBytes > MAX_NON_STREAM_BYTES) throw new Error("Provider response exceeded the 8 MiB buffer limit");
      }
      await consumeEvents(parser.push(data));
    },
    onEnd: async (frame) => {
      callbackStarted = true;
      await consumeEvents(parser.finish());
      converter.assertSuccessfulEnd();
      const usage = converter.usage ?? gatewayUsage(frame);
      if (input.stream) {
        await writer.emit(converter.finishChoices());
        await writer.finish(input.streamOptions?.includeUsage && !usageEmitted ? usage : undefined);
      } else {
        const body = completionJson(id, created, model.id, converter, usage);
        if (Buffer.byteLength(JSON.stringify(body), "utf8") > MAX_NON_STREAM_BYTES) {
          throw new Error("Provider response exceeded the 8 MiB buffer limit");
        }
        sendJson(response, 200, body);
      }
    },
    onError: async (frame) => {
      callbackStarted = true;
      await writer.fail(frame.code, frame.message, frame.upstreamStarted, statusForGateway(frame.code));
    },
    onInterrupted: async (message) => {
      callbackStarted = true;
      await writer.fail("interrupted", message, true, 502);
    },
    onLocalFailure: async (_error) => {
      callbackStarted = true;
      await writer.fail("invalid_provider_response", "The provider response was incomplete or invalid", true, 502);
    },
  };

  const gatewayInput = {
    api: "completions" as const,
    requestId: randomUUID(),
    provider: model.provider,
    model: model.id,
    envelope,
    payload: input.payload,
  } satisfies GatewayRequestInput & { api: "completions" };

  try {
    await gateway.execute(gatewayInput, callbacks, abortController.signal);
  } catch (error) {
    if (abortController.signal.aborted) return;
    const status = error instanceof GatewayPayloadTooLargeError ? 413 : error instanceof GatewayOverloadedError ? 503 : 502;
    const code = error instanceof GatewayPayloadTooLargeError ? "request_too_large" : error instanceof GatewayOverloadedError ? "overloaded" : callbackStarted ? "invalid_provider_response" : "gateway_unavailable";
    const message = error instanceof GatewayPayloadTooLargeError || error instanceof GatewayOverloadedError
      ? error.message
      : callbackStarted ? "The provider response was incomplete or invalid" : "Gateway connection failed before dispatch";
    await writer.fail(code, message, callbackStarted, status);
  }
}

class LegacyCompletionConverter {
  private readonly choices = new Map<number, LegacyChoiceState>();
  private readonly finished = new Set<number>();
  private complete = false;
  private usageValue: Usage | undefined;

  constructor(private readonly expectedChoices: number, private readonly captureOutput: boolean) {}

  consume(event: SseEvent): LegacyEvent {
    if (event.data === "[DONE]") {
      if (this.complete) throw new Error("Provider sent multiple completion sentinels");
      this.complete = true;
      return { choices: [] };
    }
    if (this.complete) throw new Error("Provider sent data after the completion sentinel");

    let payload: unknown;
    try {
      payload = JSON.parse(event.data) as unknown;
    } catch {
      throw new Error("Provider returned malformed completion JSON");
    }
    if (!isRecord(payload)) throw new Error("Provider returned an invalid completion event");
    if (isRecord(payload.error)) throw new Error("Provider returned a completion error");
    if (!Array.isArray(payload.choices)) throw new Error("Provider completion event omitted choices");

    let usage: Usage | undefined;
    if (payload.usage !== undefined && payload.usage !== null) {
      if (!isRecord(payload.usage)) throw new Error("Provider returned invalid completion usage");
      for (const key of ["prompt_tokens", "completion_tokens", "total_tokens"]) {
        if (!Number.isSafeInteger(payload.usage[key]) || Number(payload.usage[key]) < 0) {
          throw new Error("Provider returned invalid completion usage");
        }
      }
      usage = payload.usage as Usage;
      this.usageValue = usage;
    }

    const choices: LegacyEventChoice[] = [];
    const eventIndexes = new Set<number>();
    for (const rawChoice of payload.choices) {
      if (!isRecord(rawChoice) || !Number.isSafeInteger(rawChoice.index) || Number(rawChoice.index) < 0 || Number(rawChoice.index) >= this.expectedChoices ||
          typeof rawChoice.text !== "string" || (rawChoice.finish_reason !== null && rawChoice.finish_reason !== undefined && typeof rawChoice.finish_reason !== "string") ||
          (rawChoice.logprobs !== undefined && rawChoice.logprobs !== null && !isRecord(rawChoice.logprobs))) {
        throw new Error("Provider returned an invalid completion choice");
      }
      const index = Number(rawChoice.index);
      if (eventIndexes.has(index) || this.finished.has(index)) throw new Error("Provider returned a duplicate completion choice");
      eventIndexes.add(index);
      const finishReason = rawChoice.finish_reason === undefined ? null : rawChoice.finish_reason as string | null;
      const logprobs = rawChoice.logprobs === undefined ? undefined : rawChoice.logprobs as Logprobs;
      const state = this.choices.get(index) ?? { index, text: "", logprobs: undefined, finishReason: null };
      if (this.captureOutput) {
        state.text += rawChoice.text;
        if (logprobs !== undefined) state.logprobs = mergeLogprobs(state.logprobs, logprobs);
      }
      if (typeof finishReason === "string") {
        state.finishReason = finishReason;
        this.finished.add(index);
      }
      this.choices.set(index, state);
      choices.push({ index, text: rawChoice.text, ...(logprobs === undefined ? {} : { logprobs }), finishReason });
    }

    if (choices.length === 0 && usage === undefined) throw new Error("Provider returned an empty completion event");
    return { choices, ...(usage ? { usage } : {}) };
  }

  get usage(): Usage | undefined {
    return this.usageValue;
  }

  assertSuccessfulEnd(): void {
    if (!this.complete) throw new Error("Provider completion ended without its success sentinel");
    if (this.choices.size !== this.expectedChoices) throw new Error("Provider completion ended with missing choices");
    for (let index = 0; index < this.expectedChoices; index += 1) {
      if (!this.choices.has(index) || !this.choices.get(index)?.finishReason) {
        throw new Error("Provider completion ended without all finish reasons");
      }
    }
  }

  finishChoices(): LegacyEventChoice[] {
    return [...this.choices.values()].sort((a, b) => a.index - b.index).map((choice) => ({
      index: choice.index,
      text: "",
      logprobs: null,
      finishReason: choice.finishReason,
    }));
  }

  outputChoices(): Array<Record<string, unknown>> {
    return [...this.choices.values()].sort((a, b) => a.index - b.index).map((choice) => ({
      text: choice.text,
      index: choice.index,
      logprobs: choice.logprobs ?? null,
      finish_reason: choice.finishReason,
    }));
  }
}

class LegacyCompletionWriter {
  private started = false;
  private ended = false;
  private responseBytes = 0;

  constructor(
    private readonly response: ServerResponse,
    private readonly meta: { id: string; created: number; model: string; stream: boolean },
  ) {}

  async emit(choices: LegacyEventChoice[], usage?: Usage): Promise<void> {
    if (!this.meta.stream || this.ended || (choices.length === 0 && usage === undefined)) return;
    const frame: Record<string, unknown> = {
      id: this.meta.id,
      object: "text_completion",
      created: this.meta.created,
      model: this.meta.model,
      choices: choices.map((choice) => ({
        text: choice.text,
        index: choice.index,
        ...(choice.logprobs === undefined ? {} : { logprobs: choice.logprobs }),
        finish_reason: choice.finishReason ?? null,
      })),
    };
    if (usage !== undefined && choices.length === 0) frame.usage = usage;
    await this.writeEvent(frame);
  }

  async finish(usage?: Usage): Promise<void> {
    if (!this.meta.stream || this.ended) return;
    await this.ensureStarted();
    if (usage !== undefined) {
      await this.writeEvent({
        id: this.meta.id,
        object: "text_completion",
        created: this.meta.created,
        model: this.meta.model,
        choices: [],
        usage,
      });
    }
    await this.write("data: [DONE]\n\n");
    this.ended = true;
    this.response.end();
  }

  async fail(code: string, message: string, upstreamStarted: boolean, status: number): Promise<void> {
    if (this.ended || this.response.destroyed || this.response.writableEnded) return;
    if (!this.response.headersSent) {
      this.ended = true;
      sendJson(this.response, status, apiError(code, message, { upstream_started: upstreamStarted }));
      return;
    }
    try {
      await this.write(`data: ${JSON.stringify(apiError(code, message, { upstream_started: upstreamStarted }))}\n\n`);
    } catch {
      this.ended = true;
      this.response.destroy();
      return;
    }
    this.ended = true;
    this.response.end();
  }

  private async ensureStarted(): Promise<void> {
    if (this.started || this.ended) return;
    this.started = true;
    this.response.statusCode = 200;
    this.response.setHeader("content-type", "text/event-stream; charset=utf-8");
    this.response.setHeader("cache-control", "no-cache, no-transform");
    this.response.setHeader("connection", "keep-alive");
    this.response.setHeader("x-accel-buffering", "no");
  }

  private async writeEvent(frame: Record<string, unknown>): Promise<void> {
    await this.ensureStarted();
    const serialized = JSON.stringify(frame);
    if (Buffer.byteLength(serialized, "utf8") > MAX_SSE_EVENT_BYTES) {
      throw new Error("Provider output event exceeded the configured limit");
    }
    await this.write(`data: ${serialized}\n\n`);
  }

  private async write(text: string): Promise<void> {
    if (this.response.destroyed || this.response.writableEnded) throw new Error("Local client disconnected");
    this.responseBytes += Buffer.byteLength(text, "utf8");
    if (!this.meta.stream && this.responseBytes > MAX_NON_STREAM_BYTES) throw new Error("Provider response exceeded the 8 MiB buffer limit");
    let accepted: boolean;
    try {
      accepted = this.response.write(text, "utf8");
    } catch {
      throw new Error("Local response writer failed");
    }
    if (accepted) return;
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const done = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.response.off("drain", onDrain);
        this.response.off("close", onClose);
        this.response.off("error", onError);
        error ? reject(error) : resolve();
      };
      const timer = setTimeout(() => done(new Error("Local client is too slow")), MAX_LOCAL_WRITE_WAIT_MS);
      const onDrain = () => done();
      const onClose = () => done(new Error("Local client disconnected"));
      const onError = () => done(new Error("Local response writer failed"));
      this.response.once("drain", onDrain);
      this.response.once("close", onClose);
      this.response.once("error", onError);
    });
  }
}

function validateLegacyRequest(value: unknown): LegacyRequest {
  if (!isRecord(value) || typeof value.model !== "string" || value.model.length < 1 || value.model.length > 128) {
    throw new Error("A configured model is required");
  }
  if (!("prompt" in value) || !isPrompt(value.prompt)) throw new Error("prompt must be text or token IDs");
  const promptCount = typeof value.prompt === "string" || (Array.isArray(value.prompt) && value.prompt.every((part) => typeof part === "number")) ? 1 : value.prompt.length;
  if (promptCount < 1 || promptCount > MAX_PROMPTS) throw new Error("prompt must contain between 1 and 8 prompts");
  if (value.stream !== undefined && typeof value.stream !== "boolean") throw new Error("stream must be a boolean");
  if (value.n !== undefined && (!Number.isInteger(value.n) || Number(value.n) < 1 || Number(value.n) > 8)) {
    throw new Error("n must be an integer from 1 to 8");
  }
  const n = value.n === undefined ? 1 : Number(value.n);
  const expectedChoices = promptCount * n;
  if (expectedChoices > MAX_CHOICES) throw new Error("prompt and n request too many choices");
  validateLegacyFields(value);

  const payload: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(value)) {
    if (key !== "model" && key !== "stream") payload[key] = field;
  }
  const streamOptions = value.stream_options as { include_usage?: boolean } | undefined;
  payload.stream_options = { ...streamOptions, include_usage: true };
  return {
    model: value.model,
    prompt: value.prompt,
    stream: value.stream === true,
    ...(streamOptions === undefined ? {} : { streamOptions: { includeUsage: streamOptions.include_usage === true } }),
    n,
    expectedChoices,
    payload,
  };
}

function isPrompt(value: unknown): value is Prompt {
  if (typeof value === "string") return true;
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_PROMPTS) return false;
  if (value.every((part) => typeof part === "string")) return true;
  if (value.every((part) => Number.isSafeInteger(part) && Number(part) >= 0)) return true;
  return value.every((part) => Array.isArray(part) && part.length > 0 && part.every((token) => Number.isSafeInteger(token) && Number(token) >= 0));
}

function validateLegacyFields(value: Record<string, unknown>): void {
  const allowed = new Set([
    "model", "prompt", "suffix", "max_tokens", "temperature", "top_p", "n", "stream", "logprobs", "echo", "stop",
    "presence_penalty", "frequency_penalty", "best_of", "logit_bias", "user", "seed", "stream_options",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("Request contains unsupported fields");
  if (value.suffix !== undefined && value.suffix !== null && (typeof value.suffix !== "string" || Buffer.byteLength(value.suffix, "utf8") > 1_048_576)) throw new Error("suffix must be a string or null");
  if (value.max_tokens !== undefined && (!Number.isSafeInteger(value.max_tokens) || Number(value.max_tokens) < 0)) throw new Error("max_tokens must be a non-negative integer");
  if (value.temperature !== undefined && !inRange(value.temperature, 0, 2)) throw new Error("temperature must be between 0 and 2");
  if (value.top_p !== undefined && !inRange(value.top_p, 0, 1)) throw new Error("top_p must be between 0 and 1");
  if (value.presence_penalty !== undefined && !inRange(value.presence_penalty, -2, 2)) throw new Error("presence_penalty must be between -2 and 2");
  if (value.frequency_penalty !== undefined && !inRange(value.frequency_penalty, -2, 2)) throw new Error("frequency_penalty must be between -2 and 2");
  if (value.best_of !== undefined && (!Number.isSafeInteger(value.best_of) || Number(value.best_of) < 1 || Number(value.best_of) > 20)) throw new Error("best_of must be an integer from 1 to 20");
  if (value.best_of !== undefined && Number(value.best_of) > 1) throw new Error("best_of greater than 1 is unsupported by the streaming provider route");
  if (value.logprobs !== undefined && value.logprobs !== null && (!Number.isInteger(value.logprobs) || Number(value.logprobs) < 0 || Number(value.logprobs) > 5)) throw new Error("logprobs must be an integer from 0 to 5 or null");
  if (value.echo !== undefined && typeof value.echo !== "boolean") throw new Error("echo must be a boolean");
  if (value.stop !== undefined && value.stop !== null && !(typeof value.stop === "string" || (Array.isArray(value.stop) && value.stop.length <= 4 && value.stop.every((item) => typeof item === "string")))) throw new Error("stop must be a string, an array of up to 4 strings, or null");
  if (value.stop !== undefined && typeof value.stop === "string" && Buffer.byteLength(value.stop, "utf8") > 500) throw new Error("stop strings are limited to 500 bytes");
  if (Array.isArray(value.stop) && value.stop.some((item) => Buffer.byteLength(item as string, "utf8") > 500)) throw new Error("stop strings are limited to 500 bytes");
  if (value.user !== undefined && (typeof value.user !== "string" || Buffer.byteLength(value.user, "utf8") > 256)) throw new Error("user must be a string up to 256 bytes");
  if (value.seed !== undefined && !Number.isSafeInteger(value.seed)) throw new Error("seed must be a safe integer");
  if (value.logit_bias !== undefined && (!isRecord(value.logit_bias) || Object.values(value.logit_bias).some((number) => !inRange(number, -100, 100)))) throw new Error("logit_bias values must be between -100 and 100");
  if (value.stream_options !== undefined) {
    if (!isRecord(value.stream_options) || Object.keys(value.stream_options).some((key) => key !== "include_usage") ||
        (value.stream_options.include_usage !== undefined && typeof value.stream_options.include_usage !== "boolean")) {
      throw new Error("stream_options may contain only a boolean include_usage");
    }
  }
}

function mergeLogprobs(previous: Logprobs | undefined, next: Logprobs): Logprobs {
  if (next === null) return previous ?? null;
  if (previous === undefined || previous === null) return structuredClone(next);
  const merged: Record<string, unknown> = { ...previous, ...next };
  for (const key of ["tokens", "token_logprobs", "top_logprobs", "text_offset"]) {
    const left = previous[key];
    const right = next[key];
    if (left !== undefined || right !== undefined) {
      if (!Array.isArray(left) || !Array.isArray(right)) throw new Error("Provider returned invalid logprobs");
      merged[key] = [...left, ...right];
    }
  }
  return merged;
}

function completionJson(id: string, created: number, model: string, converter: LegacyCompletionConverter, usage?: Usage): Record<string, unknown> {
  return {
    id,
    object: "text_completion",
    created,
    model,
    choices: converter.outputChoices(),
    ...(usage ? { usage } : {}),
  };
}

function gatewayUsage(frame: ResponseEndMessage): Usage | undefined {
  if (!frame.usage) return undefined;
  return {
    prompt_tokens: frame.usage.inputTokens,
    completion_tokens: frame.usage.outputTokens,
    total_tokens: frame.usage.totalTokens,
  };
}

function statusForGateway(code: string): number {
  if (code === "invalid_request") return 400;
  if (code === "unauthorized" || code === "credential_invalid") return 401;
  if (code === "forbidden" || code === "provider_disallowed" || code === "model_disallowed") return 403;
  if (code === "overloaded" || code === "session_expired") return 503;
  if (code === "upstream_rate_limited") return 429;
  if (code === "slow_client") return 408;
  if (code === "cancelled") return 499;
  return 502;
}

function safeValidationMessage(error: unknown): string {
  if (!(error instanceof Error)) return "Request fields are invalid";
  const allowed = [
    "A configured model is required", "prompt must be text or token IDs", "prompt must contain between 1 and 8 prompts",
    "stream must be a boolean", "n must be an integer from 1 to 8", "prompt and n request too many choices",
    "Request contains unsupported fields", "suffix must be a string or null", "max_tokens must be a non-negative integer",
    "temperature must be between 0 and 2", "top_p must be between 0 and 1", "presence_penalty must be between -2 and 2",
    "frequency_penalty must be between -2 and 2", "best_of must be an integer from 1 to 20",
    "best_of greater than 1 is unsupported by the streaming provider route", "logprobs must be an integer from 0 to 5 or null",
    "echo must be a boolean", "stop must be a string, an array of up to 4 strings, or null", "stop strings are limited to 500 bytes",
    "user must be a string up to 256 bytes", "seed must be a safe integer", "logit_bias values must be between -100 and 100",
    "stream_options may contain only a boolean include_usage",
  ];
  return allowed.includes(error.message) ? error.message : "Request fields are invalid";
}

function inRange(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= minimum && value <= maximum;
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > MAX_HTTP_BODY_BYTES) throw new BodyLimitError();
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new Error("invalid JSON");
  }
}

class BodyLimitError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.destroyed || response.writableEnded) return;
  response.statusCode = status;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.end(JSON.stringify(body));
}

function apiError(code: string, message: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { error: { message, type: code, code, ...extra } };
}
