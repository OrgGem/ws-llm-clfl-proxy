import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_RESPONSE_BYTES } from "@ws-proxy/shared";
import type { ResponseEndMessage, ResponseErrorMessage } from "@ws-proxy/shared";
import { GatewayOverloadedError, GatewayPayloadTooLargeError, type GatewayRequestInput } from "./gateway.js";
import { SseParser, type SseEvent } from "./sse.js";
import type { AdapterConfig, ModelConfig } from "./types.js";
import type { GatewayExecutor } from "./server.js";

const MAX_HTTP_BODY_BYTES = 1_048_576;
const MAX_SSE_EVENT_CHARS = 1_048_576;
const MAX_BUFFERED_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_LOCAL_WRITE_WAIT_MS = 14_000;

type JsonRecord = Record<string, unknown>;
type ForwardEvent = { kind: "event"; data: JsonRecord; id?: string };
type ResponsesTerminal = { kind: "terminal"; event: "response.completed" | "response.incomplete"; data: JsonRecord; id?: string };
type AcceptedEvent = ForwardEvent | ResponsesTerminal;

/** Handles the native, stateless OpenAI Responses create endpoint. */
export async function handleResponses(
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
    rawBody = await readJsonBody(request, MAX_HTTP_BODY_BYTES);
  } catch (error) {
    const status = error instanceof BodyLimitError ? 413 : 400;
    sendJson(response, status, apiError("invalid_request", error instanceof BodyLimitError ? "Request body exceeds the 1 MiB limit" : "Request body must be valid JSON"));
    return;
  }

  if (!isBoundedJsonValue(rawBody)) {
    sendJson(response, 400, apiError("invalid_request", "Request JSON exceeds the supported structural limits"));
    return;
  }
  if (!isRecord(rawBody) || typeof rawBody.model !== "string" ||
      (typeof rawBody.input !== "string" && !Array.isArray(rawBody.input))) {
    sendJson(response, 400, apiError("invalid_request", "Request requires a configured model and input string or array"));
    return;
  }
  if (rawBody.stream !== undefined && typeof rawBody.stream !== "boolean") {
    sendJson(response, 400, apiError("invalid_request", "stream must be a boolean"));
    return;
  }
  if (rawBody.background !== undefined && typeof rawBody.background !== "boolean") {
    sendJson(response, 400, apiError("invalid_request", "background must be a boolean"));
    return;
  }
  if (rawBody.background === true) {
    sendJson(response, 400, apiError("invalid_request", "Background Responses are not supported"));
    return;
  }
  if (rawBody.store !== undefined && typeof rawBody.store !== "boolean") {
    sendJson(response, 400, apiError("invalid_request", "store must be a boolean"));
    return;
  }
  if (rawBody.store === true) {
    sendJson(response, 400, apiError("invalid_request", "Responses storage is disabled; set store to false"));
    return;
  }
  if (containsItemReference(rawBody.input)) {
    sendJson(response, 400, apiError("invalid_request", "Remote input item references are not supported; submit prior items in input"));
    return;
  }
  if ((rawBody.previous_response_id !== undefined && rawBody.previous_response_id !== null) ||
      (rawBody.conversation !== undefined && rawBody.conversation !== null)) {
    sendJson(response, 400, apiError("invalid_request", "Server-managed conversations and previous response IDs are not supported; submit prior items in input"));
    return;
  }
  if ("url" in rawBody || "endpoint" in rawBody) {
    sendJson(response, 400, apiError("invalid_request", "Provider endpoint fields cannot be selected by the request"));
    return;
  }

  const model = config.models.find((candidate) => candidate.id === rawBody.model);
  if (!model) {
    sendJson(response, 404, apiError("model_not_found", "Model is not configured for this adapter"));
    return;
  }
  if (model.protocol !== "openai") {
    sendJson(response, 400, apiError("unsupported_api", "The Responses API requires an OpenAI-protocol provider"));
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

  const isStreaming = rawBody.stream === true;
  const payload = responsesPayload(rawBody);
  const requestId = randomUUID();
  const parser = new SseParser(MAX_SSE_EVENT_CHARS);
  const stream = new ResponsesStream(model);
  const writer = new ResponsesWriter(response, model.id, isStreaming);
  const abortController = new AbortController();
  let upstreamBytes = 0;

  request.once("aborted", () => abortController.abort());
  response.once("close", () => {
    if (!response.writableEnded) abortController.abort();
  });

  const callbacks = {
    onChunk: async (_seq: number, data: string) => {
      upstreamBytes += Buffer.byteLength(data, "utf8");
      const maxBytes = isStreaming ? MAX_RESPONSE_BYTES : MAX_BUFFERED_RESPONSE_BYTES;
      if (upstreamBytes > maxBytes) throw new ResponsesStreamError("Provider response exceeded the adapter limit");
      for (const event of parser.push(data)) {
        const accepted = stream.accept(event);
        if (isStreaming && accepted && !isTerminal(accepted)) await writer.event(accepted.data, accepted.id);
      }
    },
    onEnd: async (frame: ResponseEndMessage) => {
      for (const event of parser.finish()) {
        const accepted = stream.accept(event);
        if (isStreaming && accepted && !isTerminal(accepted)) await writer.event(accepted.data, accepted.id);
      }
      const terminal = stream.finish();
      if (isStreaming) await writer.complete(terminal);
      else sendJson(response, 200, terminal.data.response);
      void frame;
    },
    onError: async (frame: ResponseErrorMessage) => {
      await writer.fail(frame.code, safeGatewayMessage(frame.code), statusForGateway(frame.code), stream.nextSequenceNumber());
    },
    onInterrupted: async () => {
      await writer.fail("interrupted", "Gateway connection closed before a terminal Responses event; the request may have been processed or billed.", 502, stream.nextSequenceNumber());
    },
    onLocalFailure: async (error: Error) => {
      const code = error instanceof ResponsesProviderFailure ? "provider_error" : "invalid_upstream_response";
      const message = error instanceof ResponsesProviderFailure ? "The provider could not complete this Responses request." : "The provider returned an invalid or truncated Responses stream.";
      await writer.fail(code, message, 502, stream.nextSequenceNumber());
    },
  };

  const input: GatewayRequestInput & { api: "responses" } = {
    requestId,
    api: "responses",
    provider: model.provider,
    model: model.id,
    envelope,
    payload,
  };
  try {
    await gateway.execute(input, callbacks, abortController.signal);
  } catch (error) {
    if (!abortController.signal.aborted) {
      const code = error instanceof GatewayPayloadTooLargeError ? "request_too_large" : error instanceof GatewayOverloadedError ? "overloaded" : "gateway_unavailable";
      const message = error instanceof GatewayPayloadTooLargeError
        ? "The Responses request exceeds the Gateway payload limit."
        : error instanceof GatewayOverloadedError
          ? "Gateway is busy; retry as a new request."
          : "Gateway connection failed before the request was dispatched.";
      const status = error instanceof GatewayPayloadTooLargeError ? 413 : error instanceof GatewayOverloadedError ? 503 : 502;
      await writer.fail(code, message, status, stream.nextSequenceNumber());
    }
  }
}

function responsesPayload(body: JsonRecord): JsonRecord {
  const payload = { ...body };
  delete payload.model;
  delete payload.stream;
  delete payload.url;
  delete payload.endpoint;
  delete payload.previous_response_id;
  delete payload.conversation;
  payload.store = false;
  return payload;
}

class ResponsesStream {
  private created = false;
  private responseId: string | undefined;
  private terminal: ResponsesTerminal | undefined;
  private eventCount = 0;
  private lastSequence: number | undefined;
  private failureSequence: number | undefined;

  constructor(private readonly model: ModelConfig) {}

  accept(event: SseEvent): AcceptedEvent | undefined {
    if (this.terminal) throw new ResponsesStreamError("Provider sent data after a terminal Responses event");
    let parsed: unknown;
    try {
      parsed = JSON.parse(event.data);
    } catch {
      throw new ResponsesStreamError("Provider returned malformed Responses event JSON");
    }
    if (!isRecord(parsed) || typeof parsed.type !== "string") {
      throw new ResponsesStreamError("Provider returned an invalid Responses event");
    }
    const eventName = event.event ?? parsed.type;
    if (eventName !== parsed.type || (eventName !== "error" && !/^response\.[a-z][a-z0-9_.]*$/.test(eventName))) {
      throw new ResponsesStreamError("Provider returned inconsistent Responses event metadata");
    }
    this.validateSequence(parsed);
    this.eventCount += 1;

    const nestedResponse = isRecord(parsed.response) ? parsed.response : undefined;
    if (nestedResponse?.error !== undefined && nestedResponse.error !== null) {
      this.failureSequence = Number.isSafeInteger(parsed.sequence_number) ? Number(parsed.sequence_number) : undefined;
      throw new ResponsesProviderFailure();
    }
    if (eventName === "error" || eventName === "response.failed") {
      this.failureSequence = Number.isSafeInteger(parsed.sequence_number) ? Number(parsed.sequence_number) : undefined;
      throw new ResponsesProviderFailure();
    }
    if (eventName === "response.created") {
      if (this.created) throw new ResponsesStreamError("Provider repeated response.created");
      const response = isRecord(parsed.response) ? parsed.response : undefined;
      if (!response || typeof response.id !== "string" || response.id.length === 0) {
        throw new ResponsesStreamError("Provider response.created omitted response metadata");
      }
      this.created = true;
      this.responseId = response.id;
    } else if (!this.created) {
      throw new ResponsesStreamError("Provider emitted Responses data before response.created");
    }

    if (nestedResponse && typeof nestedResponse.id === "string" && this.responseId && nestedResponse.id !== this.responseId) {
      throw new ResponsesStreamError("Provider changed the Responses response ID mid-stream");
    }
    if (eventName === "response.completed" || eventName === "response.incomplete") {
      if (!nestedResponse || nestedResponse.object !== "response" || typeof nestedResponse.id !== "string" ||
          nestedResponse.id !== this.responseId || !Array.isArray(nestedResponse.output) ||
          nestedResponse.status !== (eventName === "response.completed" ? "completed" : "incomplete")) {
        throw new ResponsesStreamError("Provider terminal status did not match its Responses event");
      }
      const terminal: ResponsesTerminal = {
        kind: "terminal",
        event: eventName,
        data: this.rewriteModel(parsed),
        ...(event.id && isSafeEventId(event.id) ? { id: event.id } : {}),
      };
      this.terminal = terminal;
      return terminal;
    }
    return {
      kind: "event",
      data: this.rewriteModel(parsed),
      ...(event.id && isSafeEventId(event.id) ? { id: event.id } : {}),
    };
  }

  finish(): ResponsesTerminal {
    if (!this.created || !this.terminal) throw new ResponsesStreamError("Provider stream ended without a successful Responses terminal event");
    return this.terminal;
  }

  nextSequenceNumber(): number {
    if (this.failureSequence !== undefined) return this.failureSequence;
    if (this.terminal) {
      if (Number.isSafeInteger(this.terminal.data.sequence_number)) return Number(this.terminal.data.sequence_number);
      if (this.lastSequence !== undefined) return this.lastSequence + 1;
      return Math.max(0, this.eventCount - 1);
    }
    return this.lastSequence === undefined ? this.eventCount : this.lastSequence + 1;
  }

  private rewriteModel(event: JsonRecord): JsonRecord {
    const output = { ...event };
    if (isRecord(event.response)) output.response = { ...event.response, model: this.model.id };
    if (typeof event.model === "string") output.model = this.model.id;
    return output;
  }

  private validateSequence(event: JsonRecord): void {
    if (event.sequence_number === undefined) return;
    if (!Number.isSafeInteger(event.sequence_number) || Number(event.sequence_number) < 0) {
      throw new ResponsesStreamError("Provider returned an invalid Responses sequence number");
    }
    const sequence = Number(event.sequence_number);
    if (this.lastSequence === undefined) {
      if (this.eventCount !== 0 || sequence !== 0) throw new ResponsesStreamError("Provider Responses sequence did not start at zero");
    } else if (sequence !== this.lastSequence + 1) {
      throw new ResponsesStreamError("Provider Responses sequence was not contiguous");
    }
    this.lastSequence = sequence;
  }
}

class ResponsesWriter {
  private started = false;
  private ended = false;

  constructor(private readonly response: ServerResponse, private readonly model: string, private readonly streaming: boolean) {}

  async event(event: JsonRecord, id?: string): Promise<void> {
    if (!this.streaming || this.ended) return;
    const name = typeof event.type === "string" ? event.type : "error";
    const encoded = JSON.stringify(event);
    if (Buffer.byteLength(encoded, "utf8") > MAX_SSE_EVENT_CHARS) throw new ResponsesStreamError("Responses event exceeded the adapter limit");
    await this.ensureStarted();
    await this.write(`${id ? `id: ${id}\n` : ""}event: ${name}\ndata: ${encoded}\n\n`);
  }

  async complete(terminal: ResponsesTerminal): Promise<void> {
    if (!this.streaming || this.ended) return;
    await this.event(terminal.data, terminal.id);
    this.ended = true;
    this.response.end();
  }

  async fail(code: string, message: string, status: number, sequenceNumber: number): Promise<void> {
    if (this.ended || this.response.destroyed || this.response.writableEnded) return;
    if (!this.response.headersSent) {
      this.ended = true;
      sendJson(this.response, status, apiError(code, message));
      return;
    }
    try {
      await this.event({ type: "error", code, message, param: null, sequence_number: sequenceNumber });
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

  private async write(text: string): Promise<void> {
    if (this.response.destroyed || this.response.writableEnded) throw new Error("Local response writer failed");
    let accepted: boolean;
    try {
      accepted = this.response.write(text, "utf8");
    } catch {
      throw new Error("Local response writer failed");
    }
    if (accepted) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => done(new Error("Local response writer stalled")), MAX_LOCAL_WRITE_WAIT_MS);
      const onDrain = () => done();
      const onClose = () => done(new Error("Local response writer closed"));
      const onError = () => done(new Error("Local response writer failed"));
      const cleanup = () => {
        clearTimeout(timer);
        this.response.off("drain", onDrain);
        this.response.off("close", onClose);
        this.response.off("error", onError);
      };
      const done = (error?: Error) => {
        cleanup();
        if (error) reject(error);
        else resolve();
      };
      this.response.once("drain", onDrain);
      this.response.once("close", onClose);
      this.response.once("error", onError);
    });
  }
}

class ResponsesStreamError extends Error {}
class ResponsesProviderFailure extends Error {}
class BodyLimitError extends Error {}

function isTerminal(event: AcceptedEvent): event is ResponsesTerminal {
  return event.kind === "terminal";
}

function isSafeEventId(value: string): boolean {
  return value.length > 0 && value.length <= 256 && /^[\x20-\x7e]+$/.test(value);
}

function containsItemReference(value: unknown): boolean {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const current = stack.pop();
    if (Array.isArray(current)) {
      for (const child of current) stack.push(child);
    } else if (isRecord(current)) {
      if (current.type === "item_reference") return true;
      for (const child of Object.values(current)) stack.push(child);
    }
  }
  return false;
}

function isBoundedJsonValue(root: unknown): boolean {
  const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  let visited = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    visited += 1;
    if (visited > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) return false;
    const value = current.value;
    if (value === null || typeof value === "string" || typeof value === "boolean") continue;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return false;
      continue;
    }
    if (Array.isArray(value)) {
      for (const child of value) stack.push({ value: child, depth: current.depth + 1 });
      continue;
    }
    if (typeof value === "object") {
      for (const child of Object.values(value)) stack.push({ value: child, depth: current.depth + 1 });
      continue;
    }
    return false;
  }
  return true;
}

async function readJsonBody(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > maxBytes) throw new BodyLimitError();
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new Error("invalid JSON");
  }
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.destroyed || response.writableEnded) return;
  response.statusCode = status;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.end(JSON.stringify(body));
}

function apiError(code: string, message: string): JsonRecord {
  return { error: { message, type: code, code } };
}

function safeGatewayMessage(code: string): string {
  if (code === "credential_invalid") return "The configured provider credential is unavailable or expired.";
  if (code === "provider_disallowed" || code === "model_disallowed") return "This model is not authorized for the configured provider.";
  if (code === "upstream_rate_limited") return "The provider is rate limiting this request.";
  if (code === "slow_client") return "The local client is too slow to receive this response.";
  if (code === "invalid_request") return "Gateway rejected the Responses request.";
  return "Gateway could not complete the Responses request.";
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

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
