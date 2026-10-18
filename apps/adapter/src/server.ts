import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { ConfigStore } from "./config.js";
import { TokenProvider } from "./auth.js";
import { GatewayClient, GatewayOverloadedError, GatewayPayloadTooLargeError, type GatewayCallbacks, type GatewayRequestInput } from "./gateway.js";
import { CompletionAccumulator, createCompletionId, buildProviderPayload, ProviderStreamConverter, type OpenAiRequest, type ProviderDelta, type Provider, type OpenAiUsage } from "./provider.js";
import { SseParser } from "./sse.js";
import { handleResponses } from "./responses.js";
import { handleLegacyCompletion } from "./legacy-completions.js";
import type { AdapterConfig } from "./types.js";
import type { ResponseEndMessage, ResponseErrorMessage } from "@ws-proxy/shared";

const MAX_HTTP_BODY_BYTES = 1_048_576;
const MAX_SSE_EVENT_CHARS = 1_048_576;
const MAX_LOCAL_WRITE_WAIT_MS = 14_000;
const MAX_NON_STREAM_RESPONSE_BYTES = 8 * 1024 * 1024;

export interface GatewayExecutor {
  execute(input: GatewayRequestInput, callbacks: GatewayCallbacks, signal?: AbortSignal): Promise<void>;
  close(): void;
}

export interface AdapterServerOptions {
  configStore: ConfigStore;
  /** Test-only override; production binds to 127.0.0.1 and uses config.port. */
  portOverride?: number;
  gateway?: GatewayExecutor;
  tokenProvider?: TokenProvider;
  /** Restrict concurrently active Gateway sockets; set to 1 for one-socket benchmarks. */
  maxGatewaySessions?: number;
}

export interface RunningAdapter {
  port: number;
  close(): Promise<void>;
}

export async function startAdapter(options: AdapterServerOptions): Promise<RunningAdapter> {
  const config = await options.configStore.load();
  const tokenProvider = options.tokenProvider ?? new TokenProvider(options.configStore);
  const maxGatewaySessions = options.maxGatewaySessions ?? gatewaySessionLimitFromEnvironment();
  if (!Number.isInteger(maxGatewaySessions) || maxGatewaySessions < 1 || maxGatewaySessions > 2) {
    throw new Error("Gateway session limit must be one or two");
  }
  const gateway = options.gateway ?? new GatewayClient(config.gatewayUrl, tokenProvider, maxGatewaySessions);
  const server = createServer((request, response) => {
    void handleRequest(request, response, config, gateway, maxGatewaySessions).catch(() => {
      if (response.destroyed || response.writableEnded) return;
      if (!response.headersSent) {
        sendJson(response, 500, apiError("internal_error", "The adapter could not complete this request"));
      } else {
        response.destroy();
      }
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  const port = options.portOverride ?? config.port;
  await listen(server, port);
  const address = server.address();
  if (!address || typeof address === "string") {
    gateway.close();
    throw new Error("Adapter failed to bind its loopback listener");
  }
  return {
    port: address.port,
    close: async () => {
      gateway.close();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  config: AdapterConfig,
  gateway: GatewayExecutor,
  maxGatewaySessions: number,
): Promise<void> {
  const port = request.socket.localPort ?? config.port;
  const origin = request.headers.origin;
  if (!isLoopbackRemote(request.socket.remoteAddress) || !isSafeHost(request.headers.host, port) || !isSafeOrigin(origin)) {
    sendJson(response, 403, apiError("forbidden", "Request host or origin is not allowed"));
    return;
  }
  if (typeof origin === "string") {
    response.setHeader("access-control-allow-origin", origin);
    response.setHeader("vary", "Origin");
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
    response.setHeader("access-control-max-age", "600");
  }
  if (request.method === "OPTIONS") {
    response.statusCode = 204;
    response.end();
    return;
  }
  if (!hasLocalBearer(request.headers.authorization, config.localBearerToken)) {
    sendJson(response, 401, apiError("unauthorized", "A valid local bearer token is required"));
    return;
  }
  let url: URL;
  try {
    url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  } catch {
    sendJson(response, 400, apiError("invalid_request", "Request target is invalid"));
    return;
  }
  if (url.search || url.hash) {
    sendJson(response, 400, apiError("invalid_request", "Query strings and fragments are not accepted"));
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/models") {
    response.setHeader("x-ws-proxy-gateway-session-limit", String(maxGatewaySessions));
    sendJson(response, 200, {
      object: "list",
      data: config.models.map((model) => ({ id: model.id, object: "model", created: 0, owned_by: "ws-llm-clfl-proxy" })),
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
    await handleCompletion(request, response, config, gateway);
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/responses") {
    await handleResponses(request, response, config, gateway);
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/completions") {
    await handleLegacyCompletion(request, response, config, gateway);
    return;
  }
  sendJson(response, 404, apiError("not_found", "Endpoint not found"));
}

async function handleCompletion(request: IncomingMessage, response: ServerResponse, config: AdapterConfig, gateway: GatewayExecutor): Promise<void> {
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
  if (!isRecord(rawBody) || typeof rawBody.model !== "string" || !Array.isArray(rawBody.messages)) {
    sendJson(response, 400, apiError("invalid_request", "Request requires a model and messages array"));
    return;
  }
  if (rawBody.stream !== undefined && typeof rawBody.stream !== "boolean") {
    sendJson(response, 400, apiError("invalid_request", "stream must be a boolean"));
    return;
  }
  const model = config.models.find((candidate) => candidate.id === rawBody.model);
  if (!model) {
    sendJson(response, 404, apiError("model_not_found", "Model is not configured for this adapter"));
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
  let payload: Record<string, unknown>;
  try {
    payload = buildProviderPayload(model.protocol, rawBody as OpenAiRequest);
  } catch (error) {
    sendJson(response, 400, apiError("invalid_request", safeLocalMessage(error)));
    return;
  }
  const isStreaming = rawBody.stream === true;
  const includeUsage = isStreaming && isRecord(rawBody.stream_options) && rawBody.stream_options.include_usage === true;
  const requestId = crypto.randomUUID();
  const completionId = createCompletionId();
  const created = Math.floor(Date.now() / 1000);
  const converter = new ProviderStreamConverter(model.protocol, typeof rawBody.n === "number" ? rawBody.n : 1);
  const accumulator = new CompletionAccumulator(!isStreaming);
  const parser = new SseParser(MAX_SSE_EVENT_CHARS);
  const abortController = new AbortController();
  const writer = new CompletionWriter(response, {
    requestId: completionId,
    created,
    model: model.id,
    isStreaming,
    includeUsage,
  });
  const pendingFinishReasons = new Map<number, string>();
  let nonStreamingBytes = 0;

  const handleUpdates = async (updates: ProviderDelta[]) => {
    for (const update of updates) {
      accumulator.add(update);
      if (isStreaming) {
        if (update.finishReason) pendingFinishReasons.set(update.index, update.finishReason);
        const { finishReason: _finishReason, ...withoutFinishReason } = update;
        await writer.emit(withoutFinishReason);
      }
    }
  };

  request.once("aborted", () => abortController.abort());
  response.once("close", () => {
    if (!response.writableEnded) abortController.abort();
  });

  const callbacks: GatewayCallbacks = {
    onChunk: async (_seq, data) => {
      if (!isStreaming) {
        nonStreamingBytes += Buffer.byteLength(data, "utf8");
        if (nonStreamingBytes > MAX_NON_STREAM_RESPONSE_BYTES) throw new Error("Non-stream response exceeded the adapter limit");
      }
      const events = parser.push(data);
      for (const event of events) {
        await handleUpdates(converter.consume(event));
      }
    },
    onEnd: async (frame) => {
      for (const event of parser.finish()) {
        await handleUpdates(converter.consume(event));
      }
      if (!converter.completed) throw new Error("Provider stream ended without its success sentinel");
      const usage = converter.usage ?? gatewayUsage(frame);
      if (isStreaming) {
        await writer.finish(pendingFinishReasons, usage, converter.systemFingerprint);
      } else {
        sendJson(response, 200, completionJson(completionId, created, model.id, accumulator, usage, converter.systemFingerprint));
      }
    },
    onError: async (frame) => {
      await writer.fail(frame.code, frame.message, frame.upstreamStarted, statusForGateway(frame.code));
    },
    onInterrupted: async (message) => {
      await writer.fail("interrupted", message, true, 502);
    },
    onLocalFailure: async (error) => {
      await writer.fail("stream_error", safeLocalMessage(error), true, 502);
    },
  };

  const input: GatewayRequestInput = {
    requestId,
    provider: model.provider,
    model: model.id,
    envelope,
    payload,
  };
  try {
    await gateway.execute(input, callbacks, abortController.signal);
  } catch (error) {
    if (!abortController.signal.aborted) {
      await writer.fail(
        error instanceof GatewayPayloadTooLargeError ? "request_too_large" : error instanceof GatewayOverloadedError ? "overloaded" : "gateway_unavailable",
        error instanceof GatewayPayloadTooLargeError ? error.message : error instanceof GatewayOverloadedError ? error.message : "Gateway connection failed before dispatch",
        false,
        error instanceof GatewayPayloadTooLargeError ? 413 : error instanceof GatewayOverloadedError ? 503 : 502,
      );
    }
  }
}

class CompletionWriter {
  private started = false;
  private ended = false;
  private readonly startedChoices = new Set<number>();
  private systemFingerprint: string | undefined;

  constructor(
    private readonly response: ServerResponse,
    private readonly meta: { requestId: string; created: number; model: string; isStreaming: boolean; includeUsage: boolean },
  ) {}

  async emit(update: ProviderDelta): Promise<void> {
    if (!this.meta.isStreaming || this.ended) return;
    if (update.systemFingerprint) this.systemFingerprint = update.systemFingerprint;
    if (Object.keys(update.delta).length === 0 && update.logprobs === undefined) return;
    await this.ensureChoiceStarted(update.index);
    await this.write(`data: ${JSON.stringify(this.chunk(update.delta, null, update.index, update.logprobs))}\n\n`);
  }

  async finish(finishReasons: Map<number, string>, usage?: OpenAiUsage, systemFingerprint?: string): Promise<void> {
    if (!this.meta.isStreaming || this.ended) return;
    if (systemFingerprint) this.systemFingerprint = systemFingerprint;
    for (const [index, finishReason] of [...finishReasons].sort(([a], [b]) => a - b)) {
      await this.ensureChoiceStarted(index);
      await this.write(`data: ${JSON.stringify(this.chunk({}, finishReason, index))}\n\n`);
    }
    if (this.meta.includeUsage && usage) {
      await this.write(`data: ${JSON.stringify({
        id: this.meta.requestId,
        object: "chat.completion.chunk",
        created: this.meta.created,
        model: this.meta.model,
        choices: [],
        usage,
      })}\n\n`);
    }
    await this.write("data: [DONE]\n\n");
    this.ended = true;
    this.response.end();
  }

  async fail(code: string, message: string, upstreamStarted: boolean, status: number): Promise<void> {
    if (this.ended || this.response.destroyed) return;
    const body = apiError(code, message, { upstream_started: upstreamStarted });
    if (!this.response.headersSent) {
      this.ended = true;
      sendJson(this.response, status, body);
      return;
    }
    try {
      await this.write(`data: ${JSON.stringify(body)}\n\n`);
    } catch {
      this.ended = true;
      this.response.destroy();
      return;
    }
    this.ended = true;
    this.response.end();
  }

  private async ensureChoiceStarted(index: number): Promise<void> {
    await this.ensureStarted();
    if (this.startedChoices.has(index)) return;
    this.startedChoices.add(index);
    await this.write(`data: ${JSON.stringify(this.chunk({ role: "assistant" }, null, index))}\n\n`);
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

  private chunk(delta: Record<string, unknown>, finishReason: string | null, index: number, logprobs?: unknown): Record<string, unknown> {
    return {
      id: this.meta.requestId,
      object: "chat.completion.chunk",
      ...(this.systemFingerprint ? { system_fingerprint: this.systemFingerprint } : {}),
      created: this.meta.created,
      model: this.meta.model,
      choices: [{ index, delta, finish_reason: finishReason, ...(logprobs === undefined ? {} : { logprobs }) }],
    };
  }

  private async write(text: string): Promise<void> {
    if (this.response.destroyed || this.response.writableEnded) throw new Error("Local client disconnected");
    let accepted: boolean;
    try {
      accepted = this.response.write(text, "utf8");
    } catch {
      throw new Error("Local response writer failed");
    }
    if (accepted) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => done(new Error("Local client is too slow")), MAX_LOCAL_WRITE_WAIT_MS);
      const onDrain = () => done();
      const onClose = () => done(new Error("Local client disconnected"));
      const onError = () => done(new Error("Local response writer failed"));
      const cleanup = () => {
        clearTimeout(timer);
        this.response.off("drain", onDrain);
        this.response.off("close", onClose);
        this.response.off("error", onError);
      };
      const done = (error?: Error) => {
        cleanup();
        error ? reject(error) : resolve();
      };
      this.response.once("drain", onDrain);
      this.response.once("close", onClose);
      this.response.once("error", onError);
    });
  }
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

class BodyLimitError extends Error {}

function isSafeHost(hostHeader: string | undefined, port: number): boolean {
  if (!hostHeader || hostHeader.length > 256) return false;
  let url: URL;
  try {
    url = new URL(`http://${hostHeader}`);
  } catch {
    return false;
  }
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return false;
  if (!isLoopbackHostname(url.hostname)) return false;
  return url.port === String(port);
}

function isSafeOrigin(origin: string | undefined): boolean {
  if (origin === undefined) return true;
  if (origin.length > 512 || origin === "null") return false;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  return (url.protocol === "http:" || url.protocol === "https:")
    && isLoopbackHostname(url.hostname)
    && !url.username
    && !url.password
    && url.pathname === "/"
    && !url.search
    && !url.hash;
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1" || hostname === "[::1]";
}

function isLoopbackRemote(address: string | undefined): boolean {
  if (!address) return false;
  if (address === "::1" || address === "127.0.0.1") return true;
  if (address.startsWith("::ffff:")) return isLoopbackRemote(address.slice(7));
  const family = isIP(address);
  return family === 4 && address.split(".")[0] === "127";
}

function hasLocalBearer(header: string | string[] | undefined, expected: string): boolean {
  if (typeof header !== "string" || header.length > 512) return false;
  const match = /^Bearer ([A-Za-z0-9_-]+)$/i.exec(header);
  if (!match?.[1]) return false;
  const supplied = Buffer.from(match[1], "utf8");
  const target = Buffer.from(expected, "utf8");
  return supplied.byteLength === target.byteLength && timingSafeEqual(supplied, target);
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

function completionJson(id: string, created: number, model: string, accumulator: CompletionAccumulator, usage?: OpenAiUsage, systemFingerprint?: string): Record<string, unknown> {
  const choices = accumulator.choiceIndices.map((index) => {
    const result = accumulator.snapshot(index);
    const message: Record<string, unknown> = { role: "assistant", content: result.content || null };
    if (result.refusal) message.refusal = result.refusal;
    if (result.toolCalls.length > 0) message.tool_calls = result.toolCalls;
    if (result.reasoningContent) message.reasoning_content = result.reasoningContent;
    if (result.functionCall) message.function_call = result.functionCall;
    return { index, message, finish_reason: result.finishReason, ...(result.logprobs === undefined ? {} : { logprobs: result.logprobs }) };
  });
  return {
    id,
    object: "chat.completion",
    ...(systemFingerprint ? { system_fingerprint: systemFingerprint } : {}),
    created,
    model,
    choices,
    ...(usage ? { usage } : {}),
  };
}

function gatewayUsage(frame: ResponseEndMessage): OpenAiUsage | undefined {
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

function gatewaySessionLimitFromEnvironment(): number {
  const value = process.env.WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS;
  if (value === undefined) return 2;
  if (value === "1" || value === "2") return Number(value);
  throw new Error("WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS must be 1 or 2");
}

function safeLocalMessage(error: unknown): string {
  if (error instanceof Error && [
    "messages must be a non-empty array",
    "Each message must have a role",
    "Anthropic system messages must be text",
    "Anthropic user messages must be text in this adapter version",
    "Tool results require tool_call_id",
    "Assistant tool calls require id and function name",
    "Assistant tool call arguments must be valid JSON for Anthropic",
    "Invalid assistant tool call",
    "Anthropic tools must use the OpenAI function tool shape",
    "n must be an integer from 1 to 8",
    "Anthropic supports exactly one completion choice per request",
    "stream_options.include_usage must be a boolean",
    "This adapter supports text output only",
    "Audio output is not supported by this adapter",
    "Audio message content is not supported by this adapter",
    "Provider endpoint fields cannot be selected by the request",
    "Non-stream response exceeded the adapter limit",
    "Provider returned too many tool calls",
  ].includes(error.message)) return error.message;
  if (error instanceof Error && error.message === "Unsupported message role for Anthropic") return error.message;
  if (error instanceof Error && [
    "Provider returned malformed SSE JSON",
    "Provider returned an invalid SSE event",
    "Provider stream returned an error",
    "Provider stream ended without its success sentinel",
    "Provider returned tool arguments before tool metadata",
    "SSE event exceeded the configured buffer limit",
  ].includes(error.message)) return error.message;
  return "The adapter could not complete this request";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "127.0.0.1");
  });
}
