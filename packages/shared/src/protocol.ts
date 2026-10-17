import { z } from "zod";
import { CredentialEnvelopeSchema } from "./envelope.js";

export const GATEWAY_PROTOCOL_VERSION = 1 as const;
export const MAX_GATEWAY_FRAME_BYTES = 1_048_576;
export const MAX_REQUEST_FRAME_BYTES = 1_048_576;
export const MAX_REQUEST_START_FRAME_BYTES = MAX_REQUEST_FRAME_BYTES;
export const MIN_REQUEST_PAYLOAD_BYTES = 1_024;
export const MAX_REQUEST_PAYLOAD_BYTES = 1_048_576;
export const MAX_RESPONSE_FRAME_BYTES = 262_144;
export const MAX_CONTROL_FRAME_BYTES = 4_096;
export const MAX_IN_FLIGHT = 8;
export const MAX_IN_FLIGHT_REQUESTS = MAX_IN_FLIGHT;
export const MAX_CHUNK_BYTES = 32_768;
export const ACK_WINDOW = 8;
export const ACK_TIMEOUT_MS = 15_000;
export const MAX_REQUEST_DURATION_MS = 300_000;
export const MIN_SESSION_SECONDS = 30;
export const MAX_SESSION_SECONDS = 300;
export const MAX_RESPONSE_BYTES = 16_777_216;
export const MAX_REQUEST_IDS_PER_SOCKET = 1_024;
export const MAX_JSON_DEPTH = 64;
export const MAX_JSON_NODES = 65_536;

const IdentifierSchema = z.string().min(1).max(128);
const ModelNameSchema = z.string().min(1).max(128).regex(/^[^\u0000-\u001f\u007f]+$/);
const SequenceSchema = z.number().int().nonnegative().safe();
const TerminalSequenceSchema = z.number().int().min(-1).safe();
const UnixSecondsSchema = z.number().int().nonnegative().safe();
const RequestIdSchema = z
  .uuid()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

function isBoundedJsonValue(value: unknown): boolean {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const seen = new Set<object>();
  let visited = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    visited += 1;
    if (visited > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) return false;

    const item = current.value;
    if (item === null || typeof item === "string" || typeof item === "boolean") continue;
    if (typeof item === "number") {
      if (!Number.isFinite(item)) return false;
      continue;
    }
    if (Array.isArray(item)) {
      if (seen.has(item)) return false;
      seen.add(item);
      for (const child of item) stack.push({ value: child, depth: current.depth + 1 });
      continue;
    }
    if (typeof item === "object") {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) return false;
      if (seen.has(item)) return false;
      seen.add(item);
      for (const child of Object.values(item)) {
        stack.push({ value: child, depth: current.depth + 1 });
      }
      continue;
    }
    return false;
  }

  return true;
}

const JsonObjectSchema = z
  .record(z.string(), z.unknown())
  .superRefine((value, context) => {
    if (!isBoundedJsonValue(value)) {
      context.addIssue({
        code: "custom",
        message: `must be JSON data within depth ${MAX_JSON_DEPTH} and ${MAX_JSON_NODES} values`,
      });
    }
  });

const SessionReadySchema = z
  .object({
    event: z.literal("session.ready"),
    protocol: z.literal(GATEWAY_PROTOCOL_VERSION),
    connectionId: IdentifierSchema,
    maxInFlight: z.number().int().min(1).max(MAX_IN_FLIGHT_REQUESTS),
    maxPayloadBytes: z.number().int().min(MIN_REQUEST_PAYLOAD_BYTES).max(MAX_REQUEST_PAYLOAD_BYTES),
    maxSessionSeconds: z.number().int().min(MIN_SESSION_SECONDS).max(MAX_SESSION_SECONDS),
    maxChunkBytes: z.literal(MAX_CHUNK_BYTES),
    ackWindow: z.literal(ACK_WINDOW),
    maxRequestFrameBytes: z.literal(MAX_REQUEST_FRAME_BYTES),
    maxResponseFrameBytes: z.literal(MAX_RESPONSE_FRAME_BYTES),
    tokenExpiresAt: UnixSecondsSchema,
  })
  .strict();

const RequestStartSchema = z
  .object({
    event: z.literal("request.start"),
    requestId: RequestIdSchema,
    provider: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
    model: ModelNameSchema,
    envelope: CredentialEnvelopeSchema,
    payload: JsonObjectSchema,
  })
  .strict()
  .superRefine((message, context) => {
    for (const forbidden of ["model", "stream", "url", "endpoint"]) {
      if (forbidden in message.payload) {
        context.addIssue({
          code: "custom",
          path: ["payload", forbidden],
          message: `must be selected by the server, not included in payload`,
        });
      }
    }
  });

const RequestStartAckSchema = z
  .object({
    event: z.literal("request.start"),
    op: z.literal("ack"),
    requestId: RequestIdSchema,
    ackSeq: SequenceSchema,
  })
  .strict();

const RequestCancelSchema = z
  .object({
    event: z.literal("request.cancel"),
    requestId: RequestIdSchema,
  })
  .strict();

const ResponseChunkSchema = z
  .object({
    event: z.literal("response.chunk"),
    requestId: RequestIdSchema,
    seq: SequenceSchema,
    data: z
      .string()
      .min(1)
      .refine(
        (value) => new TextEncoder().encode(value).byteLength <= MAX_CHUNK_BYTES,
        `must be at most ${MAX_CHUNK_BYTES} UTF-8 bytes`,
      ),
  })
  .strict();

const ResponseEndSchema = z
  .object({
    event: z.literal("response.end"),
    requestId: RequestIdSchema,
    lastSeq: TerminalSequenceSchema,
    usage: z
      .object({
        inputTokens: SequenceSchema,
        outputTokens: SequenceSchema,
        totalTokens: SequenceSchema,
      })
      .strict()
      .optional(),
  })
  .strict();

const ResponseErrorSchema = z
  .object({
    event: z.literal("response.error"),
    requestId: RequestIdSchema,
    lastSeq: TerminalSequenceSchema,
    code: z.enum([
      "invalid_request",
      "unauthorized",
      "forbidden",
      "credential_invalid",
      "provider_disallowed",
      "model_disallowed",
      "overloaded",
      "upstream_rate_limited",
      "upstream_error",
      "upstream_timeout",
      "response_too_large",
      "slow_client",
      "cancelled",
      "session_expired",
      "internal_error",
    ]),
    message: z.string().min(1).max(1_024),
    upstreamStarted: z.boolean(),
    retryable: z.boolean(),
  })
  .strict();

const SessionDrainingSchema = z
  .object({
    event: z.literal("session.draining"),
    reason: z.enum(["token_expiring", "server_shutdown", "policy"]),
    reconnectAfterMs: z.number().int().nonnegative().safe().optional(),
  })
  .strict();

export const GatewayMessageSchema = z.union([
  SessionReadySchema,
  RequestStartSchema,
  RequestStartAckSchema,
  RequestCancelSchema,
  ResponseChunkSchema,
  ResponseEndSchema,
  ResponseErrorSchema,
  SessionDrainingSchema,
]);

export const GatewayClientFrameSchema = z.union([
  RequestStartSchema,
  RequestStartAckSchema,
  RequestCancelSchema,
]);

export const GatewayServerFrameSchema = z.union([
  SessionReadySchema,
  ResponseChunkSchema,
  ResponseEndSchema,
  ResponseErrorSchema,
  SessionDrainingSchema,
]);

export type SessionReadyMessage = z.infer<typeof SessionReadySchema>;
export type RequestStartMessage = z.infer<typeof RequestStartSchema>;
export type RequestStartAckMessage = z.infer<typeof RequestStartAckSchema>;
export type RequestCancelMessage = z.infer<typeof RequestCancelSchema>;
export type ResponseChunkMessage = z.infer<typeof ResponseChunkSchema>;
export type ResponseEndMessage = z.infer<typeof ResponseEndSchema>;
export type ResponseErrorMessage = z.infer<typeof ResponseErrorSchema>;
export type SessionDrainingMessage = z.infer<typeof SessionDrainingSchema>;
export type GatewayMessage = z.infer<typeof GatewayMessageSchema>;
export type GatewayClientFrame = z.infer<typeof GatewayClientFrameSchema>;
export type GatewayServerFrame = z.infer<typeof GatewayServerFrameSchema>;
export type GatewayEventName = GatewayMessage["event"];

export type GatewayProtocolErrorCode = "frame_too_large" | "invalid_json" | "invalid_message";

export class GatewayProtocolError extends Error {
  readonly code: GatewayProtocolErrorCode;

  constructor(code: GatewayProtocolErrorCode, message: string) {
    super(message);
    this.name = "GatewayProtocolError";
    this.code = code;
  }
}

function getEvent(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null || !("event" in value)) return undefined;
  const event = (value as { event?: unknown }).event;
  return typeof event === "string" ? event : undefined;
}

/** Validates an already-decoded event object and returns the typed message. */
export function parseGatewayMessage(value: unknown): GatewayMessage {
  const parsed = GatewayMessageSchema.safeParse(value);
  if (!parsed.success) {
    throw new GatewayProtocolError("invalid_message", "Gateway message does not match protocol v1");
  }
  if (
    parsed.data.event === "request.start" &&
    !("op" in parsed.data) &&
    !isBoundedJsonValue(parsed.data.payload)
  ) {
    throw new GatewayProtocolError("invalid_message", "Request payload is not bounded JSON data");
  }
  return parsed.data;
}

/** Parses a WebSocket JSON text frame after enforcing wire-size limits. */
export function parseGatewayFrame(text: string): GatewayMessage {
  const frameBytes = new TextEncoder().encode(text).byteLength;
  if (frameBytes > MAX_GATEWAY_FRAME_BYTES) {
    throw new GatewayProtocolError("frame_too_large", "Gateway frame exceeds the 1 MiB limit");
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(text) as unknown;
  } catch {
    throw new GatewayProtocolError("invalid_json", "Gateway frame must contain valid JSON");
  }

  const message = parseGatewayMessage(decoded);
  const isNormalStart = message.event === "request.start" && !("op" in message);
  if (message.event === "response.chunk" && frameBytes > MAX_RESPONSE_FRAME_BYTES) {
    throw new GatewayProtocolError("frame_too_large", "Response chunk frame exceeds the 256 KiB limit");
  }
  if (!isNormalStart && message.event !== "response.chunk" && frameBytes > MAX_CONTROL_FRAME_BYTES) {
    throw new GatewayProtocolError("frame_too_large", "Gateway control frame exceeds the 4 KiB limit");
  }
  if (isNormalStart && frameBytes > MAX_REQUEST_FRAME_BYTES) {
    throw new GatewayProtocolError("frame_too_large", "Request start frame exceeds the 1 MiB limit");
  }
  return message;
}
