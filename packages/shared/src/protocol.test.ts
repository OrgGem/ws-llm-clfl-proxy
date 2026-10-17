import { describe, expect, it } from "vitest";
import {
  ACK_WINDOW,
  GATEWAY_PROTOCOL_VERSION,
  MAX_CHUNK_BYTES,
  MAX_IN_FLIGHT,
  MAX_REQUEST_PAYLOAD_BYTES,
  MIN_REQUEST_PAYLOAD_BYTES,
  MAX_SESSION_SECONDS,
  MIN_SESSION_SECONDS,
  MAX_RESPONSE_FRAME_BYTES,
  MAX_REQUEST_FRAME_BYTES,
  GatewayProtocolError,
  parseGatewayFrame,
  parseGatewayMessage,
} from "./protocol.js";

const requestId = "3a0d1ae4-6c1d-4f4a-9c93-b5be26646a01";
const envelope = {
  v: 1 as const,
  alg: "A256GCM" as const,
  kid: "env-2026-10",
  credentialId: "cred_01JABC",
  userId: "usr_01JABC",
  projectId: "prj_01JABC",
  provider: "openai",
  exp: 2_000_000_000,
  nonce: "AAAAAAAAAAAAAAAA",
  ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
};

function requestStart(payload: Record<string, unknown> = { messages: [] }) {
  return {
    event: "request.start",
    requestId,
    provider: "openai",
    model: "fast-chat",
    envelope,
    payload,
  };
}

describe("Gateway protocol v1", () => {
  it("accepts contract session, start, acknowledgement, chunk, and terminal frames", () => {
    const ready = parseGatewayMessage({
      event: "session.ready",
      protocol: GATEWAY_PROTOCOL_VERSION,
      connectionId: "conn_01JABC",
      maxInFlight: MAX_IN_FLIGHT,
      maxPayloadBytes: MAX_REQUEST_PAYLOAD_BYTES,
      maxSessionSeconds: MAX_SESSION_SECONDS,
      maxChunkBytes: MAX_CHUNK_BYTES,
      ackWindow: ACK_WINDOW,
      maxRequestFrameBytes: MAX_REQUEST_FRAME_BYTES,
      maxResponseFrameBytes: MAX_RESPONSE_FRAME_BYTES,
      tokenExpiresAt: 2_000_000_000,
    });
    const start = parseGatewayMessage(requestStart());
    const ack = parseGatewayFrame(JSON.stringify({ event: "request.start", op: "ack", requestId, ackSeq: 0 }));
    const chunk = parseGatewayMessage({ event: "response.chunk", requestId, seq: 0, data: "data: x\n\n" });
    const end = parseGatewayMessage({ event: "response.end", requestId, lastSeq: 0, usage: { inputTokens: 1, outputTokens: 2, totalTokens: 3 } });

    expect(ready.event).toBe("session.ready");
    expect(start.event).toBe("request.start");
    expect(ack).toMatchObject({ event: "request.start", op: "ack", ackSeq: 0 });
    expect(chunk.event).toBe("response.chunk");
    expect(end.event).toBe("response.end");
  });

  it("accepts project concurrency limits within the hard cap", () => {
    const ready = {
      event: "session.ready",
      protocol: GATEWAY_PROTOCOL_VERSION,
      connectionId: "conn_01JABC",
      maxInFlight: 1,
      maxPayloadBytes: MIN_REQUEST_PAYLOAD_BYTES,
      maxSessionSeconds: MIN_SESSION_SECONDS,
      maxChunkBytes: MAX_CHUNK_BYTES,
      ackWindow: ACK_WINDOW,
      maxRequestFrameBytes: MAX_REQUEST_FRAME_BYTES,
      maxResponseFrameBytes: MAX_RESPONSE_FRAME_BYTES,
      tokenExpiresAt: 2_000_000_000,
    };

    expect(parseGatewayMessage(ready)).toMatchObject({ maxInFlight: 1 });
    const atHardCap = parseGatewayMessage({ ...ready, maxInFlight: MAX_IN_FLIGHT });
    expect(atHardCap.event === "session.ready" && atHardCap.maxInFlight).toBe(MAX_IN_FLIGHT);
    expect(() => parseGatewayMessage({ ...ready, maxInFlight: 0 })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...ready, maxInFlight: MAX_IN_FLIGHT + 1 })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...ready, maxPayloadBytes: MIN_REQUEST_PAYLOAD_BYTES - 1 })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...ready, maxPayloadBytes: MAX_REQUEST_PAYLOAD_BYTES + 1 })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...ready, maxSessionSeconds: MIN_SESSION_SECONDS - 1 })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...ready, maxSessionSeconds: MAX_SESSION_SECONDS + 1 })).toThrow(GatewayProtocolError);
  });

  it("rejects unknown events, extra fields, noncanonical IDs, and client routing fields", () => {
    expect(() => parseGatewayMessage({ event: "response.unknown" })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...requestStart(), surprise: true })).toThrow(GatewayProtocolError);
    expect(() => parseGatewayMessage({ ...requestStart(), requestId: requestId.toUpperCase() })).toThrow(
      GatewayProtocolError,
    );
    expect(() => parseGatewayMessage(requestStart({ messages: [], model: "attacker-model" }))).toThrow(
      GatewayProtocolError,
    );
    expect(() => parseGatewayMessage(requestStart({ messages: [], endpoint: "https://attacker.test" }))).toThrow(
      GatewayProtocolError,
    );
  });

  it("enforces UTF-8 chunk byte limits and rejects empty chunks", () => {
    const atLimit = "🙂".repeat(MAX_CHUNK_BYTES / 4);
    const overLimit = "🙂".repeat(MAX_CHUNK_BYTES / 4 + 1);

    expect(parseGatewayMessage({ event: "response.chunk", requestId, seq: 0, data: atLimit }).event).toBe(
      "response.chunk",
    );
    expect(() => parseGatewayMessage({ event: "response.chunk", requestId, seq: 0, data: overLimit })).toThrow(
      GatewayProtocolError,
    );
    expect(() => parseGatewayMessage({ event: "response.chunk", requestId, seq: 0, data: "" })).toThrow(
      GatewayProtocolError,
    );
  });

  it("bounds nested payloads and oversized request and control frames", () => {
    let nested: unknown = "leaf";
    for (let depth = 0; depth < 65; depth += 1) nested = { child: nested };
    expect(() => parseGatewayMessage(requestStart({ nested }))).toThrow(GatewayProtocolError);

    const oversizedStart = JSON.stringify(requestStart({ content: "x".repeat(MAX_REQUEST_FRAME_BYTES) }));
    expect(() => parseGatewayFrame(oversizedStart)).toThrow(/1 MiB/);

    const control = JSON.stringify({ event: "session.draining", reason: "policy" });
    const oversizedControl = control.slice(0, -1) + " ".repeat(4_100) + "}";
    expect(() => parseGatewayFrame(oversizedControl)).toThrow(/4 KiB/);
    expect(() => parseGatewayFrame("not json")).toThrow(/valid JSON/);
  });
});
