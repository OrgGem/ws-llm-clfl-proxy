import { afterEach, describe, expect, it, vi } from "vitest";
import { encryptCredentialEnvelope, ACK_TIMEOUT_MS } from "@ws-proxy/shared";
import { boundedProjectLimits, GatewaySession, splitUtf8, validateIdentityClaims } from "./session.js";
import { buildProviderRequest } from "./providers.js";
import { issuerConfigurationIsValid } from "./index.js";
import type { GatewayDependencies, IdentityInternalBinding, MachineClaims, ProjectLimits } from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const issuer = "https://identity.example.test";
const envelopeKey = new Uint8Array(32).fill(9);
const fixtureCredentialExpiresAt = Math.floor(Date.now() / 1000) + 3_600;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function requestId(number: number): string {
  return `00000000-0000-4000-8000-${number.toString(16).padStart(12, "0")}`;
}

class MemorySocket {
  readyState = 1;
  binaryType: BinaryType = "blob";
  readonly sent: string[] = [];
  closeCode: number | undefined;
  private readonly listeners = new Map<string, Array<(event: Event) => void>>();

  accept(): void {}

  addEventListener(type: string, callback: EventListenerOrEventListenerObject): void {
    const listener = typeof callback === "function"
      ? callback as (event: Event) => void
      : (event: Event) => callback.handleEvent(event);
    const entries = this.listeners.get(type) ?? [];
    entries.push(listener);
    this.listeners.set(type, entries);
  }

  send(data: string | ArrayBuffer | ArrayBufferView): void {
    if (this.readyState !== 1) throw new Error("socket closed");
    if (typeof data !== "string") throw new Error("unexpected binary output");
    this.sent.push(data);
  }

  close(code?: number): void {
    this.closeCode = code;
    this.readyState = 3;
    this.emit("close", new Event("close"));
  }

  emitMessage(data: unknown): void {
    this.emit("message", new MessageEvent("message", { data }));
  }

  peerClose(): void {
    this.readyState = 3;
    this.emit("close", new Event("close"));
  }

  frames(): Array<Record<string, unknown>> {
    return this.sent.map((frame) => JSON.parse(frame) as Record<string, unknown>);
  }

  private emit(type: string, event: Event): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

function validClaims(): MachineClaims {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: "user-a",
    sid: "session-a",
    project_id: "project-a",
    client_id: "client-a",
    iss: issuer,
    aud: "llm-socket-gateway",
    jti: "token-a",
    iat: now,
    nbf: now,
    exp: now + 300,
  };
}

async function makeEnvelope(userId = "user-a", projectId = "project-a") {
  return await encryptCredentialEnvelope(encoder.encode("sk-test-provider-key"), {
    credentialId: "credential-a",
    userId,
    projectId,
    provider: "openai",
    kid: "key-v1",
    exp: fixtureCredentialExpiresAt,
  }, envelopeKey);
}

async function makeEnvelopeWithPlaintext(plaintext: Uint8Array) {
  return await encryptCredentialEnvelope(plaintext, {
    credentialId: "credential-a",
    userId: "user-a",
    projectId: "project-a",
    provider: "openai",
    kid: "key-v1",
    exp: fixtureCredentialExpiresAt,
  }, envelopeKey);
}

interface TestSession {
  session: GatewaySession;
  socket: MemorySocket;
  identity: {
    validateToken: ReturnType<typeof vi.fn>;
    authorizeTokenRequest: ReturnType<typeof vi.fn>;
  };
  fetcher: ReturnType<typeof vi.fn>;
}

function createSession(options: {
  authorize?: (input: unknown) => Promise<unknown> | unknown;
  fetcher?: typeof fetch;
  claims?: MachineClaims;
  sessionLimits?: ProjectLimits;
  requestLimits?: ProjectLimits;
  credentialExpiresAt?: number;
  envelopeKeys?: string;
} = {}): TestSession {
  const claims = options.claims ?? validClaims();
  const identity = {
    fetch: vi.fn(),
    validateToken: vi.fn(async () => ({ valid: true, claims })),
    authorizeTokenRequest: vi.fn(options.authorize ?? (async () => ({
      allowed: true,
      principal: {
        userId: claims.sub,
        projectId: claims.project_id,
        clientId: claims.client_id,
        sessionId: claims.sid,
      },
      credentialMetadata: {
        credentialId: "credential-a",
        userId: claims.sub,
        projectId: claims.project_id,
        provider: "openai",
        expiresAt: options.credentialExpiresAt ?? fixtureCredentialExpiresAt,
        keyVersion: "key-v1",
      },
      authorizedModel: { alias: "fast-chat", upstreamModel: "gpt-4o-mini" },
      ...(options.requestLimits ? { limits: options.requestLimits } : {}),
    }))),
  };
  const fetcher = vi.fn(options.fetcher ?? (async () => new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      },
    }),
    { headers: { "content-type": "text/event-stream" } },
  )));
  const socket = new MemorySocket();
  const dependencies: GatewayDependencies = {
    identity: identity as unknown as IdentityInternalBinding,
    machineIssuer: issuer,
    envelopeKeys: options.envelopeKeys ?? JSON.stringify({ current: "key-v1", keys: { "key-v1": base64Url(envelopeKey) } }),
    fetcher: fetcher as unknown as typeof fetch,
  };
  const context = { waitUntil: (promise: Promise<unknown>) => { void promise.catch(() => undefined); } };
  const session = new GatewaySession(socket as unknown as WebSocket, "signed-token", claims, dependencies, context, options.sessionLimits);
  session.attach();
  return { session, socket, identity, fetcher };
}

async function waitForFrame(
  socket: MemorySocket,
  predicate: (frame: Record<string, unknown>) => boolean,
  timeoutMs = 2_000,
): Promise<Record<string, unknown>> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const frame = socket.frames().find(predicate);
    if (frame) return frame;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error(`Timed out waiting for Gateway frame; saw ${JSON.stringify(socket.frames())}`);
}

function startFrame(id: number, envelope: unknown): Record<string, unknown> {
  return {
    event: "request.start",
    requestId: requestId(id),
    provider: "openai",
    model: "fast-chat",
    envelope,
    payload: { messages: [{ role: "user", content: "hello" }] },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("GatewaySession", () => {
  it("rejects a cross-owner credential before decryption or provider fetch", async () => {
    const denied = createSession({ authorize: async () => ({ allowed: false, reasonCode: "credential_owner_mismatch" }) });
    const envelope = await makeEnvelope("other-user", "other-project");
    const id = requestId(1);
    denied.socket.emitMessage(JSON.stringify(startFrame(1, envelope)));

    const terminal = await waitForFrame(denied.socket, (frame) => frame.event === "response.error");
    expect(terminal).toMatchObject({ event: "response.error", requestId: id, code: "forbidden", upstreamStarted: false });
    expect(denied.fetcher).not.toHaveBeenCalled();
    denied.socket.peerClose();
  });

  it("classifies authenticated ciphertext tampering as an invalid credential", async () => {
    const envelope = await makeEnvelope();
    const tampered = { ...envelope };
    const index = Math.floor(tampered.ciphertext.length / 2);
    const replacement = tampered.ciphertext[index] === "A" ? "B" : "A";
    tampered.ciphertext = `${tampered.ciphertext.slice(0, index)}${replacement}${tampered.ciphertext.slice(index + 1)}`;
    const test = createSession();
    const id = requestId(22);
    test.socket.emitMessage(JSON.stringify(startFrame(22, tampered)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({
      code: "credential_invalid",
      upstreamStarted: false,
      retryable: false,
      message: "The provider credential is unavailable.",
    });
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledOnce();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("classifies malformed decrypted provider keys as invalid credentials", async () => {
    const test = createSession();
    test.socket.emitMessage(JSON.stringify(startFrame(23, await makeEnvelopeWithPlaintext(new Uint8Array([0xff])))));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(23));
    expect(terminal).toMatchObject({ code: "credential_invalid", upstreamStarted: false, retryable: false });
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("classifies malformed Gateway keyring configuration as an internal error", async () => {
    const test = createSession({ envelopeKeys: "{invalid-json" });
    test.socket.emitMessage(JSON.stringify(startFrame(24, await makeEnvelope())));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(24));
    expect(terminal).toMatchObject({ code: "internal_error", upstreamStarted: false, retryable: false });
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it.each([
    ["invalid_or_inactive_token", "unauthorized"],
    ["credential_unavailable", "credential_invalid"],
    ["provider_or_model_not_allowed", "model_disallowed"],
  ])("maps Identity denial %s to %s", async (reasonCode, expectedCode) => {
    const test = createSession({ authorize: async () => ({ allowed: false, reasonCode }) });
    test.socket.emitMessage(JSON.stringify(startFrame(2, await makeEnvelope())));
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error");
    expect(terminal.code).toBe(expectedCode);
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("does not launch upstream when cancellation races Identity authorization", async () => {
    let finishAuthorization!: (value: unknown) => void;
    const authorization = new Promise((resolve) => { finishAuthorization = resolve; });
    const test = createSession({ authorize: () => authorization });
    const id = requestId(3);
    test.socket.emitMessage(JSON.stringify(startFrame(3, await makeEnvelope())));
    await waitForFrame(test.socket, (frame) => frame.event === "session.ready");
    test.socket.emitMessage(JSON.stringify({ event: "request.cancel", requestId: id }));
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error");
    expect(terminal).toMatchObject({ requestId: id, code: "cancelled", upstreamStarted: false });
    finishAuthorization({ allowed: true });
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("aborts the provider fetch and response reader on cancellation", async () => {
    let streamCancelled = false;
    let providerSignal: AbortSignal | undefined;
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      providerSignal = init?.signal as AbortSignal;
      const body = new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(encoder.encode("data: pending\n\n")); },
        cancel() { streamCancelled = true; },
      });
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    });
    const test = createSession({ fetcher });
    const id = requestId(4);
    test.socket.emitMessage(JSON.stringify(startFrame(4, await makeEnvelope())));
    await waitForFrame(test.socket, (frame) => frame.event === "session.ready");
    await waitForFrame(test.socket, (frame) => frame.event === "response.chunk");
    expect(fetcher).toHaveBeenCalledOnce();
    test.socket.emitMessage(JSON.stringify({ event: "request.cancel", requestId: id }));
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error");
    expect(terminal.code).toBe("cancelled");
    expect(providerSignal?.aborted).toBe(true);
    expect(streamCancelled).toBe(true);
    test.socket.peerClose();
  });

  it("closes on an ACK for a sequence that has not been sent", async () => {
    let streamCancelled = false;
    let providerSignal: AbortSignal | undefined;
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      providerSignal = init?.signal as AbortSignal;
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(encoder.encode("data: pending\n\n")); },
        cancel() { streamCancelled = true; },
      }), { headers: { "content-type": "text/event-stream" } });
    });
    const test = createSession({ fetcher });
    const id = requestId(20);
    test.socket.emitMessage(JSON.stringify(startFrame(20, await makeEnvelope())));
    await waitForFrame(test.socket, (frame) => frame.event === "response.chunk" && frame.requestId === id);
    test.socket.emitMessage(JSON.stringify({ event: "request.start", op: "ack", requestId: id, ackSeq: 1 }));
    await new Promise((resolve) => setTimeout(resolve, 5));

    expect(test.socket.closeCode).toBe(1002);
    expect(providerSignal?.aborted).toBe(true);
    expect(streamCancelled).toBe(true);
    expect(test.socket.frames().filter((frame) => frame.event === "response.chunk" && frame.requestId === id)).toHaveLength(1);
    expect(test.socket.frames().some((frame) =>
      (frame.event === "response.end" || frame.event === "response.error") && frame.requestId === id,
    )).toBe(false);
    test.socket.peerClose();
  });

  it("aborts active upstream work when the WebSocket peer disconnects", async () => {
    let streamCancelled = false;
    let providerSignal: AbortSignal | undefined;
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      providerSignal = init?.signal as AbortSignal;
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(encoder.encode("data: pending\n\n")); },
        cancel() { streamCancelled = true; },
      }), { headers: { "content-type": "text/event-stream" } });
    });
    const test = createSession({ fetcher });
    const id = requestId(21);
    test.socket.emitMessage(JSON.stringify(startFrame(21, await makeEnvelope())));
    await waitForFrame(test.socket, (frame) => frame.event === "response.chunk" && frame.requestId === id);
    test.socket.peerClose();
    await new Promise((resolve) => setTimeout(resolve, 5));

    expect(providerSignal?.aborted).toBe(true);
    expect(streamCancelled).toBe(true);
    expect(test.socket.frames().some((frame) =>
      (frame.event === "response.end" || frame.event === "response.error") && frame.requestId === id,
    )).toBe(false);
  });

  it("keeps already-authorized work alive after token expiry until it finishes", async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = { ...validClaims(), iat: now - 299, nbf: now - 299, exp: now + 1 };
    const fetcher = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        setTimeout(() => {
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
        }, 1_200);
      },
    }), { headers: { "content-type": "text/event-stream" } }));
    const test = createSession({ claims, fetcher });
    const id = requestId(5);
    test.socket.emitMessage(JSON.stringify(startFrame(5, await makeEnvelope())));
    await waitForFrame(test.socket, (frame) => frame.event === "session.ready");
    const end = Date.now() + 500;
    while (!fetcher.mock.calls.length && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 2));
    expect(fetcher).toHaveBeenCalledOnce();
    await new Promise((resolve) => setTimeout(resolve, 1_050));
    expect(test.socket.closeCode).toBeUndefined();
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.end" && frame.requestId === id);
    expect(terminal.lastSeq).toBe(0);
    test.socket.emitMessage(JSON.stringify({ event: "request.start", op: "ack", requestId: id, ackSeq: 0 }));
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(test.socket.closeCode).toBe(1000);
  });

  it("closes at the hard session lifetime cap and aborts active upstream work", async () => {
    const originalSetTimeout = globalThis.setTimeout;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((handler: unknown, timeout?: number, ...args: unknown[]) =>
      originalSetTimeout(handler as TimerHandler, timeout === 30_000 ? 40 : timeout, ...args)) as typeof globalThis.setTimeout);
    let providerSignal: AbortSignal | undefined;
    let streamCancelled = false;
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      providerSignal = init?.signal as AbortSignal;
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(encoder.encode("data: pending\n\n")); },
        cancel() { streamCancelled = true; },
      }), { headers: { "content-type": "text/event-stream" } });
    });
    const test = createSession({
      fetcher,
      sessionLimits: { maxPayloadBytes: 1_048_576, maxConcurrency: 8, maxSessionSeconds: 30 },
    });
    const id = requestId(6);
    test.socket.emitMessage(JSON.stringify(startFrame(6, await makeEnvelope())));
    const ready = await waitForFrame(test.socket, (frame) => frame.event === "session.ready");
    expect(ready.maxSessionSeconds).toBe(30);
    await waitForFrame(test.socket, (frame) => frame.event === "response.chunk" && frame.requestId === id);
    await new Promise((resolve) => setTimeout(resolve, 75));
    expect(test.socket.closeCode).toBe(1000);
    expect(providerSignal?.aborted).toBe(true);
    expect(streamCancelled).toBe(true);
    expect(test.socket.frames().some((frame) => frame.event === "response.error" && frame.requestId === id)).toBe(false);
    test.socket.peerClose();
  });

  it("advertises and enforces a lower project concurrency limit", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response(
      new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(encoder.encode("data: pending\n\n")); },
        cancel() { void init?.signal; },
      }),
      { headers: { "content-type": "text/event-stream" } },
    ));
    const limits = { maxPayloadBytes: 1_048_576, maxConcurrency: 1, maxSessionSeconds: 300 };
    const test = createSession({ fetcher, sessionLimits: limits });
    const envelope = await makeEnvelope();
    test.socket.emitMessage(JSON.stringify(startFrame(7, envelope)));
    const ready = await waitForFrame(test.socket, (frame) => frame.event === "session.ready");
    expect(ready.maxInFlight).toBe(1);
    await waitForFrame(test.socket, (frame) => frame.event === "response.chunk" && frame.requestId === requestId(7));
    test.socket.emitMessage(JSON.stringify(startFrame(8, envelope)));
    const rejected = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(8));
    expect(rejected.code).toBe("overloaded");
    expect(fetcher).toHaveBeenCalledOnce();
    test.socket.peerClose();
  });

  it("enforces the fresh per-request payload limit before provider fetch", async () => {
    const test = createSession({
      requestLimits: { maxPayloadBytes: 1_024, maxConcurrency: 8, maxSessionSeconds: 300 },
    });
    const frame = startFrame(9, await makeEnvelope());
    frame.payload = { messages: [{ role: "user", content: "x".repeat(2_000) }] };
    test.socket.emitMessage(JSON.stringify(frame));
    const terminal = await waitForFrame(test.socket, (item) => item.event === "response.error" && item.requestId === requestId(9));
    expect(terminal.code).toBe("invalid_request");
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("retains completed requests until ACK and closes on terminal ACK timeout", async () => {
    const originalSetTimeout = globalThis.setTimeout;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((handler: unknown, timeout?: number, ...args: unknown[]) =>
      originalSetTimeout(handler as TimerHandler, timeout === ACK_TIMEOUT_MS ? 500 : timeout, ...args)) as typeof globalThis.setTimeout);
    const test = createSession();
    const envelope = await makeEnvelope();

    for (let id = 10; id < 18; id += 1) {
      test.socket.emitMessage(JSON.stringify(startFrame(id, envelope)));
      await waitForFrame(test.socket, (frame) => frame.event === "response.end" && frame.requestId === requestId(id));
    }

    test.socket.emitMessage(JSON.stringify(startFrame(18, envelope)));
    const overloaded = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(18));
    expect(overloaded.code).toBe("overloaded");
    expect(test.fetcher).toHaveBeenCalledTimes(8);
    await waitForFrame(test.socket, () => test.socket.closeCode === 1013, 2_000);
    test.socket.peerClose();
  });

  it("caps cumulative outbound bytes across repeated requests despite ACKs", async () => {
    const providerSignals: AbortSignal[] = [];
    const responseText = encoder.encode("x".repeat(65_536));
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      providerSignals.push(init?.signal as AbortSignal);
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(responseText);
          controller.close();
        },
      }), { headers: { "content-type": "text/event-stream" } });
    });
    const envelope = await makeEnvelope();
    const test = createSession({ fetcher, credentialExpiresAt: envelope.exp });
    let frameCursor = 0;
    let completedRequests = 0;

    for (let idNumber = 30; idNumber < 500 && test.socket.closeCode === undefined; idNumber += 1) {
      const id = requestId(idNumber);
      test.socket.emitMessage(JSON.stringify(startFrame(idNumber, envelope)));
      let lastSeq = -1;
      let terminal: Record<string, unknown> | undefined;
      const deadline = Date.now() + 2_000;
      while (terminal === undefined && test.socket.closeCode === undefined && Date.now() < deadline) {
        while (frameCursor < test.socket.sent.length) {
          const frame = JSON.parse(test.socket.sent[frameCursor++]!) as Record<string, unknown>;
          if (frame.requestId !== id) continue;
          if (frame.event === "response.chunk") lastSeq = frame.seq as number;
          if (frame.event === "response.end" || frame.event === "response.error") {
            terminal = frame;
            break;
          }
        }
        if (terminal === undefined && test.socket.closeCode === undefined) {
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
      }
      if (test.socket.closeCode !== undefined) break;
      expect(terminal).toMatchObject({ event: "response.end", requestId: id, lastSeq: 3 });
      completedRequests += 1;
      test.socket.emitMessage(JSON.stringify({ event: "request.start", op: "ack", requestId: id, ackSeq: lastSeq }));
    }

    expect(test.socket.closeCode).toBe(1013);
    expect(completedRequests).toBeGreaterThan(0);
    expect(completedRequests).toBeLessThan(470);
    expect(test.socket.frames().some((frame) => frame.event === "session.draining" && frame.reason === "policy")).toBe(true);
    const lifetimeBytes = test.socket.sent.reduce((total, frame) => total + encoder.encode(frame).byteLength, 0);
    expect(lifetimeBytes).toBeGreaterThan(8 * 1_048_576 - 2 * 65_536);
    expect(lifetimeBytes).toBeLessThanOrEqual(8 * 1_048_576);
    expect(providerSignals.at(-1)?.aborted).toBe(true);
    test.socket.peerClose();
  });

  it("rejects oversized incoming frames", async () => {
    const test = createSession();
    test.socket.emitMessage(`"${"x".repeat(1_048_576)}"`);
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(test.socket.closeCode).toBe(1009);
  });

  it("does not follow provider redirects or send credentials to their destination", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.redirect).toBe("manual");
      return new Response(null, { status: 302, headers: { location: "https://attacker.example/collect" } });
    });
    const test = createSession({ fetcher });
    test.socket.emitMessage(JSON.stringify(startFrame(19, await makeEnvelope())));
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(19));
    expect(terminal).toMatchObject({ code: "upstream_error", upstreamStarted: true });
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0]?.[0]).toBe("https://api.openai.com/v1/chat/completions");
    test.socket.peerClose();
  });
});

describe("Gateway boundaries", () => {
  it("splits UTF-8 without breaking code points and caps emitted chunks at 16 KiB", () => {
    const value = "🙂漢字é".repeat(10_000);
    const parts = splitUtf8(value, 16_384);
    expect(parts.join("")).toBe(value);
    expect(parts.length).toBeGreaterThan(1);
    expect(parts.every((part) => encoder.encode(part).byteLength <= 16_384)).toBe(true);
    for (const part of parts) expect(() => decoder.decode(encoder.encode(part))).not.toThrow();
  });

  it("uses a fixed provider endpoint and rejects an oversized JSON body", () => {
    const request = buildProviderRequest("openai", "sk-test", "gpt-4o-mini", { messages: [] }, new AbortController().signal);
    expect(request.url).toBe("https://api.openai.com/v1/chat/completions");
    expect(request.init.redirect).toBe("manual");
    expect(new Headers(request.init.headers).get("authorization")).toBe("Bearer sk-test");
    expect(new Headers(request.init.headers).get("x-api-key")).toBeNull();
    expect(JSON.parse(String(request.init.body))).toMatchObject({ model: "gpt-4o-mini", stream: true });
    const anthropic = buildProviderRequest("anthropic", "sk-ant-test", "claude-haiku", { messages: [] }, new AbortController().signal);
    expect(anthropic.url).toBe("https://api.anthropic.com/v1/messages");
    expect(anthropic.init.redirect).toBe("manual");
    expect(new Headers(anthropic.init.headers).get("x-api-key")).toBe("sk-ant-test");
    expect(new Headers(anthropic.init.headers).get("authorization")).toBeNull();
    expect(JSON.parse(String(anthropic.init.body))).toMatchObject({ model: "claude-haiku", stream: true });
    expect(() => buildProviderRequest(
      "openai",
      "sk-test",
      "gpt-4o-mini",
      { content: "x".repeat(1_048_576) },
      new AbortController().signal,
    )).toThrow(/Gateway payload limit/);
  });

  it("requires complete claims and rejects future issued-at/not-before values", () => {
    const claims = validClaims();
    const now = Math.floor(Date.now() / 1000);
    expect(validateIdentityClaims({ valid: true, claims }, issuer, now)).toMatchObject({ sub: claims.sub });
    const { iat: _iat, ...missingIat } = claims;
    expect(validateIdentityClaims({ valid: true, claims: missingIat }, issuer, now)).toBeUndefined();
    expect(validateIdentityClaims({ valid: true, claims: { ...claims, iat: now + 31 } }, issuer, now)).toBeUndefined();
    expect(validateIdentityClaims({ valid: true, claims: { ...claims, nbf: now + 31 } }, issuer, now)).toBeUndefined();
  });

  it("allows loopback HTTP issuers only in explicit local configuration", () => {
    const keys = "{}";
    expect(issuerConfigurationIsValid({ MACHINE_ISSUER: "http://localhost:9999", GATEWAY_ENVIRONMENT: "staging", ENVELOPE_KEYS: keys })).toBe(false);
    expect(issuerConfigurationIsValid({ MACHINE_ISSUER: "http://localhost:9999", GATEWAY_ENVIRONMENT: "local", ENVELOPE_KEYS: keys })).toBe(true);
    expect(issuerConfigurationIsValid({ MACHINE_ISSUER: "https://identity.example.test", GATEWAY_ENVIRONMENT: "staging", ENVELOPE_KEYS: keys })).toBe(true);
  });

  it("clamps project limits to Gateway hard caps and rejects invalid values", () => {
    expect(boundedProjectLimits({ maxPayloadBytes: 2_000_000, maxConcurrency: 20, maxSessionSeconds: 500 })).toEqual({
      maxPayloadBytes: 1_048_576,
      maxConcurrency: 8,
      maxSessionSeconds: 300,
    });
    expect(boundedProjectLimits({ maxPayloadBytes: 10_000, maxConcurrency: 2, maxSessionSeconds: 60 })).toEqual({
      maxPayloadBytes: 10_000,
      maxConcurrency: 2,
      maxSessionSeconds: 60,
    });
    expect(boundedProjectLimits({ maxPayloadBytes: 10, maxConcurrency: 1, maxSessionSeconds: 60 })).toBeUndefined();
    expect(boundedProjectLimits({ maxPayloadBytes: 10, maxConcurrency: 1, maxSessionSeconds: 29 })).toBeUndefined();
  });
});
