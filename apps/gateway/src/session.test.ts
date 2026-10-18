import { afterEach, describe, expect, it, vi } from "vitest";
import { encryptCredentialEnvelope, ACK_TIMEOUT_MS, type ProviderRequestApi } from "@ws-proxy/shared";
import { boundedProjectLimits, GatewaySession, splitUtf8, validateIdentityClaims } from "./session.js";
import { buildProviderRequest } from "./providers.js";
import { issuerConfigurationIsValid } from "./index.js";
import type { AuthorizedProvider, GatewayDependencies, IdentityInternalBinding, MachineClaims, ProjectLimits } from "./types.js";

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

async function makeEnvelope(userId = "user-a", projectId = "project-a", provider = "openai") {
  return await encryptCredentialEnvelope(encoder.encode("sk-test-provider-key"), {
    credentialId: "credential-a",
    userId,
    projectId,
    provider,
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
  endpointDnsFetcher: ReturnType<typeof vi.fn>;
}

function createSession(options: {
  authorize?: (input: unknown) => Promise<unknown> | unknown;
  fetcher?: typeof fetch;
  claims?: MachineClaims;
  sessionLimits?: ProjectLimits;
  requestLimits?: ProjectLimits;
  credentialExpiresAt?: number;
  envelopeKeys?: string;
  providerRegistry?: AuthorizedProvider | null;
  credentialProvider?: string;
  endpointDnsFetcher?: typeof fetch;
  gatewayOrigin?: string;
} = {}): TestSession {
  const claims = options.claims ?? validClaims();
  const providerRegistry = options.providerRegistry === undefined
    ? {
        id: "openai",
        displayName: "OpenAI",
        protocol: "openai" as const,
        baseUrl: "https://api.openai.com/v1/",
        custom: false,
      }
    : options.providerRegistry;
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
        provider: providerRegistry?.id ?? options.credentialProvider ?? "openai",
        expiresAt: options.credentialExpiresAt ?? fixtureCredentialExpiresAt,
        keyVersion: "key-v1",
      },
      authorizedModel: { alias: "fast-chat", upstreamModel: "gpt-4o-mini" },
      ...(providerRegistry ? { authorizedProvider: providerRegistry } : {}),
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
  const endpointDnsFetcher = vi.fn(options.endpointDnsFetcher ?? (async (input: RequestInfo | URL) => {
    const query = new URL(String(input)).searchParams;
    const isV6 = query.get("type") === "AAAA" || query.get("type") === "28";
    return Response.json({
      Status: 0,
      Answer: [{ type: isV6 ? 28 : 1, data: isV6 ? "2606:4700:4700::1111" : "1.1.1.1" }],
    });
  }));
  const dependencies: GatewayDependencies = {
    identity: identity as unknown as IdentityInternalBinding,
    machineIssuer: issuer,
    envelopeKeys: options.envelopeKeys ?? JSON.stringify({ current: "key-v1", keys: { "key-v1": base64Url(envelopeKey) } }),
    fetcher: fetcher as unknown as typeof fetch,
    endpointDnsFetcher: endpointDnsFetcher as unknown as typeof fetch,
    ...(options.gatewayOrigin ? { gatewayOrigin: options.gatewayOrigin } : {}),
  };
  const context = { waitUntil: (promise: Promise<unknown>) => { void promise.catch(() => undefined); } };
  const session = new GatewaySession(socket as unknown as WebSocket, "signed-token", claims, dependencies, context, options.sessionLimits);
  session.attach();
  return { session, socket, identity, fetcher, endpointDnsFetcher };
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

function startFrame(
  id: number,
  envelope: unknown,
  provider = "openai",
  api?: ProviderRequestApi,
): Record<string, unknown> {
  return {
    event: "request.start",
    requestId: requestId(id),
    ...(api === undefined ? {} : { api }),
    provider,
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

  it("routes a registered custom OpenAI-compatible provider and rechecks Identity after DNS", async () => {
    const registry: AuthorizedProvider = {
      id: "acme-llm",
      displayName: "Acme LLM",
      protocol: "openai",
      baseUrl: "https://llm.example.net/gateway/v1/",
      custom: true,
    };
    const dnsFetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? new URL(input.url) : new URL(String(input));
      const isV6 = url.searchParams.get("type") === "AAAA" || url.searchParams.get("type") === "28";
      return Response.json({
        Status: 0,
        Answer: [{ type: isV6 ? 28 : 1, data: isV6 ? "2606:4700:4700::1111" : "1.1.1.1" }],
      });
    });
    const test = createSession({ providerRegistry: registry, endpointDnsFetcher: dnsFetcher as typeof fetch });
    const id = requestId(80);
    test.socket.emitMessage(JSON.stringify(startFrame(80, await makeEnvelope("user-a", "project-a", registry.id), registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.end" && frame.requestId === id);
    expect(terminal).toMatchObject({ event: "response.end", requestId: id });
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledTimes(2);
    expect(dnsFetcher).toHaveBeenCalledTimes(2);
    expect(test.fetcher).toHaveBeenCalledOnce();
    expect(test.fetcher.mock.calls[0]?.[0]).toBe("https://llm.example.net/gateway/v1/chat/completions");
    const init = test.fetcher.mock.calls[0]?.[1] as RequestInit;
    expect(init.redirect).toBe("manual");
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer sk-test-provider-key");
    const chunks = test.socket.frames().filter((frame) => frame.event === "response.chunk" && frame.requestId === id);
    if (chunks.length > 0) {
      test.socket.emitMessage(JSON.stringify({ event: "request.start", op: "ack", requestId: id, ackSeq: chunks.length - 1 }));
    }
    test.socket.peerClose();
  });

  it("routes custom Responses only under the authorized base URL and rechecks that route after DNS", async () => {
    const registry: AuthorizedProvider = {
      id: "acme-responses",
      displayName: "Acme Responses",
      protocol: "openai",
      baseUrl: "https://responses.example.net/tenant/v2/",
      custom: true,
    };
    const dnsFetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      const isV6 = url.searchParams.get("type") === "AAAA";
      return Response.json({ Status: 0, Answer: [{ type: isV6 ? 28 : 1, data: isV6 ? "2606:4700:4700::1111" : "1.1.1.1" }] });
    });
    const test = createSession({ providerRegistry: registry, endpointDnsFetcher: dnsFetcher as typeof fetch });
    const frame = startFrame(98, await makeEnvelope("user-a", "project-a", registry.id), registry.id, "responses");
    frame.payload = { input: "hello" };
    test.socket.emitMessage(JSON.stringify(frame));

    const terminal = await waitForFrame(test.socket, (item) => item.event === "response.end" && item.requestId === requestId(98));
    expect(terminal).toMatchObject({ event: "response.end" });
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledTimes(2);
    expect(dnsFetcher).toHaveBeenCalledTimes(2);
    expect(test.fetcher.mock.calls[0]?.[0]).toBe("https://responses.example.net/tenant/v2/responses");
    expect(JSON.parse(String((test.fetcher.mock.calls[0]?.[1] as RequestInit).body))).toMatchObject({
      input: "hello",
      store: false,
      model: "gpt-4o-mini",
      stream: true,
    });
    test.socket.peerClose();
  });

  it("routes a registered custom Anthropic-compatible provider to its fixed operation path", async () => {
    const registry: AuthorizedProvider = {
      id: "anthropic-edge",
      displayName: "Anthropic Edge",
      protocol: "anthropic",
      baseUrl: "https://anthropic.example.net/anthropic/v1/",
      custom: true,
    };
    const test = createSession({ providerRegistry: registry });
    const id = requestId(89);
    test.socket.emitMessage(JSON.stringify(startFrame(89, await makeEnvelope("user-a", "project-a", registry.id), registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.end" && frame.requestId === id);
    expect(terminal).toMatchObject({ event: "response.end", requestId: id });
    expect(test.fetcher).toHaveBeenCalledOnce();
    expect(test.fetcher.mock.calls[0]?.[0]).toBe("https://anthropic.example.net/anthropic/v1/messages");
    const init = test.fetcher.mock.calls[0]?.[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(init.redirect).toBe("manual");
    expect(headers.get("x-api-key")).toBe("sk-test-provider-key");
    expect(headers.get("anthropic-version")).toBe("2023-06-01");
    expect(headers.get("authorization")).toBeNull();
    test.socket.peerClose();
  });

  it("uses only the fixed built-in endpoint when older Identity fixtures omit provider metadata", async () => {
    const test = createSession({ providerRegistry: null, credentialProvider: "openai" });
    const id = requestId(90);
    test.socket.emitMessage(JSON.stringify(startFrame(90, await makeEnvelope())));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.end" && frame.requestId === id);
    expect(terminal).toMatchObject({ event: "response.end", requestId: id });
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher.mock.calls[0]?.[0]).toBe("https://api.openai.com/v1/chat/completions");
    test.socket.peerClose();
  });

  it.each([
    { api: "responses" as const, endpoint: "https://api.openai.com/v1/responses" },
    { api: "completions" as const, endpoint: "https://api.openai.com/v1/completions" },
  ])("routes OpenAI $api to its native fixed endpoint and streams provider bytes", async ({ api, endpoint }) => {
    const test = createSession();
    const id = requestId(api === "responses" ? 91 : 92);
    const frame = startFrame(api === "responses" ? 91 : 92, await makeEnvelope(), "openai", api);
    frame.payload = api === "responses" ? { input: "Hello" } : { prompt: "Hello" };
    test.socket.emitMessage(JSON.stringify(frame));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.end" && frame.requestId === id);
    expect(terminal).toMatchObject({ event: "response.end", requestId: id });
    expect(test.fetcher).toHaveBeenCalledOnce();
    expect(test.fetcher.mock.calls[0]?.[0]).toBe(endpoint);
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.socket.frames().some((frame) => frame.event === "response.chunk" && frame.requestId === id && String(frame.data).includes("[DONE]"))).toBe(true);
    const init = test.fetcher.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ model: "gpt-4o-mini", stream: true });
    if (api === "responses") expect(JSON.parse(String(init.body))).toMatchObject({ store: false, input: "Hello" });
    test.socket.peerClose();
  });

  it.each([
    { payload: { input: "Hello", store: true } },
    { payload: { input: "Hello", background: true } },
    { payload: { input: "Hello", previous_response_id: "resp_previous" } },
    { payload: { input: "Hello", conversation: "conv_remote" } },
    { payload: { input: [{ type: "item_reference", id: "resp_remote_item" }] } },
  ])("rejects stateful Responses fields before authorization, DNS, or decryption", async ({ payload }) => {
    const test = createSession();
    const frame = startFrame(96, await makeEnvelope(), "openai", "responses");
    frame.payload = payload;
    test.socket.emitMessage(JSON.stringify(frame));

    const terminal = await waitForFrame(test.socket, (item) => item.event === "response.error" && item.requestId === requestId(96));
    expect(terminal).toMatchObject({ event: "response.error", code: "invalid_request", upstreamStarted: false });
    expect(test.identity.authorizeTokenRequest).not.toHaveBeenCalled();
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects a nested Responses item_reference before authorization, decryption, or upstream work", async () => {
    const envelope = await makeEnvelope();
    const tamperedEnvelope = { ...envelope };
    const index = Math.floor(tamperedEnvelope.ciphertext.length / 2);
    tamperedEnvelope.ciphertext = `${tamperedEnvelope.ciphertext.slice(0, index)}${tamperedEnvelope.ciphertext[index] === "A" ? "B" : "A"}${tamperedEnvelope.ciphertext.slice(index + 1)}`;

    const test = createSession();
    const frame = startFrame(97, tamperedEnvelope, "openai", "responses");
    frame.payload = {
      input: [{
        role: "assistant",
        content: [{ type: "item_reference", id: "resp_remote_item" }],
      }],
    };
    test.socket.emitMessage(JSON.stringify(frame));

    const terminal = await waitForFrame(test.socket, (item) => item.event === "response.error" && item.requestId === requestId(97));
    expect(terminal).toMatchObject({ event: "response.error", code: "invalid_request", upstreamStarted: false });
    expect(test.identity.authorizeTokenRequest).not.toHaveBeenCalled();
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("counts the forced Responses store:false field against the project payload limit", async () => {
    const requestLimit = 1_024;
    const baseBodyBytes = encoder.encode(JSON.stringify({ input: "", model: "gpt-4o-mini", stream: true })).byteLength;
    const inputBytes = requestLimit - baseBodyBytes;
    const test = createSession({ requestLimits: { maxPayloadBytes: requestLimit, maxConcurrency: 1, maxSessionSeconds: 60 } });
    const frame = startFrame(99, await makeEnvelope(), "openai", "responses");
    frame.payload = { input: "x".repeat(inputBytes) };
    test.socket.emitMessage(JSON.stringify(frame));

    const terminal = await waitForFrame(test.socket, (item) => item.event === "response.error" && item.requestId === requestId(99));
    expect(terminal).toMatchObject({ event: "response.error", code: "invalid_request", upstreamStarted: false });
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledOnce();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects OpenAI generation APIs for Anthropic before decrypting or resolving endpoints", async () => {
    const registry: AuthorizedProvider = {
      id: "anthropic",
      displayName: "Anthropic",
      protocol: "anthropic",
      baseUrl: "https://api.anthropic.com/v1/",
      custom: false,
    };
    const envelope = await makeEnvelope("user-a", "project-a", "anthropic");
    const tampered = { ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -1)}${envelope.ciphertext.endsWith("A") ? "B" : "A"}` };
    const test = createSession({ providerRegistry: registry, credentialProvider: "anthropic" });
    const id = requestId(93);
    test.socket.emitMessage(JSON.stringify(startFrame(93, tampered, "anthropic", "responses")));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ event: "response.error", code: "invalid_request", upstreamStarted: false });
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledOnce();
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects invalid API discriminators and arbitrary endpoint fields before authorization", async () => {
    const invalidApi = createSession();
    const invalidApiFrame = startFrame(94, await makeEnvelope());
    invalidApiFrame.api = "https://attacker.example/v1/responses";
    invalidApi.socket.emitMessage(JSON.stringify(invalidApiFrame));
    expect(invalidApi.socket.closeCode).toBe(1002);
    expect(invalidApi.identity.authorizeTokenRequest).not.toHaveBeenCalled();
    expect(invalidApi.fetcher).not.toHaveBeenCalled();

    const arbitraryEndpoint = createSession();
    const arbitraryEndpointFrame = startFrame(95, await makeEnvelope());
    arbitraryEndpointFrame.payload = { messages: [], endpoint: "https://attacker.example/v1/chat/completions" };
    arbitraryEndpoint.socket.emitMessage(JSON.stringify(arbitraryEndpointFrame));
    expect(arbitraryEndpoint.socket.closeCode).toBe(1002);
    expect(arbitraryEndpoint.identity.authorizeTokenRequest).not.toHaveBeenCalled();
    expect(arbitraryEndpoint.fetcher).not.toHaveBeenCalled();
  });

  it("rejects a custom provider whose route changes during the post-DNS Identity check", async () => {
    const registry: AuthorizedProvider = {
      id: "changing-llm",
      displayName: "Changing LLM",
      protocol: "openai",
      baseUrl: "https://llm.example.net/v1/",
      custom: true,
    };
    const claims = validClaims();
    let calls = 0;
    const authorize = () => {
      calls += 1;
      return {
        allowed: true,
        principal: { userId: claims.sub, projectId: claims.project_id, clientId: claims.client_id, sessionId: claims.sid },
        credentialMetadata: {
          credentialId: "credential-a",
          userId: claims.sub,
          projectId: claims.project_id,
          provider: registry.id,
          expiresAt: fixtureCredentialExpiresAt,
          keyVersion: "key-v1",
        },
        authorizedModel: { alias: "fast-chat", upstreamModel: "gpt-4o-mini" },
        authorizedProvider: calls === 1 ? registry : { ...registry, baseUrl: "https://changed.example.net/v1/" },
      };
    };
    const test = createSession({ providerRegistry: registry, authorize });
    const envelope = await makeEnvelope("user-a", "project-a", registry.id);
    const tampered = { ...envelope };
    const index = Math.floor(tampered.ciphertext.length / 2);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, index)}${tampered.ciphertext[index] === "A" ? "B" : "A"}${tampered.ciphertext.slice(index + 1)}`;
    const id = requestId(84);
    test.socket.emitMessage(JSON.stringify(startFrame(84, tampered, registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledTimes(2);
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("does not decrypt or launch upstream if cancelled while custom DNS validation is pending", async () => {
    const registry: AuthorizedProvider = {
      id: "slow-dns-llm",
      displayName: "Slow DNS LLM",
      protocol: "openai",
      baseUrl: "https://llm.example.net/v1/",
      custom: true,
    };
    const dnsResolvers: Array<(response: Response) => void> = [];
    const dnsFetcher = vi.fn(() => new Promise<Response>((resolve) => dnsResolvers.push(resolve)));
    const test = createSession({ providerRegistry: registry, endpointDnsFetcher: dnsFetcher as typeof fetch });
    const envelope = await makeEnvelope("user-a", "project-a", registry.id);
    const tampered = { ...envelope };
    const index = Math.floor(tampered.ciphertext.length / 2);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, index)}${tampered.ciphertext[index] === "A" ? "B" : "A"}${tampered.ciphertext.slice(index + 1)}`;
    const id = requestId(85);
    test.socket.emitMessage(JSON.stringify(startFrame(85, tampered, registry.id)));
    const waitUntilDnsStarted = Date.now() + 2_000;
    while (dnsFetcher.mock.calls.length < 2 && Date.now() < waitUntilDnsStarted) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(dnsFetcher).toHaveBeenCalledTimes(2);
    test.socket.emitMessage(JSON.stringify({ event: "request.cancel", requestId: id }));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "cancelled", upstreamStarted: false, retryable: false });
    expect(test.fetcher).not.toHaveBeenCalled();
    for (const resolve of dnsResolvers) {
      resolve(Response.json({ Status: 0, Answer: [{ type: 1, data: "1.1.1.1" }] }));
    }
    test.socket.peerClose();
  });

  it("does not decrypt or launch upstream when a custom DNS check finishes after token expiry", async () => {
    const registry: AuthorizedProvider = {
      id: "expiring-dns-llm",
      displayName: "Expiring DNS LLM",
      protocol: "openai",
      baseUrl: "https://llm.example.net/v1/",
      custom: true,
    };
    const claims = validClaims();
    claims.exp = Math.floor(Date.now() / 1000) + 1;
    const dnsResolvers: Array<(response: Response) => void> = [];
    const dnsFetcher = vi.fn(() => new Promise<Response>((resolve) => dnsResolvers.push(resolve)));
    const test = createSession({ providerRegistry: registry, claims, endpointDnsFetcher: dnsFetcher as typeof fetch });
    const envelope = await makeEnvelope("user-a", "project-a", registry.id);
    const tampered = { ...envelope };
    const index = Math.floor(tampered.ciphertext.length / 2);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, index)}${tampered.ciphertext[index] === "A" ? "B" : "A"}${tampered.ciphertext.slice(index + 1)}`;
    const id = requestId(86);
    test.socket.emitMessage(JSON.stringify(startFrame(86, tampered, registry.id)));
    const waitUntilDnsStarted = Date.now() + 2_000;
    while (dnsFetcher.mock.calls.length < 2 && Date.now() < waitUntilDnsStarted) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(dnsFetcher).toHaveBeenCalledTimes(2);
    while (Date.now() < claims.exp * 1000) await new Promise((resolve) => setTimeout(resolve, 10));
    for (const resolve of dnsResolvers) {
      resolve(Response.json({ Status: 0, Answer: [{ type: 1, data: "1.1.1.1" }] }));
    }

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "session_expired", upstreamStarted: false, retryable: false });
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects an unknown provider ID without a matching Identity registry record", async () => {
    const test = createSession({ providerRegistry: null, credentialProvider: "unknown-provider" });
    const id = requestId(81);
    test.socket.emitMessage(JSON.stringify(startFrame(81, await makeEnvelope("user-a", "project-a", "unknown-provider"), "unknown-provider")));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("does not use the built-in fallback for a custom ID missing Identity provider metadata", async () => {
    const test = createSession({ providerRegistry: null, credentialProvider: "custom-llm" });
    const id = requestId(87);
    test.socket.emitMessage(JSON.stringify(startFrame(87, await makeEnvelope("user-a", "project-a", "custom-llm"), "custom-llm")));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects the Identity service origin as a custom upstream", async () => {
    const registry: AuthorizedProvider = {
      id: "self-target-llm",
      displayName: "Self Target LLM",
      protocol: "openai",
      baseUrl: "https://identity.example.test/v1/",
      custom: true,
    };
    const test = createSession({ providerRegistry: registry });
    const id = requestId(88);
    test.socket.emitMessage(JSON.stringify(startFrame(88, await makeEnvelope("user-a", "project-a", registry.id), registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects a configured Gateway origin as a custom upstream", async () => {
    const registry: AuthorizedProvider = {
      id: "gateway-self-target-llm",
      displayName: "Gateway Self Target LLM",
      protocol: "openai",
      baseUrl: "https://gateway.example.test/v1/",
      custom: true,
    };
    const test = createSession({ providerRegistry: registry, gatewayOrigin: "wss://gateway.example.test" });
    const id = requestId(91);
    test.socket.emitMessage(JSON.stringify(startFrame(91, await makeEnvelope("user-a", "project-a", registry.id), registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects a hostile registry endpoint before decrypting or resolving it", async () => {
    const registry: AuthorizedProvider = {
      id: "hostile-llm",
      displayName: "Hostile LLM",
      protocol: "openai",
      baseUrl: "http://127.0.0.1/v1/",
      custom: true,
    };
    const envelope = await makeEnvelope("user-a", "project-a", registry.id);
    const tampered = { ...envelope };
    const index = Math.floor(tampered.ciphertext.length / 2);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, index)}${tampered.ciphertext[index] === "A" ? "B" : "A"}${tampered.ciphertext.slice(index + 1)}`;
    const test = createSession({ providerRegistry: registry });
    const id = requestId(82);
    test.socket.emitMessage(JSON.stringify(startFrame(82, tampered, registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(test.endpointDnsFetcher).not.toHaveBeenCalled();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
  });

  it("rejects custom hosts resolving to private IPs before decrypting or calling upstream", async () => {
    const registry: AuthorizedProvider = {
      id: "private-llm",
      displayName: "Private LLM",
      protocol: "openai",
      baseUrl: "https://llm.example.net/v1/",
      custom: true,
    };
    const dnsFetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? new URL(input.url) : new URL(String(input));
      const isV6 = url.searchParams.get("type") === "AAAA" || url.searchParams.get("type") === "28";
      return Response.json({
        Status: 0,
        Answer: [{ type: isV6 ? 28 : 1, data: isV6 ? "fd00::1" : "10.0.0.7" }],
      });
    });
    const envelope = await makeEnvelope("user-a", "project-a", registry.id);
    const tampered = { ...envelope };
    const index = Math.floor(tampered.ciphertext.length / 2);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, index)}${tampered.ciphertext[index] === "A" ? "B" : "A"}${tampered.ciphertext.slice(index + 1)}`;
    const test = createSession({ providerRegistry: registry, endpointDnsFetcher: dnsFetcher as typeof fetch });
    const id = requestId(83);
    test.socket.emitMessage(JSON.stringify(startFrame(83, tampered, registry.id)));

    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === id);
    expect(terminal).toMatchObject({ code: "provider_disallowed", upstreamStarted: false, retryable: false });
    expect(dnsFetcher).toHaveBeenCalledTimes(2);
    expect(test.identity.authorizeTokenRequest).toHaveBeenCalledOnce();
    expect(test.fetcher).not.toHaveBeenCalled();
    test.socket.peerClose();
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

  it("classifies provider policy errors without exposing provider error text", async () => {
    const test = createSession({ fetcher: async () => Response.json({ error: { type: "FreeTierError", message: "sk-sensitive-key-private-prompt" } }, { status: 403 }) });
    test.socket.emitMessage(JSON.stringify(startFrame(29, await makeEnvelope())));
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(29));
    expect(terminal).toMatchObject({ code: "upstream_error", message: "The provider returned HTTP 403 (free_model_restricted).", upstreamStarted: true, retryable: false });
    expect(JSON.stringify(terminal)).not.toContain("sk-sensitive");
    expect(test.fetcher).toHaveBeenCalledOnce();
    test.socket.peerClose();
  });

  it.each([400, 401, 403, 500])("reports only safe upstream HTTP status %i", async (status) => {
    const test = createSession({ fetcher: async () => new Response('private-key-and-prompt-must-not-leak', { status }) });
    test.socket.emitMessage(JSON.stringify(startFrame(28, await makeEnvelope())));
    const terminal = await waitForFrame(test.socket, (frame) => frame.event === "response.error" && frame.requestId === requestId(28));
    expect(terminal).toMatchObject({ code: "upstream_error", message: `The provider returned HTTP ${status}.`, upstreamStarted: true, retryable: status >= 500 });
    expect(JSON.stringify(terminal)).not.toContain("private-key-and-prompt");
    expect(test.fetcher).toHaveBeenCalledOnce();
    test.socket.peerClose();
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
    const request = buildProviderRequest("openai", "https://api.openai.com/v1/chat/completions", "sk-test", "gpt-4o-mini", { messages: [] }, new AbortController().signal);
    expect(request.url).toBe("https://api.openai.com/v1/chat/completions");
    expect(request.init.redirect).toBe("manual");
    expect(new Headers(request.init.headers).get("authorization")).toBe("Bearer sk-test");
    expect(new Headers(request.init.headers).get("x-api-key")).toBeNull();
    expect(JSON.parse(String(request.init.body))).toMatchObject({ model: "gpt-4o-mini", stream: true });
    const anthropic = buildProviderRequest("anthropic", "https://api.anthropic.com/v1/messages", "sk-ant-test", "claude-haiku", { messages: [] }, new AbortController().signal);
    expect(anthropic.url).toBe("https://api.anthropic.com/v1/messages");
    expect(anthropic.init.redirect).toBe("manual");
    expect(new Headers(anthropic.init.headers).get("x-api-key")).toBe("sk-ant-test");
    expect(new Headers(anthropic.init.headers).get("authorization")).toBeNull();
    expect(JSON.parse(String(anthropic.init.body))).toMatchObject({ model: "claude-haiku", stream: true });
    const responses = buildProviderRequest(
      "openai",
      "https://api.openai.com/v1/responses",
      "sk-test",
      "gpt-4o-mini",
      { input: "hello" },
      new AbortController().signal,
      "responses",
    );
    expect(responses.url).toBe("https://api.openai.com/v1/responses");
    expect(JSON.parse(String(responses.init.body))).toMatchObject({ input: "hello", store: false, model: "gpt-4o-mini", stream: true });
    const completions = buildProviderRequest(
      "openai",
      "https://api.openai.com/v1/completions",
      "sk-test",
      "gpt-4o-mini",
      { prompt: "hello" },
      new AbortController().signal,
      "completions",
    );
    expect(completions.url).toBe("https://api.openai.com/v1/completions");
    expect(JSON.parse(String(completions.init.body))).toMatchObject({ prompt: "hello", model: "gpt-4o-mini", stream: true });
    expect(() => buildProviderRequest(
      "openai",
      "https://api.openai.com/v1/chat/completions",
      "sk-test",
      "gpt-4o-mini",
      { input: "hello" },
      new AbortController().signal,
      "responses",
    )).toThrow(/endpoint is invalid/);
    expect(() => buildProviderRequest(
      "anthropic",
      "https://api.anthropic.com/v1/messages",
      "sk-ant-test",
      "claude-haiku",
      { input: "hello" },
      new AbortController().signal,
      "responses",
    )).toThrow(/not supported by this provider/);
    expect(() => buildProviderRequest(
      "openai",
      "https://api.openai.com/v1/responses",
      "sk-test",
      "gpt-4o-mini",
      { input: "hello", previous_response_id: "resp_previous" },
      new AbortController().signal,
      "responses",
    )).toThrow(/stateless/);
    expect(() => buildProviderRequest(
      "openai",
      "https://api.openai.com/v1/responses",
      "sk-test",
      "gpt-4o-mini",
      { input: [{ type: "item_reference", id: "resp_remote_item" }] },
      new AbortController().signal,
      "responses",
    )).toThrow(/stateless/);
    expect(() => buildProviderRequest(
      "openai",
      "https://api.openai.com/v1/chat/completions",
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
