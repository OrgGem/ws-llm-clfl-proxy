import { encryptCredentialEnvelope, issueGatewayAccessToken, type ProviderRequestApi } from "@ws-proxy/shared";
import { env, reset, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decodeBase64Url, migrateIdentityDatabase, randomId, randomProviderSecret } from "./db-fixtures.js";

interface GatewayTestEnv {
  DB: D1Database;
  MACHINE_ISSUER: string;
  MACHINE_JWT_PRIVATE_JWK: string;
  ENVELOPE_KEYS: string;
}

interface UserFixture {
  id: string;
  subject: string;
  projectId: string;
  clientRowId: string;
  clientIdentifier: string;
  sessionId: string;
  credentialId: string;
  credentialExpiresAt: number;
  envelope: Awaited<ReturnType<typeof encryptCredentialEnvelope>>;
}

interface ProviderStats {
  requests: number;
  cancellations: number;
  lastRequest: { method: string; origin: string; path: string } | null;
}

interface ServerFrame {
  event: string;
  [key: string]: unknown;
}

class SocketInbox {
  private readonly queued: ServerFrame[] = [];
  private readonly waiters: Array<{
    resolve: (frame: ServerFrame) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  constructor(private readonly socket: WebSocket) {
    socket.addEventListener("message", (event: MessageEvent<unknown>) => {
      try {
        const value = typeof event.data === "string"
          ? event.data
          : new TextDecoder().decode(event.data as ArrayBuffer);
        const frame = JSON.parse(value) as ServerFrame;
        const waiter = this.waiters.shift();
        if (waiter) {
          clearTimeout(waiter.timer);
          waiter.resolve(frame);
        } else {
          this.queued.push(frame);
        }
      } catch (error) {
        const waiter = this.waiters.shift();
        if (waiter) {
          clearTimeout(waiter.timer);
          waiter.reject(error instanceof Error ? error : new Error("Invalid WebSocket frame"));
        }
      }
    });
    socket.addEventListener("error", () => {
      const error = new Error("Gateway WebSocket failed");
      for (const waiter of this.waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(error);
      }
    });
  }

  next(timeoutMs = 5_000): Promise<ServerFrame> {
    const queued = this.queued.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      const waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const index = this.waiters.indexOf(waiter);
          if (index >= 0) this.waiters.splice(index, 1);
          reject(new Error("Timed out waiting for a Gateway frame"));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
    });
  }
}

const integrationEnv = env as unknown as GatewayTestEnv;
const openSockets: WebSocket[] = [];
let fixtures: { owner: UserFixture; other: UserFixture };
let providerRequestCount = 0;
let providerCancellationCount = 0;
let dnsRequestCount = 0;
let lastProviderRequest: ProviderStats["lastRequest"] = null;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(integrationEnv.DB);
  providerRequestCount = 0;
  providerCancellationCount = 0;
  dnsRequestCount = 0;
  lastProviderRequest = null;
  vi.stubGlobal("fetch", mockProviderFetch);
  fixtures = await seedGatewayDatabase();
});

afterEach(() => {
  vi.unstubAllGlobals();
  for (const socket of openSockets.splice(0)) {
    try {
      if (socket.readyState === 0 || socket.readyState === 1) socket.close(1000, "test complete");
    } catch {
      // A test may already have closed its peer.
    }
  }
});

describe("Gateway and Identity Worker integration", () => {
  it("authorizes against D1, decrypts the envelope, streams provider data, and consumes cumulative ACKs", async () => {
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect(await inbox.next()).toMatchObject({
      event: "session.ready",
      maxInFlight: 1,
      maxPayloadBytes: 1_024,
      maxSessionSeconds: 60,
    });

    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(requestId, "finite", fixtures.owner.envelope)));
    const chunks: string[] = [];
    let terminal: ServerFrame | undefined;
    while (!terminal) {
      const frame = await inbox.next();
      if (frame.event === "response.chunk") {
        expect(frame.requestId).toBe(requestId);
        chunks.push(String(frame.data));
        socket.send(JSON.stringify({ event: "request.start", op: "ack", requestId, ackSeq: frame.seq }));
      } else if (frame.event === "response.end" || frame.event === "response.error") {
        terminal = frame;
      }
    }

    expect(terminal.event, JSON.stringify({ terminal, provider: await providerStats() })).toBe("response.end");
    expect(chunks.join("")).toContain('[DONE]');
    expect(await providerStats()).toMatchObject({ requests: 1, cancellations: 0 });
  });

  it("routes native Responses and Completions APIs to fixed OpenAI endpoints and forwards streams", async () => {
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");

    for (const testCase of [
      { api: "responses" as const, path: "/v1/responses", payload: { input: "hello" } },
      { api: "completions" as const, path: "/v1/completions", payload: { prompt: "hello" } },
    ]) {
      const requestId = crypto.randomUUID();
      const frame = startFrame(requestId, "finite", fixtures.owner.envelope, "openai", testCase.api);
      frame.payload = testCase.payload;
      socket.send(JSON.stringify(frame));
      const chunks: string[] = [];
      let terminal: ServerFrame | undefined;
      while (!terminal) {
        const response = await inbox.next();
        if (response.event === "response.chunk") {
          chunks.push(String(response.data));
          socket.send(JSON.stringify({ event: "request.start", op: "ack", requestId, ackSeq: response.seq }));
        } else if (response.event === "response.end" || response.event === "response.error") {
          terminal = response;
        }
      }
      expect(terminal).toMatchObject({ event: "response.end", requestId });
      expect(chunks.join("")).toContain("[DONE]");
      expect(await providerStats()).toMatchObject({
        lastRequest: { method: "POST", origin: "https://api.openai.com", path: testCase.path },
      });
    }
    expect(await providerStats()).toMatchObject({ requests: 2, cancellations: 0 });
    socket.close(1000, "test complete");
  });

  it("rejects arbitrary API and endpoint values before provider access", async () => {
    const cases = [
      { api: "https://attacker.example/v1/responses" },
      { payload: { messages: [], endpoint: "https://attacker.example/v1/chat/completions" } },
    ];
    for (const overrides of cases) {
      const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
      expect((await inbox.next()).event).toBe("session.ready");
      const requestId = crypto.randomUUID();
      const frame = { ...startFrame(requestId, "finite", fixtures.owner.envelope), ...overrides };
      const closed = new Promise<number>((resolve) => socket.addEventListener("close", (event) => resolve(event.code), { once: true }));
      socket.send(JSON.stringify(frame));
      expect(await closed).toBe(1002);
      expect(await providerStats()).toMatchObject({ requests: 0, cancellations: 0 });
    }
  });

  it("cancels the provider stream when the client cancels the request", async () => {
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");

    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(requestId, "hold", fixtures.owner.envelope)));
    const first = await inbox.next();
    expect(first.event).toBe("response.chunk");
    socket.send(JSON.stringify({ event: "request.start", op: "ack", requestId, ackSeq: first.seq }));
    socket.send(JSON.stringify({ event: "request.cancel", requestId }));

    const terminal = await inbox.next();
    expect(terminal).toMatchObject({ event: "response.error", requestId, code: "cancelled", upstreamStarted: true });
    const stats = await waitForProviderStats((value) => value.cancellations === 1);
    expect(stats).toMatchObject({ requests: 1, cancellations: 1 });
  });

  it("rejects a credential owned by another user before calling the provider", async () => {
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");
    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(requestId, "finite", fixtures.other.envelope)));

    expect(await inbox.next()).toMatchObject({
      event: "response.error",
      requestId,
      code: "forbidden",
      upstreamStarted: false,
    });
    expect(await providerStats()).toMatchObject({ requests: 0, cancellations: 0 });
  });

  it("rejects a revoked credential before calling the provider", async () => {
    await integrationEnv.DB.prepare("UPDATE credentials SET revoked_at = ? WHERE id = ?")
      .bind(Math.floor(Date.now() / 1000), fixtures.owner.credentialId)
      .run();

    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");
    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(requestId, "finite", fixtures.owner.envelope)));

    expect(await inbox.next()).toMatchObject({
      event: "response.error",
      requestId,
      code: "credential_invalid",
      upstreamStarted: false,
    });
    expect(await providerStats()).toMatchObject({ requests: 0, cancellations: 0 });
  });

  it("rejects a tampered credential envelope before calling the provider", async () => {
    const ciphertext = decodeBase64Url(fixtures.owner.envelope.ciphertext);
    ciphertext[0] ^= 0x01;
    const tamperedEnvelope = {
      ...fixtures.owner.envelope,
      ciphertext: encodeBase64Url(ciphertext),
    };
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");
    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(requestId, "finite", tamperedEnvelope)));

    expect(await inbox.next()).toMatchObject({
      event: "response.error",
      requestId,
      code: "credential_invalid",
      upstreamStarted: false,
    });
    expect(await providerStats()).toMatchObject({ requests: 0, cancellations: 0 });
  });

  it("routes a granted custom provider through its registry URL after public DNS validation", async () => {
    const now = Math.floor(Date.now() / 1000);
    const customProvider = "custom-openai";
    const customAlias = "custom-model";
    const baseUrl = "https://custom-provider.example.org/v1/";
    const envelopeKeyConfig = JSON.parse(integrationEnv.ENVELOPE_KEYS) as { current: string; keys: Record<string, string> };
    const envelopeKid = envelopeKeyConfig.current;
    const envelopeKey = decodeBase64Url(envelopeKeyConfig.keys[envelopeKid]!);
    const credentialId = randomId("cred");
    const credentialExpiresAt = now + 3_600;
    const envelope = await encryptCredentialEnvelope(
      new TextEncoder().encode(randomProviderSecret()),
      {
        credentialId,
        userId: fixtures.owner.id,
        projectId: fixtures.owner.projectId,
        provider: customProvider,
        kid: envelopeKid,
        exp: credentialExpiresAt,
      },
      envelopeKey,
    );

    await integrationEnv.DB.prepare(
      "INSERT INTO providers(provider,display_name,enabled,protocol,base_url,custom) VALUES(?,?,1,'openai',?,1)",
    ).bind(customProvider, "Custom OpenAI", baseUrl).run();
    await integrationEnv.DB.prepare(
      "INSERT INTO provider_models(provider,alias,upstream_model,display_name,enabled,created_at) VALUES(?,?,?,'Custom Model',1,?)",
    ).bind(customProvider, customAlias, "org/custom-model", now).run();
    await integrationEnv.DB.prepare(
      "INSERT INTO project_permissions(project_id,provider,model,created_by,created_at) VALUES(?,?,?,?,?)",
    ).bind(fixtures.owner.projectId, customProvider, customAlias, fixtures.owner.id, now).run();
    await integrationEnv.DB.prepare(
      "INSERT INTO client_permissions(client_id,provider,model,created_by,created_at) VALUES(?,?,?,?,?)",
    ).bind(fixtures.owner.clientRowId, customProvider, customAlias, fixtures.owner.id, now).run();
    await integrationEnv.DB.prepare(
      "INSERT INTO credentials(id,user_id,project_id,provider,key_version,expires_at,created_at) VALUES(?,?,?,?,?,?,?)",
    ).bind(credentialId, fixtures.owner.id, fixtures.owner.projectId, customProvider, envelopeKid, credentialExpiresAt, now).run();

    const token = await machineToken(fixtures.owner);
    const identityBinding = (env as unknown as {
      IDENTITY: { authorizeTokenRequest(input: { accessToken: string; credentialId: string; provider: string; model: string }): Promise<unknown> };
    }).IDENTITY;
    const authorization = await identityBinding.authorizeTokenRequest({ accessToken: token, credentialId, provider: customProvider, model: customAlias });
    expect(authorization).toMatchObject({
      allowed: true,
      authorizedProvider: { id: customProvider, protocol: "openai", baseUrl, custom: true },
      authorizedModel: { alias: customAlias, upstreamModel: "org/custom-model" },
    });

    const { socket, inbox } = await connectGateway(token);
    expect((await inbox.next()).event).toBe("session.ready");
    const requestId = crypto.randomUUID();
    const frame = startFrame(requestId, customAlias, envelope, customProvider);
    frame.payload = { messages: [{ role: "user", content: "custom provider request" }] };
    socket.send(JSON.stringify(frame));

    let terminal: ServerFrame | undefined;
    while (!terminal) {
      const response = await inbox.next();
      if (response.event === "response.chunk") {
        socket.send(JSON.stringify({ event: "request.start", op: "ack", requestId, ackSeq: response.seq }));
      } else if (response.event === "response.end" || response.event === "response.error") {
        terminal = response;
      }
    }
    expect(terminal, JSON.stringify({ terminal, stats: await providerStats(), dnsRequestCount })).toMatchObject({ event: "response.end", requestId });
    expect(dnsRequestCount).toBe(2);
    expect(await providerStats()).toMatchObject({
      requests: 1,
      cancellations: 0,
      lastRequest: { method: "POST", origin: "https://custom-provider.example.org", path: "/v1/chat/completions" },
    });
  });

  it("enforces current project and client model ACLs before provider access", async () => {
    await integrationEnv.DB.prepare("DELETE FROM client_permissions WHERE client_id = ? AND model = 'finite'")
      .bind(fixtures.owner.clientRowId)
      .run();

    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");
    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(requestId, "finite", fixtures.owner.envelope)));

    expect(await inbox.next()).toMatchObject({
      event: "response.error",
      requestId,
      code: "model_disallowed",
      upstreamStarted: false,
    });
    expect(await providerStats()).toMatchObject({ requests: 0, cancellations: 0 });
  });

  it("enforces the project provider-payload size limit before provider access", async () => {
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");
    const requestId = crypto.randomUUID();
    socket.send(JSON.stringify({
      ...startFrame(requestId, "finite", fixtures.owner.envelope),
      payload: { messages: [{ role: "user", content: "x".repeat(1_200) }] },
    }));

    expect(await inbox.next()).toMatchObject({
      event: "response.error",
      requestId,
      code: "invalid_request",
      upstreamStarted: false,
    });
    expect(await providerStats()).toMatchObject({ requests: 0, cancellations: 0 });
  });

  it("limits concurrent provider requests to the project setting", async () => {
    const { socket, inbox } = await connectGateway(await machineToken(fixtures.owner));
    expect((await inbox.next()).event).toBe("session.ready");
    const firstRequestId = crypto.randomUUID();
    const secondRequestId = crypto.randomUUID();
    socket.send(JSON.stringify(startFrame(firstRequestId, "hold", fixtures.owner.envelope)));
    const firstChunk = await inbox.next();
    expect(firstChunk).toMatchObject({ event: "response.chunk", requestId: firstRequestId });
    socket.send(JSON.stringify({ event: "request.start", op: "ack", requestId: firstRequestId, ackSeq: firstChunk.seq }));
    socket.send(JSON.stringify(startFrame(secondRequestId, "finite", fixtures.owner.envelope)));

    expect(await inbox.next()).toMatchObject({
      event: "response.error",
      requestId: secondRequestId,
      code: "overloaded",
      upstreamStarted: false,
    });
    socket.send(JSON.stringify({ event: "request.cancel", requestId: firstRequestId }));
    expect(await inbox.next()).toMatchObject({ event: "response.error", requestId: firstRequestId, code: "cancelled" });
    expect(await waitForProviderStats((stats) => stats.cancellations === 1)).toMatchObject({ requests: 1, cancellations: 1 });
  });
});

function startFrame(
  requestId: string,
  model: string,
  envelope: UserFixture["envelope"],
  provider = "openai",
  api?: ProviderRequestApi,
): Record<string, unknown> {
  return {
    event: "request.start",
    requestId,
    ...(api === undefined ? {} : { api }),
    provider,
    model,
    envelope,
    payload: { messages: [{ role: "user", content: "integration request" }] },
  };
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function connectGateway(token: string): Promise<{ socket: WebSocket; inbox: SocketInbox }> {
  const response = await SELF.fetch(new Request("https://ws-llm-gateway-staging.test/v1/socket", {
    method: "GET",
    headers: {
      authorization: `Bearer ${token}`,
      connection: "Upgrade",
      upgrade: "websocket",
      "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
      "sec-websocket-version": "13",
      "sec-websocket-protocol": "llm-proxy.v1",
    },
  }));
  expect(response.status).toBe(101);
  const socket = (response as Response & { webSocket?: WebSocket }).webSocket;
  expect(socket).toBeDefined();
  if (!socket) throw new Error("Gateway upgrade returned no client WebSocket");
  socket.accept();
  openSockets.push(socket);
  return { socket, inbox: new SocketInbox(socket) };
}

async function machineToken(user: UserFixture): Promise<string> {
  const jwk = JSON.parse(integrationEnv.MACHINE_JWT_PRIVATE_JWK) as JsonWebKey & { kid: string };
  const signingJwk: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
  const key = await crypto.subtle.importKey("jwk", signingJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return issueGatewayAccessToken({
    userId: user.id,
    sessionId: user.sessionId,
    projectId: user.projectId,
    clientId: user.clientIdentifier,
    tokenId: randomId("jti"),
  }, key, { issuer: integrationEnv.MACHINE_ISSUER, kid: jwk.kid });
}

async function seedGatewayDatabase(): Promise<{ owner: UserFixture; other: UserFixture }> {
  const now = Math.floor(Date.now() / 1000);
  const keyConfig = JSON.parse(integrationEnv.ENVELOPE_KEYS) as { current: string; keys: Record<string, string> };
  const envelopeKey = decodeBase64Url(keyConfig.keys[keyConfig.current]!);
  const owner = await createUser("owner", now, keyConfig.current, envelopeKey);
  const other = await createUser("other", now, keyConfig.current, envelopeKey);

  for (const [alias, upstreamModel] of [["finite", "integration-finite"], ["hold", "integration-hold"]] as const) {
    await integrationEnv.DB.prepare(
      "INSERT INTO provider_models (provider, alias, upstream_model, display_name, enabled, created_at) VALUES ('openai', ?, ?, ?, 1, ?)",
    ).bind(alias, upstreamModel, alias, now).run();
    await integrationEnv.DB.prepare(
      "INSERT INTO project_permissions (project_id, provider, model, created_by, created_at) VALUES (?, 'openai', ?, ?, ?)",
    ).bind(owner.projectId, alias, owner.id, now).run();
    await integrationEnv.DB.prepare(
      "INSERT INTO client_permissions (client_id, provider, model, created_by, created_at) VALUES (?, 'openai', ?, ?, ?)",
    ).bind(owner.clientRowId, alias, owner.id, now).run();
  }
  await integrationEnv.DB.prepare(
    "INSERT INTO project_limits (project_id, max_payload_bytes, max_concurrency, max_session_seconds, updated_by, updated_at) VALUES (?, 1024, 1, 60, ?, ?)",
  ).bind(owner.projectId, owner.id, now).run();
  return { owner, other };
}

async function createUser(
  label: string,
  now: number,
  envelopeKid: string,
  envelopeKey: Uint8Array,
): Promise<UserFixture> {
  const issuer = "https://accounts.integration.test";
  const subject = `sub-${label}-${crypto.randomUUID()}`;
  const id = randomId("usr");
  const projectId = randomId("prj");
  const clientRowId = randomId("client");
  const clientIdentifier = randomId("cli");
  const secretHash = await sha256Base64Url(randomProviderSecret());
  const sessionId = randomId("ses");
  const credentialId = randomId("cred");
  const credentialExpiresAt = now + 3_600;

  await integrationEnv.DB.prepare(
    "INSERT INTO user_allowlist (issuer, subject, email, is_admin, approved_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
  ).bind(issuer, subject, `${label}@integration.test`, now, now).run();
  await integrationEnv.DB.prepare(
    "INSERT INTO users (id, issuer, subject, email, display_name, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
  ).bind(id, issuer, subject, `${label}@integration.test`, label, now, now).run();
  await integrationEnv.DB.prepare(
    "INSERT INTO projects (id, owner_user_id, name, created_at) VALUES (?, ?, 'Integration', ?)",
  ).bind(projectId, id, now).run();
  await integrationEnv.DB.prepare(
    "INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
  ).bind(projectId, id, now).run();
  await integrationEnv.DB.prepare(
    "INSERT INTO clients (id, client_identifier, project_id, created_by, name, kind, secret_hash, active, created_at) VALUES (?, ?, ?, ?, 'Integration adapter', 'confidential', ?, 1, ?)",
  ).bind(clientRowId, clientIdentifier, projectId, id, secretHash, now).run();
  await integrationEnv.DB.prepare(
    "INSERT INTO sessions (id, user_id, project_id, client_id, kind, device_name, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, 'client_credentials', 'integration', ?, ?, ?)",
  ).bind(sessionId, id, projectId, clientRowId, now, now + 3_600, now).run();
  const envelope = await encryptCredentialEnvelope(
    new TextEncoder().encode(randomProviderSecret()),
    { credentialId, userId: id, projectId, provider: "openai", kid: envelopeKid, exp: credentialExpiresAt },
    envelopeKey,
  );
  await integrationEnv.DB.prepare(
    "INSERT INTO credentials (id, user_id, project_id, provider, key_version, expires_at, created_at) VALUES (?, ?, ?, 'openai', ?, ?, ?)",
  ).bind(credentialId, id, projectId, envelopeKid, credentialExpiresAt, now).run();
  return { id, subject, projectId, clientRowId, clientIdentifier, sessionId, credentialId, credentialExpiresAt, envelope };
}

async function providerStats(): Promise<ProviderStats> {
  return {
    requests: providerRequestCount,
    cancellations: providerCancellationCount,
    lastRequest: lastProviderRequest,
  };
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function mockProviderFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.origin === "https://cloudflare-dns.com" && url.pathname === "/dns-query") {
    dnsRequestCount += 1;
    const type = url.searchParams.get("type");
    const answer = type === "A"
      ? [{ name: url.searchParams.get("name"), type: 1, TTL: 300, data: "1.1.1.1" }]
      : type === "AAAA"
        ? [{ name: url.searchParams.get("name"), type: 28, TTL: 300, data: "2606:4700:4700::1111" }]
        : [];
    return Response.json({ Status: 0, Answer: answer }, { headers: { "content-type": "application/dns-json" } });
  }
  const request = new Request(input, init);
  lastProviderRequest = { method: request.method, origin: url.origin, path: url.pathname };
  if (request.method !== "POST" || !["https://api.openai.com", "https://custom-provider.example.org"].includes(url.origin) ||
      !["/v1/chat/completions", "/v1/responses", "/v1/completions"].includes(url.pathname)) {
    return Response.json({ error: "unexpected provider route" }, { status: 404 });
  }

  providerRequestCount += 1;
  const payload = await request.clone().json() as { model?: string };
  const encoder = new TextEncoder();
  if (payload.model === "integration-hold") {
    return new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'));
      },
      cancel() {
        providerCancellationCount += 1;
      },
    }), { headers: { "content-type": "text/event-stream" } });
  }

  return new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode('data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'));
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      controller.close();
    },
  }), { headers: { "content-type": "text/event-stream" } });
}

async function waitForProviderStats(predicate: (stats: ProviderStats) => boolean): Promise<ProviderStats> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const stats = await providerStats();
    if (predicate(stats)) return stats;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return providerStats();
}
