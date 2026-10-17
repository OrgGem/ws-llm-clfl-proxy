import { mkdtemp, rm } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigStore, createInitialConfig, validateConfig } from "./config.js";
import { startAdapter, type GatewayExecutor } from "./server.js";

const temporaryDirectories: string[] = [];
const runningServers: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(runningServers.splice(0).map((server) => server.close()));
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("loopback OpenAI-compatible HTTP boundary", () => {
  it("guards Host, Origin, and bearer authorization and serves configured models", async () => {
    const { server, token } = await createServer({ execute: async () => undefined, close: () => undefined });
    const endpoint = `http://127.0.0.1:${server.port}/v1/models`;

    expect(await requestStatus(endpoint, { authorization: `Bearer ${token}`, host: "attacker.example" })).toBe(403);
    expect((await fetch(endpoint, { headers: { authorization: `Bearer ${token}`, origin: "https://attacker.example" } })).status).toBe(403);
    expect((await fetch(endpoint)).status).toBe(401);
    const models = await fetch(endpoint, { headers: { authorization: `Bearer ${token}` } });
    expect(models.status).toBe(200);
    expect(models.headers.get("x-ws-proxy-gateway-session-limit")).toBe("2");
  });

  it("exposes the enforced one-socket benchmark setting", async () => {
    const { server, token } = await createServer({ execute: async () => undefined, close: () => undefined }, 1);
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/models`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.headers.get("x-ws-proxy-gateway-session-limit")).toBe("1");
  });

  it("converts a real API request to Gateway frames and ends SSE only after provider completion", async () => {
    let receivedModel = "";
    const upstream = [
      'data: {"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}\n\n',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
      "data: [DONE]\n\n",
    ].join("");
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        receivedModel = input.model;
        expect(input.provider).toBe("openai");
        expect(input.payload).toMatchObject({ messages: [{ role: "user", content: "hello" }] });
        await callbacks.onChunk(0, upstream);
        await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "local-chat", messages: [{ role: "user", content: "hello" }], stream: true }),
    });

    const body = await response.text();
    expect(response.status).toBe(200);
    expect(receivedModel).toBe("local-chat");
    expect(body).toContain('"content":"hello"');
    expect(body).toContain('"finish_reason":"stop"');
    expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it("returns a sanitized Gateway failure without leaking its rejection message", async () => {
    const gateway: GatewayExecutor = {
      execute: async () => { throw new Error("secret key and private prompt"); },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "local-chat", messages: [{ role: "user", content: "hello" }], stream: false }),
    });
    const body = await response.text();

    expect(response.status).toBe(502);
    expect(body).toContain("gateway_unavailable");
    expect(body).not.toContain("secret key");
    expect(body).not.toContain("private prompt");
  });

  it("cancels Gateway work when the local HTTP caller disconnects", async () => {
    const started = deferred<void>();
    const cancelled = deferred<void>();
    const gateway: GatewayExecutor = {
      execute: async (_input, _callbacks, signal) => {
        started.resolve();
        if (signal?.aborted) {
          cancelled.resolve();
          return;
        }
        await new Promise<void>((resolve) => {
          signal?.addEventListener("abort", () => {
            cancelled.resolve();
            resolve();
          }, { once: true });
        });
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const controller = new AbortController();
    const request = fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "local-chat", messages: [{ role: "user", content: "hello" }], stream: true }),
      signal: controller.signal,
    }).catch(() => undefined);
    await started.promise;
    controller.abort();
    await cancelled.promise;
    await request;
  });
});

async function createServer(gateway: GatewayExecutor, maxGatewaySessions = 2): Promise<{
  server: Awaited<ReturnType<typeof startAdapter>>;
  token: string;
}> {
  const directory = await mkdtemp(path.join(tmpdir(), "adapter-http-"));
  temporaryDirectories.push(directory);
  const store = new ConfigStore(path.join(directory, "state", "adapter.json"));
  const initial = createInitialConfig({
    identityUrl: "http://127.0.0.1:3000",
    gatewayUrl: "ws://127.0.0.1:8787/session",
    auth: { type: "public", clientId: "client_test", refreshToken: "refresh-token-test" },
  });
  const configured = validateConfig({
    ...initial,
    models: [{ id: "local-chat", provider: "openai", credentialId: "credential_test" }],
    envelopes: [{
      v: 1,
      alg: "A256GCM",
      kid: "test-key",
      credentialId: "credential_test",
      userId: "user_test",
      projectId: "project_test",
      provider: "openai",
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
    }],
  });
  await store.save(configured);
  const server = await startAdapter({ configStore: store, portOverride: 0, gateway, maxGatewaySessions });
  runningServers.push(server);
  return { server, token: configured.localBearerToken };
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function requestStatus(url: string, headers: Record<string, string>): Promise<number> {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: target.hostname,
      port: Number(target.port),
      path: target.pathname,
      method: "GET",
      headers,
    }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode ?? 0));
    });
    request.once("error", reject);
    request.end();
  });
}
