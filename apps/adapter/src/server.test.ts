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

  it("keeps a custom provider ID for Gateway authorization and converts by its explicit protocol", async () => {
    const upstream = [
      'data: {"choices":[{"index":0,"delta":{"content":"custom reply"},"finish_reason":null}]}\n\n',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
      "data: [DONE]\n\n",
    ].join("");
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        expect(input.provider).toBe("vendor_x");
        expect(input.model).toBe("vendor-chat");
        expect(input.payload).toMatchObject({ messages: [{ role: "user", content: "hello" }], frequency_penalty: 0.3 });
        await callbacks.onChunk(0, upstream);
        await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway, 2, {
      id: "vendor-chat",
      provider: "vendor_x",
      protocol: "openai",
      credentialId: "credential_test",
    });
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "vendor-chat", messages: [{ role: "user", content: "hello" }], frequency_penalty: 0.3, stream: true }),
    });

    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain('"content":"custom reply"');
    expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it("streams interleaved choices, tool arguments, logprobs and detailed usage without merging choices", async () => {
    const upstream = [
      { choices: [{ index: 1, delta: { content: "Second" }, logprobs: { content: [{ token: "Second", logprob: -0.2, bytes: [83], top_logprobs: [] }] }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "lookup", arguments: '{"q":' } }] }, finish_reason: null }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '"test"}' } }] }, finish_reason: "tool_calls" }, { index: 1, delta: {}, finish_reason: "stop" }] },
      { choices: [], usage: { prompt_tokens: 9, completion_tokens: 4, total_tokens: 13, completion_tokens_details: { reasoning_tokens: 2 } } },
    ].map((event) => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n";
    const { server, token } = await createServer({
      execute: async (input, callbacks) => {
        expect(input.payload.n).toBe(2);
        // Split JSON and tool argument fragments across unrelated transport boundaries.
        for (let offset = 0, seq = 0; offset < upstream.length; offset += 11, seq++) {
          await callbacks.onChunk(seq, upstream.slice(offset, offset + 11));
        }
        await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0, usage: { inputTokens: 9, outputTokens: 4, totalTokens: 13 } });
      }, close: () => undefined,
    });
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "local-chat", messages: [{ role: "user", content: "test" }], n: 2, stream: true, stream_options: { include_usage: true } }),
    });
    const body = await response.text();
    const events = body.split("\n\n").filter((line) => line.startsWith("data: ") && !line.includes("[DONE]")).map((line) => JSON.parse(line.slice(6)));
    expect(events.flatMap((event) => event.choices).filter((choice) => choice.delta.role).map((choice) => choice.index).sort()).toEqual([0, 1]);
    expect(events.flatMap((event) => event.choices).filter((choice) => choice.finish_reason).map((choice) => [choice.index, choice.finish_reason])).toEqual([[0, "tool_calls"], [1, "stop"]]);
    expect(events.flatMap((event) => event.choices).find((choice) => choice.logprobs)?.logprobs.content[0].token).toBe("Second");
    expect(events.at(-1).usage.completion_tokens_details.reasoning_tokens).toBe(2);
    expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it("returns separate buffered choices with refusal and logprobs", async () => {
    const { server, token } = await createServer({
      execute: async (input, callbacks) => {
        await callbacks.onChunk(0, 'data: {"choices":[{"index":0,"delta":{"refusal":"Cannot do that"},"logprobs":{"refusal":[{"token":"Cannot","logprob":-0.1}]},"finish_reason":"stop"},{"index":1,"delta":{"content":"Safe alternative"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n');
        await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
      }, close: () => undefined,
    });
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "local-chat", messages: [{ role: "user", content: "test" }], n: 2 }),
    });
    const body = await response.json() as { choices: Array<{ index: number; message: { content: string; refusal?: string }; logprobs?: { refusal: unknown[] } }> };
    expect(body.choices.map((choice) => choice.index)).toEqual([0, 1]);
    expect(body.choices[0]?.message.refusal).toBe("Cannot do that");
    expect(body.choices[0]?.logprobs?.refusal).toHaveLength(1);
    expect(body.choices[1]?.message.content).toBe("Safe alternative");
  });

  it("never reports a successful terminal when provider DONE lacks a choice finish reason", async () => {
    const { server, token } = await createServer({
      execute: async (input, callbacks) => {
        try {
          await callbacks.onChunk(0, 'data: {"choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}\n\ndata: [DONE]\n\n');
          await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
        } catch (error) { await callbacks.onLocalFailure(error as Error); }
      }, close: () => undefined,
    });
    const response = await fetch(`http://127.0.0.1:${server.port}/v1/chat/completions`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "local-chat", messages: [{ role: "user", content: "test" }], stream: true }),
    });
    const body = await response.text();
    expect(body).toContain("partial");
    expect(body).toContain('"code":"stream_error"');
    expect(body).not.toContain("[DONE]");
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

async function createServer(
  gateway: GatewayExecutor,
  maxGatewaySessions = 2,
  model: { id: string; provider: string; protocol?: string; credentialId: string } = {
    id: "local-chat", provider: "openai", credentialId: "credential_test",
  },
): Promise<{
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
    models: [model],
    envelopes: [{
      v: 1,
      alg: "A256GCM",
      kid: "test-key",
      credentialId: "credential_test",
      userId: "user_test",
      projectId: "project_test",
      provider: model.provider,
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
