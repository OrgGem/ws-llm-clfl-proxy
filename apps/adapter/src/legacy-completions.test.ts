import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConfigStore, createInitialConfig, validateConfig } from "./config.js";
import { startAdapter, type GatewayExecutor } from "./server.js";
import type { ResponseEndMessage } from "@ws-proxy/shared";

const temporaryDirectories: string[] = [];
const runningServers: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(runningServers.splice(0).map((server) => server.close()));
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("native legacy Completions HTTP adapter", () => {
  it("forwards completion parameters and streams native text chunks while withholding DONE until Gateway end", async () => {
    const chunkWritten = deferred<void>();
    const finishRequest = deferred<void>();
    const stream = [
      `data: ${JSON.stringify({ choices: [
        { text: "hel", index: 0, logprobs: { tokens: ["hel"], token_logprobs: [-0.1], top_logprobs: [{ hel: -0.1 }], text_offset: [0] }, finish_reason: null },
        { text: "yo", index: 1, logprobs: null, finish_reason: null },
      ] })}\n\n`,
      `data: ${JSON.stringify({ choices: [
        { text: "lo", index: 0, logprobs: { tokens: ["lo"], token_logprobs: [-0.2], top_logprobs: [{ lo: -0.2 }], text_offset: [3] }, finish_reason: "stop" },
        { text: "!", index: 1, logprobs: null, finish_reason: "length" },
      ] })}\n\n`,
      `data: ${JSON.stringify({ choices: [], usage: { prompt_tokens: 4, completion_tokens: 5, total_tokens: 9 } })}\n\n`,
      "data: [DONE]\n\n",
    ].join("");
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        expect(input.api).toBe("completions");
        expect(input.provider).toBe("custom_openai");
        expect(input.model).toBe("local-instruct");
        expect(input.payload).toMatchObject({
          prompt: ["first", "second"],
          suffix: "!",
          max_tokens: 19,
          n: 1,
          logprobs: 2,
          echo: true,
          stop: ["END"],
          frequency_penalty: 0.2,
          stream_options: { include_usage: true },
        });
        expect(input.payload).not.toHaveProperty("model");
        expect(input.payload).not.toHaveProperty("stream");
        await callbacks.onChunk(0, stream);
        chunkWritten.resolve();
        await finishRequest.promise;
        await callbacks.onEnd(gatewayEnd(input.requestId));
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway, { id: "local-instruct", provider: "custom_openai", protocol: "openai" });
    const responsePromise = fetch(completionsUrl(server.port), {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        model: "local-instruct",
        prompt: ["first", "second"],
        max_tokens: 19,
        n: 1,
        suffix: "!",
        logprobs: 2,
        echo: true,
        stop: ["END"],
        frequency_penalty: 0.2,
        stream: true,
        stream_options: { include_usage: true },
      }),
    });

    await chunkWritten.promise;
    const response = await responsePromise;
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const reader = response.body!.getReader();
    const initial = await reader.read();
    let body = new TextDecoder().decode(initial.value);
    expect(body).toContain('"object":"text_completion"');
    expect(body).toContain('"model":"local-instruct"');
    expect(body).toContain('"logprobs"');
    expect(body).not.toContain("[DONE]");

    finishRequest.resolve();
    while (!body.endsWith("data: [DONE]\n\n")) {
      const next = await reader.read();
      if (next.done) break;
      body += new TextDecoder().decode(next.value);
    }
    expect(body).toContain('"text":"hel"');
    expect(body).toContain('"index":1');
    expect(body).toContain('"finish_reason":"stop"');
    expect(body).toContain('"finish_reason":"length"');
    expect(body).toContain('"prompt_tokens":4');
    expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it("buffers native choices, concatenates logprobs, and prefers upstream usage", async () => {
    const events = [
      { choices: [{ text: "A", index: 0, logprobs: { tokens: ["A"], token_logprobs: [-0.5], top_logprobs: [{ A: -0.5 }], text_offset: [0] }, finish_reason: null }] },
      { choices: [{ text: "B", index: 0, logprobs: { tokens: ["B"], token_logprobs: [-0.3], top_logprobs: [{ B: -0.3 }], text_offset: [1] }, finish_reason: "stop" }] },
      { choices: [], usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5, native: true } },
      "[DONE]",
    ];
    const gateway: GatewayExecutor = {
      execute: async (_input, callbacks) => {
        await callbacks.onChunk(0, events.map((event) => `data: ${event === "[DONE]" ? event : JSON.stringify(event)}\n\n`).join(""));
        await callbacks.onEnd(gatewayEnd("request-buffered", { inputTokens: 99, outputTokens: 99, totalTokens: 198 }));
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "text", logprobs: 1 });
    const body = await response.json() as Record<string, any>;

    expect(response.status).toBe(200);
    expect(body).toMatchObject({ object: "text_completion", model: "local-instruct", usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5, native: true } });
    expect(body.choices).toEqual([{
      text: "AB",
      index: 0,
      logprobs: { tokens: ["A", "B"], token_logprobs: [-0.5, -0.3], top_logprobs: [{ A: -0.5 }, { B: -0.3 }], text_offset: [0, 1] },
      finish_reason: "stop",
    }]);
  });

  it("always requests provider usage but keeps streaming usage opt-in locally", async () => {
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        expect(input.payload).toMatchObject({ stream_options: { include_usage: true } });
        await callbacks.onChunk(0, [
          `data: ${JSON.stringify({ choices: [{ index: 0, text: "answer", finish_reason: "stop" }] })}\n\n`,
          `data: ${JSON.stringify({ choices: [], usage: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 } })}\n\n`,
          "data: [DONE]\n\n",
        ].join(""));
        await callbacks.onEnd(gatewayEnd(input.requestId));
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "x" });
    const body = await response.json() as Record<string, any>;

    expect(response.status).toBe(200);
    expect(body.usage).toEqual({ prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 });

    const streamed = await post(server.port, token, { model: "local-instruct", prompt: "x", stream: true });
    const streamBody = await streamed.text();
    expect(streamed.status).toBe(200);
    expect(streamBody).not.toContain('"usage"');
    expect(streamBody.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it.each([false, true])("accepts native usage:null chunks before final usage (stream=%s)", async (stream) => {
    const events = [
      { choices: [{ index: 0, text: "A", finish_reason: null }], usage: null },
      { choices: [{ index: 0, text: "B", finish_reason: "stop" }], usage: null },
      { choices: [], usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } },
      "[DONE]",
    ];
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        expect(input.payload).toMatchObject({ stream_options: { include_usage: true } });
        await callbacks.onChunk(0, events.map((event) => `data: ${event === "[DONE]" ? event : JSON.stringify(event)}\n\n`).join(""));
        await callbacks.onEnd(gatewayEnd(input.requestId));
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, {
      model: "local-instruct",
      prompt: "x",
      stream,
      ...(stream ? { stream_options: { include_usage: true } } : {}),
    });

    expect(response.status).toBe(200);
    if (stream) {
      const body = await response.text();
      expect(body).toContain('"text":"A"');
      expect(body).toContain('"text":"B"');
      expect(body).toContain('"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}');
      expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
    } else {
      const body = await response.json() as Record<string, any>;
      expect(body.choices[0].text).toBe("AB");
      expect(body.usage).toEqual({ prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 });
    }
  });

  it.each([
    { name: "a negative counter", usage: { prompt_tokens: -1, completion_tokens: 1, total_tokens: 0 } },
    { name: "a missing counter", usage: { prompt_tokens: 1, completion_tokens: 1 } },
  ])("rejects upstream usage with $name", async ({ usage }) => {
    const gateway: GatewayExecutor = {
      execute: async (_input, callbacks) => {
        await callbacks.onChunk(0, `data: ${JSON.stringify({ choices: [], usage })}\n\n`);
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "x" });
    const body = await response.text();

    expect(response.status).toBe(502);
    expect(body).toContain("invalid_provider_response");
    expect(body).not.toContain("prompt_tokens");
  });

  it.each([
    {
      name: "duplicate choice indices in one event",
      events: [{ choices: [
        { index: 0, text: "a", finish_reason: null },
        { index: 0, text: "b", finish_reason: "stop" },
      ] }],
    },
    {
      name: "choice data after a finish reason",
      events: [
        { choices: [{ index: 0, text: "a", finish_reason: "stop" }] },
        { choices: [{ index: 0, text: "b", finish_reason: null }] },
      ],
    },
  ])("rejects $name", async ({ events }) => {
    const gateway: GatewayExecutor = {
      execute: async (_input, callbacks) => {
        const upstream = events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("");
        await callbacks.onChunk(0, upstream);
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "x" });
    const body = await response.text();

    expect(response.status).toBe(502);
    expect(body).toContain("invalid_provider_response");
    expect(body).not.toContain('"text":"a"');
  });

  it.each([
    { name: "missing success sentinel", upstream: `data: ${JSON.stringify({ choices: [{ index: 0, text: "partial", finish_reason: "stop" }] })}\n\n` },
    { name: "missing finish reason", upstream: `data: ${JSON.stringify({ choices: [{ index: 0, text: "partial", finish_reason: null }] })}\n\ndata: [DONE]\n\n` },
  ])("does not return a successful buffered response on $name", async ({ upstream }) => {
    const gateway: GatewayExecutor = {
      execute: async (_input, callbacks) => {
        await callbacks.onChunk(0, upstream);
        await callbacks.onEnd(gatewayEnd("request-incomplete"));
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "text" });
    const body = await response.text();
    expect(response.status).toBe(502);
    expect(body).toContain("invalid_provider_response");
    expect(body).not.toContain("partial");
  });

  it("rejects invalid prompts, unsupported best_of, endpoint injection, and non-OpenAI protocols before dispatch", async () => {
    const execute = vi.fn(async () => undefined);
    const gateway: GatewayExecutor = { execute, close: () => undefined };
    const { server, token } = await createServer(gateway);
    for (const invalid of [
      { model: "local-instruct", prompt: ["one", 5] },
      { model: "local-instruct", prompt: "x", n: 9 },
      { model: "local-instruct", prompt: "x", best_of: 2 },
      { model: "local-instruct", prompt: "x", endpoint: "https://example.org" },
    ]) {
      expect((await post(server.port, token, invalid)).status).toBe(400);
    }
    expect((await post(server.port, token, { model: "local-anthropic", prompt: "x" })).status).toBe(400);
    expect(execute).not.toHaveBeenCalled();
  });

  it("uses Gateway usage when a successful stream requests usage and upstream omits it", async () => {
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        await callbacks.onChunk(0, `data: ${JSON.stringify({ choices: [{ index: 0, text: "ok", finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`);
        await callbacks.onEnd(gatewayEnd(input.requestId, { inputTokens: 2, outputTokens: 3, totalTokens: 5 }));
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "x", stream: true, stream_options: { include_usage: true } });
    const body = await response.text();
    expect(body).toContain('"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}');
    expect(body.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it("withholds finish reasons and DONE if Gateway reports an error after provider finish signals", async () => {
    const gateway: GatewayExecutor = {
      execute: async (input, callbacks) => {
        await callbacks.onChunk(0, `data: ${JSON.stringify({ choices: [{ index: 0, text: "partial", finish_reason: "stop" }] })}\n\n`);
        await callbacks.onError({
          event: "response.error",
          requestId: input.requestId,
          lastSeq: 0,
          code: "upstream_error",
          message: "The provider request failed.",
          upstreamStarted: true,
          retryable: false,
        });
      },
      close: () => undefined,
    };
    const { server, token } = await createServer(gateway);
    const response = await post(server.port, token, { model: "local-instruct", prompt: "x", stream: true });
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('"text":"partial"');
    expect(body).toContain('"code":"upstream_error"');
    expect(body).not.toContain('"finish_reason":"stop"');
    expect(body).not.toContain("[DONE]");
  });
});

async function createServer(
  gateway: GatewayExecutor,
  model: { id: string; provider: string; protocol: "openai" | "anthropic" } = { id: "local-instruct", provider: "openai", protocol: "openai" },
): Promise<{ server: Awaited<ReturnType<typeof startAdapter>>; token: string }> {
  const directory = await mkdtemp(path.join(tmpdir(), "adapter-legacy-completions-"));
  temporaryDirectories.push(directory);
  const store = new ConfigStore(path.join(directory, "state", "adapter.json"));
  const initial = createInitialConfig({
    identityUrl: "http://127.0.0.1:3000",
    gatewayUrl: "ws://127.0.0.1:8787/session",
    auth: { type: "public", clientId: "client_test", refreshToken: "refresh-token-test" },
  });
  const config = validateConfig({
    ...initial,
    models: [
      { ...model, credentialId: "credential_test" },
      { id: "local-anthropic", provider: "anthropic", protocol: "anthropic", credentialId: "credential_anthropic" },
    ],
    envelopes: [
      { v: 1, alg: "A256GCM", kid: "test-key", credentialId: "credential_test", userId: "user_test", projectId: "project_test", provider: model.provider, exp: Math.floor(Date.now() / 1000) + 3600, nonce: "AAAAAAAAAAAAAAAA", ciphertext: "AAAAAAAAAAAAAAAAAAAAAA" },
      { v: 1, alg: "A256GCM", kid: "test-key", credentialId: "credential_anthropic", userId: "user_test", projectId: "project_test", provider: "anthropic", exp: Math.floor(Date.now() / 1000) + 3600, nonce: "AAAAAAAAAAAAAAAA", ciphertext: "AAAAAAAAAAAAAAAAAAAAAA" },
    ],
  });
  await store.save(config);
  const server = await startAdapter({ configStore: store, portOverride: 0, gateway });
  runningServers.push(server);
  return { server, token: config.localBearerToken };
}

function completionsUrl(port: number): string {
  return `http://127.0.0.1:${port}/v1/completions`;
}

function post(port: number, token: string, body: unknown): Promise<Response> {
  return fetch(completionsUrl(port), {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function gatewayEnd(requestId: string, usage?: ResponseEndMessage["usage"]): ResponseEndMessage {
  return { event: "response.end", requestId, lastSeq: 0, ...(usage ? { usage } : {}) };
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
