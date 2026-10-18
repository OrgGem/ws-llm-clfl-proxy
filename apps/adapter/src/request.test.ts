import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigStore, createInitialConfig, validateConfig } from "./config.js";
import { readLimitedStream, runRequestCommand, writeWithBackpressure } from "./request.js";
import { startAdapter } from "./server.js";
import type { GatewayExecutor } from "./server.js";
import type { GatewayCallbacks, GatewayRequestInput } from "./gateway.js";
import type { TokenProvider } from "./auth.js";

const directories: string[] = [];
const running: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(running.splice(0).map((server) => server.close()));
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("agent request command", () => {
  it("injects the only alias, streams structured tool calls unchanged, and never executes them", async () => {
    const store = await createStore();
    let dispatched: GatewayRequestInput | undefined;
    let starts = 0;
    const providerStream = [
      'data: {"id":"upstream","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_lookup","type":"function","function":{"name":"lookup","arguments":"{\\"city\\":"}}]},"finish_reason":null}]}\n\n',
      'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"Paris\\"}"}}]},"finish_reason":null}]}\n\n',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
      "data: [DONE]\n\n",
    ].join("");
    const gateway = gatewayExecutor(async (input, callbacks) => {
      starts += 1;
      dispatched = input;
      await callbacks.onChunk(0, providerStream);
      await callbacks.onEnd({ event: "response.end", requestId: input.requestId, lastSeq: 0 });
    });
    const output = collectingWritable();

    await runRequestCommand([
      "--api", "chat.completions",
    ], store, {
      stdin: Readable.from([JSON.stringify({
        messages: [{ role: "user", content: "Find Paris" }],
        tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }],
        stream: true,
      })]),
      stdout: output,
      startAdapterImpl: (options) => startAdapter({
        ...options,
        gateway,
        tokenProvider: { getAccessToken: async () => "test-token" } as unknown as TokenProvider,
      }),
    });

    const text = outputText(output);
    expect(dispatched).toMatchObject({
      provider: "openai",
      model: "agent-alias",
      payload: { messages: [{ role: "user", content: "Find Paris" }], tools: [{ type: "function", function: { name: "lookup" } }] },
    });
    expect(starts).toBe(1);
    expect(text).toContain('"tool_calls"');
    expect(text).toContain('"name":"lookup"');
    const streamedToolArguments = text.split("\n\n")
      .filter((event) => event.startsWith("data: {") )
      .map((event) => JSON.parse(event.slice(6)) as ChatChunk)
      .flatMap((chunk) => chunk.choices.flatMap((choice) => choice.delta?.tool_calls?.map((call) => call.function?.arguments ?? "") ?? []))
      .join("");
    expect(streamedToolArguments).toBe('{"city":"Paris"}');
    expect(text.endsWith("data: [DONE]\n\n")).toBe(true);
  });

  it("returns nonzero for an SSE error and does not mistake provider DONE for success after Gateway interruption", async () => {
    const store = await createStore();
    const output = collectingWritable();
    const gateway = gatewayExecutor(async (_input, callbacks) => {
      await callbacks.onChunk(0, 'data: {"choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}\n\ndata: [DONE]\n\n');
      await callbacks.onInterrupted("Gateway disconnected");
    });
    await expect(runRequestCommand(["--api", "chat.completions"], store, {
      stdin: Readable.from([JSON.stringify({ model: "agent-alias", messages: [{ role: "user", content: "hello" }], stream: true })]),
      stdout: output,
      startAdapterImpl: (options) => startAdapter({
        ...options,
        gateway,
        tokenProvider: { getAccessToken: async () => "test-token" } as unknown as TokenProvider,
      }),
    })).rejects.toThrow("API stream reported an error");
    expect(outputText(output)).not.toContain("[DONE]");
  });

  it("surfaces incomplete buffered Responses as nonzero after writing the requested JSON", async () => {
    const store = await createStore();
    const output = collectingWritable();
    let closed = false;
    await expect(runRequestCommand(["--api", "responses"], store, {
      stdin: Readable.from([JSON.stringify({ input: "hello" })]),
      stdout: output,
      startAdapterImpl: async () => ({ port: 1234, close: async () => { closed = true; } }),
      fetchImpl: async () => new Response(JSON.stringify({ id: "resp_test", status: "incomplete", output: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    })).rejects.toThrow("API returned an incomplete response");
    expect(JSON.parse(outputText(output))).toMatchObject({ id: "resp_test", status: "incomplete" });
    expect(closed).toBe(true);
  });

  it("does not print successful JSON when a local API response contains an error", async () => {
    const store = await createStore();
    const output = collectingWritable();
    await expect(runRequestCommand(["--api", "responses"], store, {
      stdin: Readable.from([JSON.stringify({ model: "agent-alias", input: "hello" })]),
      stdout: output,
      startAdapterImpl: async () => ({ port: 1234, close: async () => undefined }),
      fetchImpl: async () => new Response(JSON.stringify({ error: { message: "secret prompt sentinel" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    })).rejects.toThrow("API returned an error response");
    expect(outputText(output)).toBe("");
  });

  it("awaits stdout write callbacks and maps asynchronous EPIPE to a fixed error", async () => {
    const store = await createStore();
    const output = new Writable({
      write(_chunk, _encoding, callback) {
        setImmediate(() => callback(Object.assign(new Error("private output detail"), { code: "EPIPE" })));
      },
    });
    await expect(runRequestCommand(["--api", "responses"], store, {
      stdin: Readable.from([JSON.stringify({ model: "agent-alias", input: "hello" })]),
      stdout: output,
      startAdapterImpl: async () => ({ port: 1234, close: async () => undefined }),
      fetchImpl: async () => new Response(JSON.stringify({ id: "resp_test", status: "completed", output: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    })).rejects.toThrow("Output stream failed");
  });

  it("keeps a safe error listener until a pending write reports EPIPE after cancellation", async () => {
    let finishWrite!: (error?: Error | null) => void;
    const output = new Writable({
      write(_chunk, _encoding, callback) { finishWrite = callback; },
    });
    const controller = new AbortController();
    const pending = writeWithBackpressure(output, Buffer.from("partial"), controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow("Request cancelled");
    finishWrite(Object.assign(new Error("private delayed pipe detail"), { code: "EPIPE" }));
    await new Promise((resolve) => setImmediate(resolve));
    expect(output.listenerCount("error")).toBe(0);
  });

  it("bounds stdin before parsing or dispatch", async () => {
    const tooLarge = Readable.from([Buffer.alloc(1_048_577, 0x20)]);
    await expect(readLimitedStream(tooLarge, 1_048_576)).rejects.toThrow("1 MiB limit");
  });
});

async function createStore(): Promise<ConfigStore> {
  const directory = await mkdtemp(path.join(tmpdir(), "adapter-request-"));
  directories.push(directory);
  const store = new ConfigStore(path.join(directory, "adapter.json"));
  const base = createInitialConfig({
    identityUrl: "https://identity.example.test",
    gatewayUrl: "wss://gateway.example.test/v1/socket",
    auth: { type: "confidential", clientId: "client_test", clientSecret: "client_secret_test" },
  });
  const envelope = {
    v: 1,
    alg: "A256GCM",
    kid: "key_test",
    credentialId: "credential_test",
    userId: "user_test",
    projectId: "project_test",
    provider: "openai",
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: "AAAAAAAAAAAAAAAA",
    ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
  };
  await store.save(validateConfig({
    ...base,
    models: [{ id: "agent-alias", provider: "openai", protocol: "openai", credentialId: "credential_test" }],
    envelopes: [envelope],
  }));
  return store;
}

function gatewayExecutor(execute: (input: GatewayRequestInput, callbacks: GatewayCallbacks) => Promise<void>): GatewayExecutor {
  return {
    execute,
    close: () => undefined,
  };
}

function collectingWritable(): Writable {
  const chunks: Buffer[] = [];
  const writable = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  }) as Writable & { chunks: Buffer[] };
  writable.chunks = chunks;
  return writable;
}

function outputText(output: Writable & { chunks?: Buffer[] }): string {
  return (output.chunks ?? []).map((chunk) => chunk.toString("utf8")).join("");
}

interface ChatChunk {
  choices: Array<{
    delta?: {
      tool_calls?: Array<{ function?: { arguments?: string } }>;
    };
  }>;
}
