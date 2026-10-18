import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import WebSocket, { WebSocketServer } from "ws";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigStore, createInitialConfig, validateConfig } from "./config.js";
import { GatewayClient } from "./gateway.js";
import { startAdapter, type RunningAdapter } from "./server.js";

const temporaryDirectories: string[] = [];
const runningAdapters: RunningAdapter[] = [];
const mockGateways: WebSocketServer[] = [];

afterEach(async () => {
  await Promise.all(runningAdapters.splice(0).map((adapter) => adapter.close()));
  await Promise.all(mockGateways.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("HTTP to Gateway generation wire", () => {
  it("forwards Responses over a real GatewayClient and preserves fragmented typed SSE through response.end", async () => {
    const gatewayWire = await createMockGateway();
    const { adapter, token } = await createAdapter(gatewayWire.url);
    let responseStart!: Record<string, unknown>;
    const allProviderEvents = [
      providerEvent("response.created", {
        type: "response.created",
        response: { id: "resp_wire", object: "response", status: "in_progress", model: "wire-model", output: [], usage: null },
      }),
      providerEvent("response.output_item.added", {
        type: "response.output_item.added",
        output_index: 0,
        item: { id: "reason_wire", type: "reasoning", status: "in_progress", summary: [] },
      }),
      providerEvent("response.reasoning_summary_text.delta", {
        type: "response.reasoning_summary_text.delta", item_id: "reason_wire", output_index: 0, summary_index: 0, delta: "Checking the request.",
      }),
      providerEvent("response.output_item.added", {
        type: "response.output_item.added",
        output_index: 1,
        item: { id: "msg_wire", type: "message", status: "in_progress", role: "assistant", content: [] },
      }),
      providerEvent("response.content_part.added", {
        type: "response.content_part.added", item_id: "msg_wire", output_index: 1, content_index: 0,
        part: { type: "output_text", text: "", annotations: [] },
      }),
      providerEvent("response.output_text.delta", {
        type: "response.output_text.delta", item_id: "msg_wire", output_index: 1, content_index: 0, delta: "The answer is 42.",
      }),
      providerEvent("response.output_item.added", {
        type: "response.output_item.added",
        output_index: 2,
        item: { id: "fc_wire", type: "function_call", status: "in_progress", call_id: "call_wire", name: "lookup", arguments: "" },
      }),
      providerEvent("response.function_call_arguments.delta", {
        type: "response.function_call_arguments.delta", item_id: "fc_wire", output_index: 2, delta: '{"city":',
      }),
      providerEvent("response.function_call_arguments.delta", {
        type: "response.function_call_arguments.delta", item_id: "fc_wire", output_index: 2, delta: '"Paris"}',
      }),
      providerEvent("response.completed", {
        type: "response.completed",
        response: {
          id: "resp_wire",
          object: "response",
          status: "completed",
          model: "wire-model",
          output: [
            { id: "reason_wire", type: "reasoning", summary: [{ type: "summary_text", text: "Checking the request." }] },
            { id: "msg_wire", type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "The answer is 42.", annotations: [] }] },
            { id: "fc_wire", type: "function_call", status: "completed", call_id: "call_wire", name: "lookup", arguments: '{"city":"Paris"}' },
          ],
          usage: {
            input_tokens: 11,
            output_tokens: 8,
            total_tokens: 19,
            input_tokens_details: { cached_tokens: 2 },
            output_tokens_details: { reasoning_tokens: 3 },
          },
        },
      }),
    ].join("");

    gatewayWire.onStart = async (socket, frame) => {
      responseStart = frame;
      const split = Math.floor(allProviderEvents.length / 2);
      await gatewayWire.sendChunk(socket, frame.requestId, 0, allProviderEvents.slice(0, split));
      await gatewayWire.sendChunk(socket, frame.requestId, 1, allProviderEvents.slice(split));
      await gatewayWire.sendEnd(socket, frame.requestId, 1);
    };

    const response = await fetch(`http://127.0.0.1:${adapter.port}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        model: "wire-model",
        input: [{ role: "user", content: [{ type: "input_text", text: "What is the answer?" }] }],
        tools: [{ type: "function", name: "lookup", parameters: { type: "object", properties: { city: { type: "string" } } } }],
        reasoning: { effort: "low" },
        store: false,
        stream: true,
      }),
    });
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(responseStart).toMatchObject({
      event: "request.start",
      api: "responses",
      provider: "openai",
      model: "wire-model",
      payload: {
        input: [{ role: "user", content: [{ type: "input_text", text: "What is the answer?" }] }],
        store: false,
      },
    });
    expect(gatewayWire.acknowledged).toEqual([0, 1]);
    expect(body).toContain("event: response.reasoning_summary_text.delta");
    expect(body).toContain("Checking the request.");
    expect(body).toContain("event: response.output_text.delta");
    expect(body).toContain("The answer is 42.");
    expect(body).toContain("event: response.function_call_arguments.delta");
    expect(body).toContain('delta":"{\\"city\\":');
    expect(body).toContain('delta":"\\"Paris\\"}');
    expect(body).toContain('arguments":"{\\"city\\":\\"Paris\\"}"');
    expect(body).toContain('"input_tokens":11');
    expect(body).toContain('"reasoning_tokens":3');
    expect(body).toContain("event: response.completed");
    expect(body).not.toContain("[DONE]");
    expect(body).toContain('"type":"response.completed"');
  });

  it("does not emit legacy [DONE] until the Gateway sends response.end", async () => {
    const gatewayWire = await createMockGateway();
    const { adapter, token } = await createAdapter(gatewayWire.url);
    const providerFinished = deferred<void>();
    const allowResponseEnd = deferred<void>();
    let requestId = "";
    gatewayWire.onStart = async (socket, frame) => {
      requestId = frame.requestId;
      await gatewayWire.sendChunk(socket, frame.requestId, 0,
        'data: {"id":"cmpl_wire","object":"text_completion","choices":[{"index":0,"text":"Hello","finish_reason":null}]}\n\n');
      await gatewayWire.sendChunk(socket, frame.requestId, 1,
        'data: {"choices":[{"index":0,"text":"","finish_reason":"stop"}]}\n\n');
      await gatewayWire.sendChunk(socket, frame.requestId, 2, "data: [DONE]\n\n");
      providerFinished.resolve();
      await allowResponseEnd.promise;
      await gatewayWire.sendEnd(socket, frame.requestId, 2);
    };

    const response = await fetch(`http://127.0.0.1:${adapter.port}/v1/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "wire-model", prompt: "Say hello", stream: true }),
    });
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    const outputBeforeEnd = deferred<string>();
    const readBeforeEnd = (async () => {
      let value = "";
      while (!value.includes("Hello")) {
        const next = await reader.read();
        if (next.done) break;
        value += decoder.decode(next.value, { stream: true });
      }
      outputBeforeEnd.resolve(value);
      return value;
    })();
    await providerFinished.promise;
    const beforeEnd = await outputBeforeEnd.promise;
    const maybeEarlyTerminal = await readWithTimeout(reader, 40);
    let pendingTerminalRead: Promise<ReadableStreamReadResult<Uint8Array>> | undefined;
    let earlyOutput = "";
    if (maybeEarlyTerminal.timedOut) {
      pendingTerminalRead = maybeEarlyTerminal.pending;
    } else if (!maybeEarlyTerminal.value.done) {
      earlyOutput = decoder.decode(maybeEarlyTerminal.value.value, { stream: true });
    }
    expect(response.status).toBe(200);
    expect(requestId).toBeTruthy();
    expect(gatewayWire.starts[0]).toMatchObject({ event: "request.start", api: "completions" });
    expect(gatewayWire.acknowledged).toEqual([0, 1, 2]);
    expect(beforeEnd).toContain("Hello");
    expect(beforeEnd + earlyOutput).not.toContain("[DONE]");

    allowResponseEnd.resolve();
    await readBeforeEnd;
    let rest = "";
    let firstPostEnd = pendingTerminalRead ? await pendingTerminalRead : undefined;
    while (true) {
      const next = firstPostEnd ?? await reader.read();
      firstPostEnd = undefined;
      if (next.done) break;
      rest += decoder.decode(next.value, { stream: true });
    }
    const completeBody = beforeEnd + earlyOutput + rest;
    expect(completeBody.endsWith("data: [DONE]\n\n")).toBe(true);
    expect(completeBody.indexOf("[DONE]")).toBeGreaterThan(completeBody.indexOf('"finish_reason":"stop"'));
  });

  it("cancels the active WebSocket request when the HTTP client disconnects without retrying", async () => {
    const gatewayWire = await createMockGateway();
    const { adapter, token } = await createAdapter(gatewayWire.url);
    const chunkAcknowledged = deferred<void>();
    gatewayWire.onStart = async (socket, frame) => {
      await gatewayWire.sendChunk(socket, frame.requestId, 0, providerEvent("response.created", {
        type: "response.created",
        response: { id: "resp_cancel", object: "response", status: "in_progress", model: "wire-model", output: [], usage: null },
      }));
      await gatewayWire.sendChunk(socket, frame.requestId, 1,
        providerEvent("response.output_text.delta", {
          type: "response.output_text.delta", item_id: "msg_cancel", output_index: 0, content_index: 0, delta: "partial output",
        }));
      chunkAcknowledged.resolve();
      await gatewayWire.cancelled;
    };

    const controller = new AbortController();
    const response = await fetch(`http://127.0.0.1:${adapter.port}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "wire-model", input: "Generate", stream: true }),
      signal: controller.signal,
    });
    const reader = response.body!.getReader();
    await chunkAcknowledged.promise;
    const decoder = new TextDecoder();
    let partial = "";
    while (!partial.includes("partial output")) {
      const next = await reader.read();
      if (next.done) break;
      partial += decoder.decode(next.value, { stream: true });
    }
    expect(partial).toContain("partial output");

    controller.abort();
    await gatewayWire.cancelled;
    expect(gatewayWire.cancellations).toHaveLength(1);
    expect(gatewayWire.starts).toHaveLength(1);
    expect(gatewayWire.connections).toBe(1);
    expect(gatewayWire.acknowledged).toEqual([0, 1]);
    await reader.cancel().catch(() => undefined);
  });
});

interface RequestStartFrame {
  event: "request.start";
  requestId: string;
  api?: "chat.completions" | "responses" | "completions";
  [key: string]: unknown;
}

interface MockGateway {
  url: string;
  starts: RequestStartFrame[];
  connections: number;
  acknowledged: number[];
  cancellations: Array<Record<string, unknown>>;
  cancelled: Promise<void>;
  onStart: ((socket: WebSocket, frame: RequestStartFrame) => Promise<void>) | undefined;
  sendChunk(socket: WebSocket, requestId: string, seq: number, data: string): Promise<void>;
  sendEnd(socket: WebSocket, requestId: string, lastSeq: number): Promise<void>;
}

async function createMockGateway(): Promise<MockGateway> {
  let onStart: MockGateway["onStart"];
  const starts: RequestStartFrame[] = [];
  let connections = 0;
  const acknowledged: number[] = [];
  const cancellations: Array<Record<string, unknown>> = [];
  const cancelWaiters: Array<() => void> = [];
  const cancelled = new Promise<void>((resolve) => { cancelWaiters.push(resolve); });
  const ackWaiters = new Map<string, () => void>();
  const wss = new WebSocketServer({
    port: 0,
    host: "127.0.0.1",
    handleProtocols: (protocols) => protocols.has("llm-proxy.v1") ? "llm-proxy.v1" : false,
  });
  mockGateways.push(wss);
  await new Promise<void>((resolve) => wss.once("listening", resolve));
  wss.on("connection", (socket, request) => {
    connections += 1;
    expect(request.headers.authorization).toBe("Bearer wire-test-access-token");
    socket.send(JSON.stringify({
      event: "session.ready",
      protocol: 1,
      connectionId: "adapter-generation-wire",
      maxInFlight: 1,
      maxPayloadBytes: 1_048_576,
      maxSessionSeconds: 300,
      maxChunkBytes: 32_768,
      ackWindow: 8,
      maxRequestFrameBytes: 1_048_576,
      maxResponseFrameBytes: 262_144,
      tokenExpiresAt: Math.floor(Date.now() / 1000) + 300,
    }));
    socket.on("message", (raw) => {
      const frame = JSON.parse(raw.toString()) as Record<string, unknown>;
      if (frame.event === "request.start" && frame.op === "ack") {
        const seq = Number(frame.ackSeq);
        acknowledged.push(seq);
        ackWaiters.get(`${String(frame.requestId)}:${seq}`)?.();
      } else if (frame.event === "request.start" && frame.op === undefined) {
        const start = frame as unknown as RequestStartFrame;
        starts.push(start);
        void onStart?.(socket, start);
      } else if (frame.event === "request.cancel") {
        cancellations.push(frame);
        cancelWaiters.splice(0).forEach((resolve) => resolve());
      }
    });
  });
  const address = wss.address();
  if (!address || typeof address === "string") throw new Error("Local mock Gateway failed to bind");

  return {
    url: `ws://127.0.0.1:${address.port}/v1/socket`,
    starts,
    get connections() { return connections; },
    acknowledged,
    cancellations,
    cancelled,
    get onStart() { return onStart; },
    set onStart(handler) { onStart = handler; },
    async sendChunk(socket, requestId, seq, data) {
      const key = `${requestId}:${seq}`;
      const ack = new Promise<void>((resolve) => ackWaiters.set(key, resolve));
      socket.send(JSON.stringify({ event: "response.chunk", requestId, seq, data }));
      await ack;
      ackWaiters.delete(key);
    },
    async sendEnd(socket, requestId, lastSeq) {
      socket.send(JSON.stringify({ event: "response.end", requestId, lastSeq }));
    },
  };
}

async function createAdapter(gatewayUrl: string): Promise<{ adapter: RunningAdapter; token: string }> {
  const directory = await mkdtemp(path.join(tmpdir(), "adapter-generation-wire-"));
  temporaryDirectories.push(directory);
  const store = new ConfigStore(path.join(directory, "state", "adapter.json"));
  const initial = createInitialConfig({
    identityUrl: "http://127.0.0.1:3000",
    gatewayUrl,
    auth: { type: "confidential", clientId: "wire-test-client", clientSecret: "wire-test-secret" },
  });
  const config = validateConfig({
    ...initial,
    models: [{ id: "wire-model", provider: "openai", protocol: "openai", credentialId: "credential_wire" }],
    envelopes: [{
      v: 1,
      alg: "A256GCM",
      kid: "wire-key",
      credentialId: "credential_wire",
      userId: "wire-user",
      projectId: "wire-project",
      provider: "openai",
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
    }],
  });
  await store.save(config);
  const gateway = new GatewayClient(gatewayUrl, { getAccessToken: async () => "wire-test-access-token" }, 1);
  const adapter = await startAdapter({ configStore: store, portOverride: 0, gateway, maxGatewaySessions: 1 });
  runningAdapters.push(adapter);
  return { adapter, token: config.localBearerToken };
}

function providerEvent(event: string, body: Record<string, unknown>): string {
  return `event: ${event}\ndata: ${JSON.stringify(body)}\n\n`;
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function readWithTimeout(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number,
): Promise<{ timedOut: true; pending: Promise<ReadableStreamReadResult<Uint8Array>> } | { timedOut: false; value: ReadableStreamReadResult<Uint8Array> }> {
  const pending = reader.read();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<{ timedOut: true; pending: Promise<ReadableStreamReadResult<Uint8Array>> }>((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true, pending }), timeoutMs);
  });
  const result = await Promise.race([
    pending.then((value) => ({ timedOut: false as const, value })),
    timeout,
  ]);
  if (timer) clearTimeout(timer);
  return result;
}
