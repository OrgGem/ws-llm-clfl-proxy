import WebSocket, { WebSocketServer } from "ws";
import { afterEach, describe, expect, it } from "vitest";
import { GatewayClient, GatewayOverloadedError, GatewayPayloadTooLargeError, type GatewayCallbacks, type GatewayRequestInput } from "./gateway.js";

const active: Array<{ gateway: GatewayClient; server: WebSocketServer }> = [];

afterEach(async () => {
  await Promise.all(active.splice(0).map(async ({ gateway, server }) => {
    gateway.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }));
});

describe("Gateway WebSocket adapter", () => {
  it("forwards only the fixed optional request API discriminator", async () => {
    const starts: Array<Record<string, unknown>> = [];
    const server = await createMockGateway((socket) => {
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as Record<string, unknown>;
        if (frame.event !== "request.start" || "op" in frame) return;
        starts.push(frame);
        socket.send(responseEnd(String(frame.requestId), -1));
      });
    });
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });

    await gateway.execute(requestInput(), callbacksWith());
    for (const api of ["chat.completions", "responses", "completions"] as const) {
      await gateway.execute(requestInput(api), callbacksWith());
    }

    expect(starts[0]).not.toHaveProperty("api");
    expect(starts.slice(1).map((frame) => frame.api)).toEqual(["chat.completions", "responses", "completions"]);
    expect(starts.every((frame) => !("url" in frame) && !("endpoint" in frame))).toBe(true);
  });

  it("ACKs only after the local writer drains, then accepts the terminal frame", async () => {
    let ackSeen = false;
    const ackWait = deferred<void>();
    const server = await createMockGateway((socket) => {
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event: string; op?: string; requestId?: string; ackSeq?: number };
        if (frame.event === "request.start" && !frame.op) {
          socket.send(responseChunk(frame.requestId as string));
        } else if (frame.event === "request.start" && frame.op === "ack") {
          ackSeen = frame.ackSeq === 0;
          ackWait.resolve();
          socket.send(responseEnd(frame.requestId as string, 0));
        }
      });
    });
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });
    const writer = deferred<void>();
    const chunkStarted = deferred<void>();
    const callbacks = callbacksWith({
      onChunk: async () => {
        chunkStarted.resolve();
        await writer.promise;
      },
    });
    const execution = gateway.execute(requestInput(), callbacks);
    await chunkStarted.promise;
    expect(ackSeen).toBe(false);
    writer.resolve();
    await ackWait.promise;
    await execution;
    expect(ackSeen).toBe(true);
  });

  it("does not report interruption after a queued successful terminal frame", async () => {
    const server = await createMockGateway((socket) => {
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event: string; op?: string; requestId?: string };
        if (frame.event === "request.start" && !frame.op) {
          const requestId = frame.requestId as string;
          socket.send(responseChunk(requestId));
          socket.send(responseEnd(requestId, 0));
          socket.close(1011, "test close during local drain");
        }
      });
    });
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });
    const writer = deferred<void>();
    const chunkStarted = deferred<void>();
    const seen: string[] = [];
    const callbacks = callbacksWith({
      onChunk: async () => {
        seen.push("chunk");
        chunkStarted.resolve();
        await writer.promise;
      },
      onEnd: async () => { seen.push("end"); },
      onInterrupted: async () => { seen.push("interrupted"); },
    });
    const execution = gateway.execute(requestInput(), callbacks);
    await chunkStarted.promise;
    writer.resolve();
    await execution;
    expect(seen).toEqual(["chunk", "end"]);
  });

  it("closes the session on a frame received after a terminal response", async () => {
    const clientClose = deferred<number>();
    const server = await createMockGateway((socket) => {
      socket.on("close", (code) => clientClose.resolve(code));
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event: string; op?: string; requestId?: string };
        if (frame.event !== "request.start" || frame.op) return;
        const requestId = frame.requestId as string;
        socket.send(responseEnd(requestId, -1));
        setTimeout(() => socket.send(responseChunk(requestId)), 25);
      });
    });
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });
    await gateway.execute(requestInput(), callbacksWith());
    expect(await clientClose.promise).toBe(1002);
  });

  it("sends request.cancel when the caller aborts", async () => {
    const cancelSeen = deferred<void>();
    const startSeen = deferred<void>();
    const server = await createMockGateway((socket) => {
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event: string; requestId?: string };
        if (frame.event === "request.start") startSeen.resolve();
        if (frame.event === "request.cancel") cancelSeen.resolve();
      });
    });
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });
    const controller = new AbortController();
    const execution = gateway.execute(requestInput(), callbacksWith(), controller.signal);
    await startSeen.promise;
    controller.abort();
    await cancelSeen.promise;
    expect(cancelSeen).toBeDefined();
    gateway.close();
    await execution;
  });

  it("rejects a request payload above the negotiated session limit before dispatch", async () => {
    let starts = 0;
    const server = await createMockGateway((socket) => {
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event: string; op?: string };
        if (frame.event === "request.start" && !frame.op) starts += 1;
      });
    }, 8, 1024);
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });

    const input = requestInput();
    input.payload = { messages: [{ role: "user", content: "x".repeat(1200) }] };
    await expect(gateway.execute(input, callbacksWith())).rejects.toBeInstanceOf(GatewayPayloadTooLargeError);
    expect(starts).toBe(0);
  });

  it("keeps ten-way load on one socket and respects a negotiated maxInFlight of one", async () => {
    const firstStartSeen = deferred<void>();
    const overloadSeen = deferred<void>();
    let starts = 0;
    let connections = 0;
    let overloads = 0;
    const server = await createMockGateway((socket) => {
      connections += 1;
      socket.on("message", (raw) => {
        const frame = JSON.parse(raw.toString()) as { event: string; op?: string };
        if (frame.event === "request.start" && !frame.op) {
          starts += 1;
          firstStartSeen.resolve();
        }
      });
    }, 1);
    const gateway = new GatewayClient(server.url, { getAccessToken: async () => "machine-access-token" });
    active.push({ gateway, server: server.wss });
    const requests = Array.from({ length: 10 }, (_, index) => {
      const input = requestInput();
      input.requestId = `${String(index).padStart(8, "0")}-0000-4000-8000-000000000000`;
      return gateway.execute(input, callbacksWith()).catch((error: unknown) => {
        if (error instanceof GatewayOverloadedError) {
          overloads += 1;
          overloadSeen.resolve();
        }
      });
    });

    await firstStartSeen.promise;
    await overloadSeen.promise;
    expect(connections).toBe(1);
    expect(starts).toBe(1);
    expect(overloads).toBe(9);
    gateway.close();
    await Promise.all(requests);
  });
});

async function createMockGateway(
  onConnection: (socket: WebSocket) => void,
  maxInFlight = 8,
  maxPayloadBytes = 1048576,
): Promise<{ wss: WebSocketServer; url: string }> {
  const wss = new WebSocketServer({
    port: 0,
    host: "127.0.0.1",
    handleProtocols: (protocols) => protocols.has("llm-proxy.v1") ? "llm-proxy.v1" : false,
  });
  await new Promise<void>((resolve) => wss.once("listening", resolve));
  wss.on("connection", (socket, request) => {
    expect(request.headers.authorization).toBe("Bearer machine-access-token");
    socket.send(JSON.stringify({
      event: "session.ready",
      protocol: 1,
      connectionId: "test-session",
      maxInFlight,
      maxPayloadBytes,
      maxSessionSeconds: 300,
      maxChunkBytes: 32768,
      ackWindow: 8,
      maxRequestFrameBytes: 1048576,
      maxResponseFrameBytes: 262144,
      tokenExpiresAt: Math.floor(Date.now() / 1000) + 300,
    }));
    onConnection(socket);
  });
  const address = wss.address();
  if (!address || typeof address === "string") throw new Error("Mock WebSocket server failed to bind");
  return { wss, url: `ws://127.0.0.1:${address.port}/session` };
}

function responseChunk(requestId: string): string {
  return JSON.stringify({
    event: "response.chunk",
    requestId,
    seq: 0,
    data: 'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}\n\n',
  });
}

function responseEnd(requestId: string, lastSeq: number): string {
  return JSON.stringify({ event: "response.end", requestId, lastSeq });
}

function requestInput(api?: GatewayRequestInput["api"]): GatewayRequestInput {
  return {
    requestId: crypto.randomUUID(),
    ...(api === undefined ? {} : { api }),
    provider: "openai",
    model: "test-model",
    envelope: {
      v: 1,
      alg: "A256GCM",
      kid: "test-key",
      credentialId: "cred_test",
      userId: "user_test",
      projectId: "project_test",
      provider: "openai",
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
    },
    payload: { messages: [{ role: "user", content: "hello" }] },
  };
}

function callbacksWith(overrides: Partial<GatewayCallbacks> = {}): GatewayCallbacks {
  return {
    onChunk: async () => undefined,
    onEnd: async () => undefined,
    onError: async () => undefined,
    onInterrupted: async () => undefined,
    onLocalFailure: async () => undefined,
    ...overrides,
  };
}

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
