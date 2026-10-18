import { build } from "esbuild";
import { createServer, type Server as HttpServer } from "node:http";
import { mkdtemp, chmod, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import WebSocket, { WebSocketServer } from "ws";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

const adapterRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testDirectories: string[] = [];
const mockServers: Array<{ close(): Promise<void> }> = [];
let executable: string;

beforeAll(async () => {
  const directory = await privateTempDirectory("adapter-cli-bin-");
  executable = path.join(directory, "bin.mjs");
  await build({
    entryPoints: [path.join(adapterRoot, "src/bin.ts")],
    outfile: executable,
    bundle: true,
    platform: "node",
    target: "node22",
    format: "esm",
    external: ["ws", "https-proxy-agent", "proxy-from-env", "undici", "jose"],
    legalComments: "none",
  });
});

afterEach(async () => {
  await Promise.all(mockServers.splice(0).map((server) => server.close()));
});

afterAll(async () => {
  await Promise.all(testDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("packaged agent CLI process", () => {
  it("loads protected env config, honors inherited values, dispatches through Identity and WSS, and streams tool calls", async () => {
    const directory = await privateTempDirectory("adapter-cli-success-");
    const identity = await startIdentityMock();
    const gateway = await startGatewayMock("success");
    const env = await writeEnvironment(directory, identity.url, gateway.url);
    const child = spawnCli(["request", "--api", "chat.completions", "--config-env", env.envPath], env.childEnv);
    child.stdin.end(JSON.stringify({
      messages: [{ role: "user", content: "Find Paris" }],
      tools: [{ type: "function", function: { name: "lookup", parameters: { type: "object" } } }],
      stream: true,
    }));

    const result = await waitChild(child);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain('"tool_calls"');
    expect(result.stdout).toContain('"name":"lookup"');
    expect(result.stdout.endsWith("data: [DONE]\n\n")).toBe(true);
    expect(identity.authorization).toBe(`Basic ${Buffer.from("runtime-client:runtime-secret").toString("base64")}`);
    expect(gateway.accessAuthorization).toBe("Bearer cli-test-access-token");
    expect(gateway.start).toMatchObject({
      event: "request.start",
      provider: "openai",
      model: "agent-alias",
      payload: { messages: [{ role: "user", content: "Find Paris" }] },
    });
    expect(await fileExists(path.join(directory, "adapter.json"))).toBe(false);
  });

  it("exits nonzero and prints no body for Gateway API errors", async () => {
    const directory = await privateTempDirectory("adapter-cli-error-");
    const identity = await startIdentityMock();
    const gateway = await startGatewayMock("error");
    const env = await writeEnvironment(directory, identity.url, gateway.url);
    const child = spawnCli(["--config-env", env.envPath, "request", "--api", "chat.completions"], env.childEnv);
    child.stdin.end(JSON.stringify({ model: "agent-alias", messages: [{ role: "user", content: "hello" }], stream: true }));
    const result = await waitChild(child);

    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("HTTP status 502");
    expect(result.stderr).not.toContain("sentinel-secret");
  });

  it("reports SIGINT cancellation as failure and closes its Gateway session", async () => {
    const directory = await privateTempDirectory("adapter-cli-cancel-");
    const identity = await startIdentityMock();
    const gateway = await startGatewayMock("hold");
    const env = await writeEnvironment(directory, identity.url, gateway.url);
    const child = spawnCli(["request", "--api", "chat.completions", "--input", "-", "--config-env", env.envPath], env.childEnv);
    child.stdin.end(JSON.stringify({ model: "agent-alias", messages: [{ role: "user", content: "hello" }], stream: true }));
    await waitForOutput(child, "partial-before-cancel", 10_000);
    child.kill("SIGINT");
    const result = await waitChild(child);

    expect(result.code).not.toBe(0);
    expect(result.stdout).not.toContain("[DONE]");
    expect(result.stderr).toContain("Request cancelled.");
    await expect(gateway.peerClosed).resolves.toBe(true);
  });

  it("environment files with broad permissions fail before config values are loaded", async () => {
    if (process.platform === "win32") return;
    const directory = await privateTempDirectory("adapter-cli-mode-");
    const identity = await startIdentityMock();
    const gateway = await startGatewayMock("success");
    const env = await writeEnvironment(directory, identity.url, gateway.url);
    await chmod(env.envPath, 0o644);
    const child = spawnCli(["--config-env", env.envPath, "request", "--api", "chat.completions"], env.childEnv);
    child.stdin.end(JSON.stringify({ model: "agent-alias", messages: [{ role: "user", content: "hello" }] }));
    const result = await waitChild(child);
    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("0600 permissions");
  });
});

type Scenario = "success" | "error" | "hold";

async function startIdentityMock(): Promise<{ url: string; authorization: string | undefined; close(): Promise<void> }> {
  let authorization: string | undefined;
  const server = createServer((request, response) => {
    if (request.method !== "POST" || request.url !== "/oauth/token") {
      response.writeHead(404).end();
      return;
    }
    authorization = request.headers.authorization;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ access_token: "cli-test-access-token", token_type: "Bearer", expires_in: 300 }));
  });
  const port = await listen(server);
  const tracked = {
    get authorization() { return authorization; },
    url: `http://127.0.0.1:${port}`,
    close: () => closeHttp(server),
  };
  mockServers.push(tracked);
  return tracked;
}

async function startGatewayMock(scenario: Scenario): Promise<{
  url: string;
  accessAuthorization: string | undefined;
  start: Record<string, unknown> | undefined;
  cancelled: Promise<boolean>;
  peerClosed: Promise<boolean>;
  close(): Promise<void>;
}> {
  let accessAuthorization: string | undefined;
  let start: Record<string, unknown> | undefined;
  let resolveCancelled!: (value: boolean) => void;
  let resolvePeerClosed!: (value: boolean) => void;
  const cancelled = new Promise<boolean>((resolve) => { resolveCancelled = resolve; });
  const peerClosed = new Promise<boolean>((resolve) => { resolvePeerClosed = resolve; });
  const http = createServer();
  const sockets = new WebSocketServer({ noServer: true });
  http.on("upgrade", (request, socket, head) => {
    if (request.url !== "/v1/socket") {
      socket.destroy();
      return;
    }
    accessAuthorization = request.headers.authorization;
    sockets.handleUpgrade(request, socket, head, (webSocket) => sockets.emit("connection", webSocket, request));
  });
  sockets.on("connection", (socket) => {
    socket.once("close", () => resolvePeerClosed(true));
    socket.send(JSON.stringify({
      event: "session.ready",
      protocol: 1,
      connectionId: "connection_cli_test",
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
      let frame: Record<string, unknown>;
      try { frame = JSON.parse(raw.toString()) as Record<string, unknown>; } catch { return; }
      if (frame.event === "request.cancel") {
        resolveCancelled(true);
        return;
      }
      if (frame.event !== "request.start" || frame.op === "ack") return;
      start = frame;
      const requestId = frame.requestId;
      if (scenario === "error") {
        socket.send(JSON.stringify({
          event: "response.error", requestId, lastSeq: -1, code: "upstream_error",
          message: "A sentinel-secret provider failure.", upstreamStarted: true, retryable: false,
        }));
        return;
      }
      const partial = 'data: {"id":"upstream","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"partial-before-cancel"},"finish_reason":null}]}\n\n';
      if (scenario === "hold") {
        socket.send(JSON.stringify({ event: "response.chunk", requestId, seq: 0, data: partial }));
        return;
      }
      const toolStream = [
        'data: {"id":"upstream","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_cli","type":"function","function":{"name":"lookup","arguments":"{\\"city\\":"}}]},"finish_reason":null}]}\n\n',
        'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"Paris\\"}"}}]},"finish_reason":null}]}\n\n',
        'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
        "data: [DONE]\n\n",
      ].join("");
      socket.send(JSON.stringify({ event: "response.chunk", requestId, seq: 0, data: toolStream }));
      socket.send(JSON.stringify({ event: "response.end", requestId, lastSeq: 0 }));
    });
  });
  const port = await listen(http);
  const tracked = {
    get accessAuthorization() { return accessAuthorization; },
    get start() { return start; },
    url: `ws://127.0.0.1:${port}/v1/socket`,
    cancelled,
    peerClosed,
    close: async () => {
      await new Promise<void>((resolve) => sockets.close(() => resolve()));
      await closeHttp(http);
    },
  };
  mockServers.push(tracked);
  return tracked;
}

async function writeEnvironment(directory: string, identityUrl: string, gatewayUrl: string): Promise<{ envPath: string; childEnv: NodeJS.ProcessEnv }> {
  const envelopePath = path.join(directory, "envelope.json");
  const envelope = {
    v: 1,
    alg: "A256GCM",
    kid: "key_cli_test",
    credentialId: "credential_cli_test",
    userId: "user_cli_test",
    projectId: "project_cli_test",
    provider: "openai",
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: "AAAAAAAAAAAAAAAA",
    ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
  };
  await writeFile(envelopePath, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
  const envPath = path.join(directory, "runtime.env");
  const settings: Record<string, string> = {
    WS_PROXY_CONFIG_SOURCE: "env",
    WS_PROXY_IDENTITY_URL: identityUrl,
    WS_PROXY_GATEWAY_URL: gatewayUrl,
    WS_PROXY_CLIENT_ID: "file-client-id-must-lose",
    WS_PROXY_CLIENT_SECRET: "runtime-secret",
    WS_PROXY_LOCAL_BEARER_TOKEN: "L".repeat(43),
    WS_PROXY_ENVELOPE_FILE: envelopePath,
    WS_PROXY_MODEL_ALIAS: "agent-alias",
    WS_PROXY_PROVIDER: "openai",
    WS_PROXY_PROTOCOL: "openai",
  };
  await writeFile(envPath, Object.entries(settings).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join("\n") + "\n", { mode: 0o600 });
  const childEnv: NodeJS.ProcessEnv = { ...process.env };
  for (const key of [
    "WS_PROXY_CONFIG_SOURCE", "WS_PROXY_IDENTITY_URL", "WS_PROXY_GATEWAY_URL", "WS_PROXY_CLIENT_ID",
    "WS_PROXY_CLIENT_SECRET", "WS_PROXY_LOCAL_BEARER_TOKEN", "WS_PROXY_ENVELOPE_FILE", "WS_PROXY_MODEL_ALIAS",
    "WS_PROXY_PROVIDER", "WS_PROXY_PROTOCOL",
  ]) delete childEnv[key];
  childEnv.WS_PROXY_CLIENT_ID = "runtime-client";
  return { envPath, childEnv };
}

function spawnCli(args: string[], env: NodeJS.ProcessEnv): ChildProcessWithoutNullStreams {
  const child = spawn(process.execPath, [executable, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  return child;
}

async function waitChild(child: ChildProcessWithoutNullStreams): Promise<{ code: number | null; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += String(chunk); });
  child.stderr.on("data", (chunk) => { stderr += String(chunk); });
  const exit = await new Promise<{ code: number | null }>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("CLI process timed out"));
    }, 15_000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code) => { clearTimeout(timer); resolve({ code }); });
  });
  return { ...exit, stdout, stderr };
}

async function waitForOutput(child: ChildProcessWithoutNullStreams, marker: string, timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => {
      cleanup();
      child.kill("SIGKILL");
      reject(new Error(`CLI output marker timed out: ${JSON.stringify(output)}`));
    }, timeoutMs);
    const onData = (chunk: unknown) => {
      output += String(chunk);
      if (output.includes(marker)) {
        cleanup();
        resolve();
      }
    };
    const onClose = () => {
      cleanup();
      reject(new Error("CLI exited before expected output"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off("data", onData);
      child.off("close", onClose);
    };
    child.stdout.on("data", onData);
    child.once("close", onClose);
  });
}

async function privateTempDirectory(prefix: string): Promise<string> {
  // Keep external production dependencies resolvable by the spawned bundle.
  const directory = await mkdtemp(path.join(adapterRoot, `.${prefix}`));
  testDirectories.push(directory);
  return directory;
}

function listen(server: HttpServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("Mock server did not bind"));
      else resolve(address.port);
    });
  });
}

function closeHttp(server: HttpServer): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function fileExists(filePath: string): Promise<boolean> {
  try { await import("node:fs/promises").then(({ stat }) => stat(filePath)); return true; } catch { return false; }
}
