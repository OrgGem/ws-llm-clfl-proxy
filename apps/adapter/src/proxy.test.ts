import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect, type AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpsProxyAgent } from "https-proxy-agent";
import { ProxyAgent } from "undici";
import WebSocket, { WebSocketServer } from "ws";
import {
  createGatewayProxyAgent,
  fetchWithEnvironmentProxy,
  getEnvironmentProxyDispatcher,
} from "./proxy.js";

const proxyEnvironment = [
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy",
] as const;

afterEach(() => vi.unstubAllEnvs());

describe("environment proxy support", () => {
  it("selects an HTTP CONNECT agent for a configured WSS proxy", () => {
    clearProxyEnvironment();
    vi.stubEnv("HTTPS_PROXY", "http://proxy-user:proxy-password@proxy.example.test:8443");

    const agent = createGatewayProxyAgent("wss://gateway.example.test/v1/socket");
    expect(agent).toBeInstanceOf(HttpsProxyAgent);
    agent?.destroy();
  });

  it("bypasses environment proxies for NO_PROXY targets", () => {
    clearProxyEnvironment();
    vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:8080");
    vi.stubEnv("NO_PROXY", "identity.example.test");

    expect(createGatewayProxyAgent("wss://gateway.example.test/v1/socket")).toBeInstanceOf(HttpsProxyAgent);
    expect(createGatewayProxyAgent("wss://identity.example.test/oauth/token")).toBeUndefined();
    expect(getEnvironmentProxyDispatcher("https://identity.example.test/oauth/token")).toBeUndefined();
  });

  it("keeps loopback development Gateway connections direct", () => {
    clearProxyEnvironment();
    vi.stubEnv("HTTP_PROXY", "http://proxy.example.test:8080");
    vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:8080");

    expect(createGatewayProxyAgent("ws://127.0.0.1:8788/v1/socket")).toBeUndefined();
    expect(createGatewayProxyAgent("wss://localhost:8788/v1/socket")).toBeUndefined();
    expect(createGatewayProxyAgent("wss://[::1]:8788/v1/socket")).toBeUndefined();
  });

  it("routes Identity fetch through an HTTP environment proxy", async () => {
    clearProxyEnvironment();
    let proxyAuthorization = "";
    let targetAuthorization = "";
    let targetProxyAuthorization: string | undefined;
    const targetServer = createServer((request, response) => {
      targetAuthorization = request.headers.authorization ?? "";
      targetProxyAuthorization = request.headers["proxy-authorization"];
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ path: request.url }));
    });
    const targetPort = await listen(targetServer);
    const proxy = createServer();
    proxy.on("connect", (request, clientSocket, head) => {
      proxyAuthorization = request.headers["proxy-authorization"] ?? "";
      tunnelTo(clientSocket, head, targetPort);
    });
    const proxyPort = await listen(proxy);
    vi.stubEnv("HTTP_PROXY", `http://proxy-user:proxy-password@127.0.0.1:${proxyPort}`);
    const target = `http://identity.example.test:${targetPort}/pairing/start`;
    const dispatcher = getEnvironmentProxyDispatcher(target);

    try {
      expect(dispatcher).toBeInstanceOf(ProxyAgent);
      const response = await fetchWithEnvironmentProxy(target, { headers: { authorization: "Bearer identity-token" } });
      expect(response.ok).toBe(true);
      expect(await response.json()).toEqual({ path: "/pairing/start" });
      expect(proxyAuthorization).toBe(`Basic ${Buffer.from("proxy-user:proxy-password").toString("base64")}`);
      expect(targetAuthorization).toBe("Bearer identity-token");
      expect(targetProxyAuthorization).toBeUndefined();
    } finally {
      await dispatcher?.close();
      await close(proxy);
      await close(targetServer);
    }
  });

  it("completes a local TLS WebSocket CONNECT through HTTPS_PROXY", async () => {
    clearProxyEnvironment();
    const { certificate, key } = temporaryTlsCredentials();
    let proxyAuthorization = "";
    let targetAuthorization = "";
    let targetProxyAuthorization: string | undefined;
    const targetServer = createHttpsServer({ key, cert: certificate });
    const webSocketServer = new WebSocketServer({
      server: targetServer,
      handleProtocols: (protocols) => protocols.has("llm-proxy.v1") ? "llm-proxy.v1" : false,
    });
    webSocketServer.on("connection", (socket, request) => {
      targetAuthorization = request.headers.authorization ?? "";
      targetProxyAuthorization = request.headers["proxy-authorization"];
      socket.close(1000, "test complete");
    });
    const targetPort = await listen(targetServer);
    const proxy = createServer();
    proxy.on("connect", (request, clientSocket, head) => {
      proxyAuthorization = request.headers["proxy-authorization"] ?? "";
      tunnelTo(clientSocket, head, targetPort);
    });
    const proxyPort = await listen(proxy);
    vi.stubEnv("HTTPS_PROXY", `http://proxy-user:proxy-password@127.0.0.1:${proxyPort}`);
    const target = `wss://gateway.example.test:${targetPort}/v1/socket`;
    const agent = createGatewayProxyAgent(target);
    if (!agent) throw new Error("Configured HTTPS proxy was not selected");
    const client = new WebSocket(target, ["llm-proxy.v1"], {
      agent,
      ca: certificate,
      headers: { authorization: "Bearer gateway-token" },
      handshakeTimeout: 3000,
    });

    try {
      await new Promise<void>((resolve, reject) => {
        client.once("open", resolve);
        client.once("error", reject);
      });
      expect(client.protocol).toBe("llm-proxy.v1");
      expect(proxyAuthorization).toBe(`Basic ${Buffer.from("proxy-user:proxy-password").toString("base64")}`);
      expect(targetAuthorization).toBe("Bearer gateway-token");
      expect(targetProxyAuthorization).toBeUndefined();
    } finally {
      client.close();
      agent.destroy();
      await new Promise<void>((resolve) => webSocketServer.close(() => resolve()));
      await close(proxy);
      await close(targetServer);
    }
  });

  it("does not expose credentials from unsupported proxy URLs", () => {
    clearProxyEnvironment();
    vi.stubEnv("HTTPS_PROXY", "socks5://private-user:private-password@proxy.example.test:1080");
    let thrown: unknown;
    try {
      createGatewayProxyAgent("wss://gateway.example.test/v1/socket");
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toContain("Only HTTP and HTTPS");
    expect((thrown as Error).message).not.toContain("private-user");
    expect((thrown as Error).message).not.toContain("private-password");
  });
});

function clearProxyEnvironment(): void {
  for (const key of proxyEnvironment) vi.stubEnv(key, "");
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Proxy test server failed to bind");
  return (address as AddressInfo).port;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function tunnelTo(clientSocket: Duplex, head: Buffer, targetPort: number): void {
  const upstream = connect(targetPort, "127.0.0.1", () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length > 0) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on("error", () => clientSocket.destroy());
}

/** Generate test-only TLS material privately, then remove the temporary files. */
function temporaryTlsCredentials(): { certificate: Buffer; key: Buffer } {
  const directory = mkdtempSync(join(tmpdir(), "ws-proxy-tls-"));
  const keyPath = join(directory, "key.pem");
  const certPath = join(directory, "cert.pem");
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-days", "1", "-subj", "/CN=gateway.example.test",
      "-addext", "subjectAltName=DNS:gateway.example.test",
      "-keyout", keyPath, "-out", certPath,
    ], { stdio: "ignore", timeout: 10_000 });
    return { key: readFileSync(keyPath), certificate: readFileSync(certPath) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
