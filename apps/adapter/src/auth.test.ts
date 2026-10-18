import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { pairPublicClient, parseClientBootstrap, TokenProvider } from "./auth.js";
import { createInitialConfig, ConfigStore } from "./config.js";

const bootstrap = {
  version: 1,
  identityUrl: "https://identity.example.test",
  gatewayUrl: "wss://gateway.example.test/v1/socket",
  client: { clientId: "client_test", kind: "confidential" },
  projectId: "project_test",
  models: [{ id: "chat-fast", provider: "openai" }],
  limits: { maxPayloadBytes: 1048576, maxConcurrency: 8, maxSessionSeconds: 300 },
};

describe("secret-free client bootstrap", () => {
  it("accepts the supported bootstrap shape and normalizes service URLs", () => {
    expect(parseClientBootstrap(bootstrap)).toEqual({
      ...bootstrap,
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/v1/socket",
      models: [{ id: "chat-fast", provider: "openai", protocol: "openai" }],
    });
  });

  it("preserves custom provider IDs and their explicit protocol in bootstrap metadata", () => {
    const custom = { ...bootstrap, models: [{ id: "vendor-chat", provider: "vendor_x", protocol: "openai" }] };
    expect(parseClientBootstrap(custom).models).toEqual([
      { id: "vendor-chat", provider: "vendor_x", protocol: "openai" },
    ]);
    expect(() => parseClientBootstrap({ ...bootstrap, models: [{ id: "vendor-chat", provider: "vendor_x" }] }))
      .toThrow("explicit supported protocol");
  });

  it("rejects raw secrets and unsupported limit values", () => {
    expect(() => parseClientBootstrap({ ...bootstrap, client: { ...bootstrap.client, clientSecret: "raw-secret" } }))
      .toThrow("valid clientId and kind");
    expect(() => parseClientBootstrap({ ...bootstrap, limits: { ...bootstrap.limits, maxConcurrency: 10 } }))
      .toThrow("outside the supported bounds");
  });

  it("rejects a client-selected insecure remote Gateway URL", () => {
    expect(() => parseClientBootstrap({ ...bootstrap, gatewayUrl: "ws://gateway.example.test/v1/socket" }))
      .toThrow("invalid Identity or Gateway URLs");
  });
});

describe("Identity POST redirect handling", () => {
  it("rejects OAuth and pairing redirects before forwarding request bodies", async () => {
    let attackerRequests = 0;
    const attacker = createServer((_request, response) => {
      attackerRequests += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true }));
    });
    const attackerPort = await listen(attacker);
    const identity = createServer((_request, response) => {
      response.writeHead(307, { location: `http://127.0.0.1:${attackerPort}/collect` });
      response.end();
    });
    const identityPort = await listen(identity);
    const identityUrl = `http://127.0.0.1:${identityPort}`;
    const config = createInitialConfig({
      identityUrl,
      gatewayUrl: "ws://127.0.0.1:8788/v1/socket",
      auth: { type: "confidential", clientId: "client_test", clientSecret: "confidential-secret" },
    });
    const configStore = { load: async () => config } as ConfigStore;

    try {
      await expect(new TokenProvider(configStore).getAccessToken()).rejects.toThrow("Identity token request failed");
      await expect(pairPublicClient({
        identityUrl,
        gatewayUrl: config.gatewayUrl,
        clientName: "test client",
        configStore,
        onCode: () => { throw new Error("Identity response should not reach pairing UI"); },
      })).rejects.toThrow("Identity request failed");
      expect(attackerRequests).toBe(0);
    } finally {
      await close(identity);
      await close(attacker);
    }
  });
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Auth test server failed to bind");
  return (address as AddressInfo).port;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
