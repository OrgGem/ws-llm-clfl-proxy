import { createServer, request as httpRequest } from "node:http";
import type { Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OAuthBridge, type OAuthBridgeManager } from "./oauth-bridge.js";

const IDENTITY_ORIGIN = "https://identity.example.test";
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  })));
});

describe("local OAuth control bridge", () => {
  it("requires the exact cloud Origin and loopback Host, and narrowly answers PNA preflight", async () => {
    const bridge = new OAuthBridge({ identityUrl: IDENTITY_ORIGIN });
    const server = await startBridge(bridge);
    const base = `${server.origin}/local/oauth/pair/start`;

    const foreign = await fetch(base, { method: "OPTIONS", headers: {
      origin: "https://attacker.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type",
    } });
    expect(foreign.status).toBe(403);
    expect(foreign.headers.get("access-control-allow-origin")).toBeNull();

    const hostilePreflight = await fetch(base, { method: "OPTIONS", headers: {
      origin: IDENTITY_ORIGIN, "access-control-request-method": "POST", "access-control-request-headers": "x-ws-proxy-secret",
    } });
    expect(hostilePreflight.status).toBe(403);

    const preflight = await fetch(base, { method: "OPTIONS", headers: {
      origin: IDENTITY_ORIGIN,
      "access-control-request-method": "POST",
      "access-control-request-headers": "content-type",
      "access-control-request-private-network": "true",
    } });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe(IDENTITY_ORIGIN);
    expect(preflight.headers.get("access-control-allow-private-network")).toBe("true");
    expect(preflight.headers.get("access-control-allow-credentials")).toBeNull();

    expect(await requestStatus(server.port, "/local/oauth/health", {
      host: `attacker.example:${server.port}`, origin: IDENTITY_ORIGIN,
    })).toBe(403);
  });

  it("requires local approval, consumes Identity pairing once, binds the connected profile, and redacts tokens", async () => {
    let now = 1_800_000_000_000;
    const emitted: string[] = [];
    const redeemedGrant = { projectId: "prj_123", expiresAt: Math.floor(now / 1000) + 120, bindingId: "opaque-binding-handle" };
    const redeemPairing = vi.fn(async (pairingToken: string, machineBearer: string) => {
      expect(pairingToken).toBe("ogt_" + "A".repeat(43));
      expect(machineBearer).toBe("machine-token-private");
      return redeemedGrant;
    });
    const bindProfile = vi.fn(async () => undefined);
    const manager: OAuthBridgeManager = {
      redeemPairing,
      startLogin: vi.fn(async () => ({
        operationId: "oauth-op_123",
        authorizationUrl: "https://auth.openai.com/api/accounts/authorize?state=not-a-provider-token&code_challenge=challenge",
      })),
      status: vi.fn(async () => ({ status: "connected" as const, profileId: "profile_1", email: "person@example.test", modelsAvailable: 2 })),
      bindProfile,
      discoverModels: vi.fn(async () => [{
        id: "gpt-example", displayName: "Example model", contextWindow: 128_000,
        inputModalities: ["text", "image"], reasoningEfforts: ["low", "high"],
      }]),
      bindModelProfile: vi.fn(async () => undefined),
      disconnect: vi.fn(async () => undefined),
      listOAuthModelAliases: vi.fn(async () => ["project-chatgpt"]),
    };
    const bridge = new OAuthBridge({
      identityUrl: IDENTITY_ORIGIN,
      manager,
      tokenProvider: { getAccessToken: async () => "machine-token-private" },
      now: () => now,
      writeApprovalCode: (message) => emitted.push(message),
    });
    const server = await startBridge(bridge);

    const started = await post(server.origin, "/local/oauth/pair/start", { pairingToken: "ogt_" + "A".repeat(43) });
    expect(started.status).toBe(202);
    const startBody = await started.json() as { pairingId: string; expiresAt: number };
    expect(startBody.expiresAt).toBe(Math.floor((now + 120_000) / 1000));
    expect(JSON.stringify(startBody)).not.toContain("ogt_");
    expect(emitted).toHaveLength(1);
    const code = /code: (\d{8})/.exec(emitted[0]!)?.[1];
    expect(code).toMatch(/^\d{8}$/);

    const approved = await post(server.origin, "/local/oauth/pair/approve", {
      pairingId: startBody.pairingId, approvalCode: code,
    });
    expect(approved.status).toBe(200);
    const approval = await approved.json() as { controlToken: string; expiresAt: number; authorizationUrl: string };
    expect(approval.controlToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(approval.authorizationUrl).toMatch(/^https:\/\/auth\.openai\.com\/api\/accounts\/authorize\?/);
    expect(JSON.stringify(approval)).not.toContain("machine-token-private");
    expect(JSON.stringify(approval)).not.toContain("ogt_");
    expect(JSON.stringify(approval)).not.toContain("profile_1");
    expect(redeemPairing).toHaveBeenCalledTimes(1);

    const replay = await post(server.origin, "/local/oauth/pair/approve", {
      pairingId: startBody.pairingId, approvalCode: code,
    });
    expect(replay.status).toBe(410);
    expect(redeemPairing).toHaveBeenCalledTimes(1);

    const statusResponse = await fetch(`${server.origin}/local/oauth/status`, {
      headers: { origin: IDENTITY_ORIGIN, authorization: `Bearer ${approval.controlToken}` },
    });
    expect(statusResponse.status).toBe(200);
    const status = await statusResponse.json() as Record<string, unknown>;
    expect(status).toMatchObject({ status: "connected", email: "person@example.test", modelsAvailable: 2 });
    expect(status).not.toHaveProperty("profileId");
    expect(bindProfile).toHaveBeenCalledWith("profile_1", redeemedGrant, IDENTITY_ORIGIN);
    expect((bindProfile.mock.calls[0] as unknown as unknown[])[1]).toBe(redeemedGrant);

    const modelsResponse = await fetch(`${server.origin}/local/oauth/models`, {
      headers: { origin: IDENTITY_ORIGIN, authorization: `Bearer ${approval.controlToken}` },
    });
    expect(modelsResponse.status).toBe(200);
    const modelBody = await modelsResponse.json() as { models: Array<Record<string, unknown>>; boundAliases: string[] };
    expect(modelBody.models).toEqual([{
      id: "gpt-example", displayName: "Example model", contextWindow: 128_000,
      inputModalities: ["text", "image"], reasoningEfforts: ["low", "high"],
    }]);
    expect(JSON.stringify(modelBody)).not.toContain("accessToken");

    const binding = await fetch(`${server.origin}/local/oauth/model`, {
      method: "POST",
      headers: { origin: IDENTITY_ORIGIN, authorization: `Bearer ${approval.controlToken}`, "content-type": "application/json" },
      body: JSON.stringify({ alias: "project-chatgpt" }),
    });
    expect(binding.status).toBe(200);
    expect(await binding.json()).toEqual({ alias: "project-chatgpt", bound: true });
    expect(manager.bindModelProfile).toHaveBeenCalledWith("project-chatgpt", "profile_1");

    now += 10 * 60_000 + 1;
    const expiredControl = await fetch(`${server.origin}/local/oauth/status`, {
      headers: { origin: IDENTITY_ORIGIN, authorization: `Bearer ${approval.controlToken}` },
    });
    expect(expiredControl.status).toBe(401);
  });

  it("expires pending codes and caps guesses at five attempts", async () => {
    let now = 1_800_000_000_000;
    const emitted: string[] = [];
    const manager: OAuthBridgeManager = {
      redeemPairing: vi.fn(async () => ({ projectId: "prj_1", expiresAt: Math.floor(now / 1000) + 120, bindingId: "binding-expiry" })),
      startLogin: vi.fn(async () => ({ operationId: "op_1", authorizationUrl: "https://auth.openai.com/api/accounts/authorize?state=x" })),
      status: vi.fn(async () => ({ status: "pending" as const })),
      bindProfile: vi.fn(async () => undefined),
      discoverModels: vi.fn(async () => []),
      bindModelProfile: vi.fn(async () => undefined),
      disconnect: vi.fn(async () => undefined),
    };
    const bridge = new OAuthBridge({
      identityUrl: IDENTITY_ORIGIN, manager,
      tokenProvider: { getAccessToken: async () => "machine" },
      now: () => now,
      writeApprovalCode: (message) => emitted.push(message),
    });
    const server = await startBridge(bridge);

    const expiredStart = await post(server.origin, "/local/oauth/pair/start", { pairingToken: "ogt_" + "B".repeat(43) });
    const expiredPair = await expiredStart.json() as { pairingId: string };
    const expiredCode = /code: (\d{8})/.exec(emitted.at(-1)!)?.[1];
    now += 120_001;
    const expired = await post(server.origin, "/local/oauth/pair/approve", { pairingId: expiredPair.pairingId, approvalCode: expiredCode });
    expect(expired.status).toBe(410);
    expect(manager.redeemPairing).not.toHaveBeenCalled();

    now += 1;
    const start = await post(server.origin, "/local/oauth/pair/start", { pairingToken: "ogt_" + "C".repeat(43) });
    const pairing = await start.json() as { pairingId: string };
    const actualCode = /code: (\d{8})/.exec(emitted.at(-1)!)?.[1];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const wrong = await post(server.origin, "/local/oauth/pair/approve", { pairingId: pairing.pairingId, approvalCode: "99999999" });
      expect(wrong.status).toBe(401);
    }
    const fifth = await post(server.origin, "/local/oauth/pair/approve", { pairingId: pairing.pairingId, approvalCode: "99999999" });
    expect(fifth.status).toBe(410);
    const afterLimit = await post(server.origin, "/local/oauth/pair/approve", { pairingId: pairing.pairingId, approvalCode: actualCode });
    expect(afterLimit.status).toBe(410);
    expect(manager.redeemPairing).not.toHaveBeenCalled();
  });

  it("does not accept the ordinary local API bearer as a bridge control token", async () => {
    const manager: OAuthBridgeManager = {
      redeemPairing: vi.fn(async () => ({ projectId: "prj_1", expiresAt: 1_900_000_000, bindingId: "binding-unused" })),
      startLogin: vi.fn(async () => ({ operationId: "op_1", authorizationUrl: "https://auth.openai.com/api/accounts/authorize?state=x" })),
      status: vi.fn(async () => ({ status: "pending" as const })),
      bindProfile: vi.fn(async () => undefined),
      discoverModels: vi.fn(async () => []),
      bindModelProfile: vi.fn(async () => undefined),
      disconnect: vi.fn(async () => undefined),
    };
    const bridge = new OAuthBridge({ identityUrl: IDENTITY_ORIGIN, manager, tokenProvider: { getAccessToken: async () => "machine" } });
    const server = await startBridge(bridge);
    const response = await fetch(`${server.origin}/local/oauth/status`, {
      headers: { origin: IDENTITY_ORIGIN, authorization: "Bearer local-api-bearer-token" },
    });
    expect(response.status).toBe(401);
    expect(manager.status).not.toHaveBeenCalled();
  });
});

async function startBridge(bridge: OAuthBridge): Promise<{ origin: string; port: number }> {
  let boundPort = 0;
  const server = createServer((request, response) => {
    void bridge.handle(request, response, boundPort).then((handled) => {
      if (!handled && !response.writableEnded) { response.statusCode = 404; response.end(); }
    }).catch(() => {
      if (!response.writableEnded) { response.statusCode = 500; response.end(); }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  servers.push(server);
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind a TCP port");
  boundPort = address.port;
  return { origin: `http://127.0.0.1:${address.port}`, port: address.port };
}

async function post(origin: string, path: string, body: unknown): Promise<Response> {
  return fetch(`${origin}${path}`, {
    method: "POST",
    headers: { origin: IDENTITY_ORIGIN, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function requestStatus(port: number, path: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpRequest({ hostname: "127.0.0.1", port, path, headers }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode ?? 0));
    });
    request.once("error", reject);
    request.end();
  });
}
