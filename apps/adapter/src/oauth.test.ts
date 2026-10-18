import { chmod, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { ChatGptOAuthManager } from "./oauth.js";
import { ConfigStore, createInitialConfig } from "./config.js";
import { OAuthProfileStore, type StoredChatGptProfile } from "./oauth-store.js";

const ISSUER = "https://auth.openai.com";
const RESOURCE = "https://api.openai.com/v1";
const CLIENT_ID = "issued-client-123";
const SUBJECT = "openai-subject-123";
const SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const REFRESH = "refresh-token-original-01234567890123456789";
const ROTATED_REFRESH = "refresh-token-rotated-012345678901234567890";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("client-owned ChatGPT OAuth", () => {
  it("does not require an OAuth private directory for API-key-only adapter configurations", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "adapter-no-oauth-"));
    directories.push(directory);
    if (process.platform !== "win32") await chmod(directory, 0o755);
    const config = new ConfigStore(path.join(directory, "adapter.json"));
    await config.save(createInitialConfig({
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/v1/socket",
      auth: { type: "public", clientId: "machine-client", refreshToken: "machine-refresh-token" },
    }));
    const manager = new ChatGptOAuthManager(config);
    try {
      expect(await manager.listOAuthModelAliases()).toEqual([]);
    } finally {
      await manager.close();
    }
  });

  it("mints a fresh Identity envelope after access-token refresh", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    await config.update((current) => ({ ...current, oauthModels: [{ alias: "chatgpt-model", profileId }] }));
    const signer = await createSigner();
    const startedAt = Date.now();
    let currentTime = startedAt;
    let tokenRequests = 0;
    const envelopeExpiries: number[] = [];
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        tokenRequests += 1;
        const lifetime = tokenRequests === 1 ? 60 : 3600;
        return jsonResponse({
          access_token: await signer.accessToken(CLIENT_ID, SUBJECT, lifetime),
          refresh_token: tokenRequests === 1 ? ROTATED_REFRESH : `${ROTATED_REFRESH}2`,
          expires_in: lifetime,
          scope: SCOPES,
        });
      }
      if (url.origin === "https://identity.example.test" && url.pathname === "/api/oauth/pairing/redeem") {
        return jsonResponse({ grant: { connectorId: "chatgpt", provider: "openai", projectId: "project_123", expiresAt: Math.floor(Date.now() / 1000) + 120 } });
      }
      if (url.origin === "https://identity.example.test" && url.pathname === "/api/oauth/token-envelope") {
        const body = JSON.parse(String(init?.body)) as { expiresAt: number };
        envelopeExpiries.push(body.expiresAt);
        const envelope = {
          v: 1, alg: "A256GCM", kid: "test-key", credentialId: `credential_${envelopeExpiries.length}`,
          userId: "user_123", projectId: "project_123", provider: "openai", exp: body.expiresAt,
          nonce: "A".repeat(16), ciphertext: "A".repeat(22),
        };
        return jsonResponse({ credentialId: envelope.credentialId, provider: "openai", expiresAt: envelope.exp, envelope });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl, () => currentTime);
    try {
      const grant = await manager.redeemPairing(`ogt_${"R".repeat(43)}`, "machine-bearer-token-long-enough-for-tests");
      await manager.bindProfile(profileId, grant, "https://identity.example.test");
      await manager.bindModelProfile("chatgpt-model", profileId);

      const firstEnvelope = await manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests");
      expect(firstEnvelope?.exp).toBeLessThanOrEqual(Math.floor(startedAt / 1000) + 60);
      currentTime += 40_000;
      const secondEnvelope = await manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests");

      expect(tokenRequests).toBe(2);
      expect(envelopeExpiries).toHaveLength(2);
      expect(secondEnvelope?.credentialId).not.toBe(firstEnvelope?.credentialId);
      expect(secondEnvelope?.exp).toBeGreaterThan(firstEnvelope?.exp ?? 0);
    } finally {
      await manager.close();
    }
  });

  it("uses PKCE and the callback-issued client ID, verifies tokens, and stores only the refresh token", async () => {
    const { directory, config } = await fixture();
    await new OAuthProfileStore(config.filePath).update((storage) => ({ ...storage, profiles: [] }));
    const signer = await createSigner();
    let nonce = "";
    let accessToken = "";
    let idToken = "";
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        const body = new URLSearchParams(String(init?.body ?? ""));
        expect(body.get("grant_type")).toBe("authorization_code");
        expect(body.get("client_id")).toBe(CLIENT_ID);
        expect(body.get("redirect_uri")).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/auth\/callback$/);
        expect(body.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{40,}$/);
        expect(body.get("resource")).toBe(RESOURCE);
        accessToken = await signer.accessToken(CLIENT_ID, SUBJECT);
        idToken = await signer.idToken(CLIENT_ID, SUBJECT, nonce);
        return jsonResponse({ access_token: accessToken, refresh_token: REFRESH, id_token: idToken, expires_in: 3600, scope: SCOPES });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const login = await manager.startLogin();
      const authorization = new URL(login.authorizationUrl);
      expect(authorization.origin).toBe(ISSUER);
      expect(authorization.pathname).toBe("/api/accounts/authorize");
      expect(authorization.searchParams.get("client_id")).toBe("dynamic_agent_client");
      expect(authorization.searchParams.get("agent_name_hint")).toBe("WS LLM Adapter");
      expect(authorization.searchParams.get("ext_agent_host_id")).toMatch(/^urn:uuid:/);
      expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authorization.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(authorization.searchParams.get("resource")).toBe(RESOURCE);
      nonce = authorization.searchParams.get("nonce") ?? "";
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const callback = new URL(authorization.searchParams.get("redirect_uri")!);
      const wrongState = await fetch(`${callback}?code=ignored-code&state=wrong-state&client_id=${CLIENT_ID}`);
      expect(wrongState.status).toBe(400);
      expect(fetchImpl).not.toHaveBeenCalled();
      const callbackResult = await fetch(`${callback}?code=short-lived-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}&client_id=${CLIENT_ID}`);
      expect(callbackResult.status).toBe(200);
      expect(await waitForStatus(manager, login.operationId)).toMatchObject({ status: "connected", email: "person@example.test" });

      const profiles = await manager.listProfiles();
      expect(profiles).toHaveLength(1);
      expect(profiles[0]).toMatchObject({ connected: true, scopes: expect.arrayContaining(["offline_access", "resource.invoke", "chatgpt.tokens.use.direct"]) });
      const serialized = await readFile(`${config.filePath}.oauth.json`, "utf8");
      expect((await stat(`${config.filePath}.oauth.json`)).mode & 0o777).toBe(0o600);
      expect(serialized).toContain(REFRESH);
      expect(serialized).not.toContain(accessToken);
      expect(serialized).not.toContain(idToken);
      expect(serialized).not.toContain("short-lived-code");
      expect(fetchImpl).toHaveBeenCalledTimes(2); // token endpoint plus one cached JWKS fetch
    } finally {
      await manager.close();
    }
  });

  it("does not persist a deferred token response after the login was cancelled", async () => {
    const { config } = await fixture();
    await new OAuthProfileStore(config.filePath).update((storage) => ({ ...storage, profiles: [] }));
    const signer = await createSigner();
    let nonce = "";
    let markTokenRequestStarted!: () => void;
    const tokenRequestStarted = new Promise<void>((resolve) => { markTokenRequestStarted = resolve; });
    let releaseTokenResponse!: () => void;
    const tokenResponseGate = new Promise<void>((resolve) => { releaseTokenResponse = resolve; });
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        markTokenRequestStarted();
        await tokenResponseGate;
        return jsonResponse({
          access_token: await signer.accessToken(CLIENT_ID, SUBJECT),
          refresh_token: REFRESH,
          id_token: await signer.idToken(CLIENT_ID, SUBJECT, nonce),
          expires_in: 3600,
          scope: SCOPES,
        });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const login = await manager.startLogin();
      const authorization = new URL(login.authorizationUrl);
      nonce = authorization.searchParams.get("nonce") ?? "";
      const callback = new URL(authorization.searchParams.get("redirect_uri")!);
      const response = await fetch(`${callback}?code=short-lived-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}&client_id=${CLIENT_ID}`);
      expect(response.status).toBe(200);
      await tokenRequestStarted;

      const cancel = manager.cancelLogin(login.operationId);
      expect(manager.status(login.operationId)).toMatchObject({ status: "failed", code: "authorization_failed" });
      releaseTokenResponse();
      await cancel;

      expect(manager.status(login.operationId)).toMatchObject({ status: "failed", code: "authorization_failed" });
      expect((await new OAuthProfileStore(config.filePath).snapshot()).profiles).toEqual([]);
      expect(await manager.listProfiles()).toEqual([]);
    } finally {
      releaseTokenResponse();
      await manager.close();
    }
  });

  it("lets an already-started profile commit finish before reporting a late cancellation", async () => {
    const { config } = await fixture();
    await new OAuthProfileStore(config.filePath).update((storage) => ({ ...storage, profiles: [] }));
    const signer = await createSigner();
    let nonce = "";
    let pauseNextUpdate = false;
    let markProfileSaved!: () => void;
    const profileSaved = new Promise<void>((resolve) => { markProfileSaved = resolve; });
    let releaseProfileUpdate!: () => void;
    const profileUpdateGate = new Promise<void>((resolve) => { releaseProfileUpdate = resolve; });
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        return jsonResponse({
          access_token: await signer.accessToken(CLIENT_ID, SUBJECT),
          refresh_token: REFRESH,
          id_token: await signer.idToken(CLIENT_ID, SUBJECT, nonce),
          expires_in: 3600,
          scope: SCOPES,
        });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    const profiles = (manager as unknown as { profiles: OAuthProfileStore }).profiles;
    const update = profiles.update.bind(profiles);
    profiles.update = async (mutator) => {
      const result = await update(mutator);
      if (pauseNextUpdate) {
        pauseNextUpdate = false;
        markProfileSaved();
        await profileUpdateGate;
      }
      return result;
    };
    try {
      const login = await manager.startLogin();
      pauseNextUpdate = true;
      const authorization = new URL(login.authorizationUrl);
      nonce = authorization.searchParams.get("nonce") ?? "";
      const callback = new URL(authorization.searchParams.get("redirect_uri")!);
      const callbackResult = await fetch(`${callback}?code=short-lived-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}&client_id=${CLIENT_ID}`);
      expect(callbackResult.status).toBe(200);
      await profileSaved;

      const cancellation = manager.cancelLogin(login.operationId);
      expect(manager.status(login.operationId)).toMatchObject({ status: "pending" });
      releaseProfileUpdate();
      await cancellation;

      expect(manager.status(login.operationId)).toMatchObject({ status: "connected" });
      expect((await manager.listProfiles())[0]?.connected).toBe(true);
    } finally {
      releaseProfileUpdate();
      await manager.close();
    }
  });

  it.each(["nonce", "client", "scope", "signature"] as const)("rejects a ChatGPT login with an invalid %s binding", async (invalidBinding) => {
    const { config } = await fixture();
    await new OAuthProfileStore(config.filePath).update((storage) => ({ ...storage, profiles: [] }));
    const signer = await createSigner();
    const attackerSigner = invalidBinding === "signature" ? await createSigner() : signer;
    let nonce = "";
    const callbackClientId = CLIENT_ID;
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        const body = new URLSearchParams(String(init?.body ?? ""));
        const clientId = body.get("client_id") ?? callbackClientId;
        const tokenSigner = invalidBinding === "signature" ? attackerSigner : signer;
        return jsonResponse({
          access_token: await signer.accessToken(clientId, SUBJECT),
          refresh_token: REFRESH,
          id_token: await tokenSigner.idToken(
            invalidBinding === "client" ? "different-client-id" : clientId,
            SUBJECT,
            invalidBinding === "nonce" ? "wrong-nonce" : nonce,
          ),
          expires_in: 3600,
          scope: invalidBinding === "scope" ? "openid profile email offline_access resource.invoke" : SCOPES,
        });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const login = await manager.startLogin();
      const authorization = new URL(login.authorizationUrl);
      nonce = authorization.searchParams.get("nonce") ?? "";
      const callback = new URL(authorization.searchParams.get("redirect_uri")!);
      const callbackResult = await fetch(`${callback}?code=short-lived-code&state=${encodeURIComponent(authorization.searchParams.get("state")!)}&client_id=${callbackClientId}`);
      expect(callbackResult.status).toBe(200);
      expect(await waitForStatus(manager, login.operationId)).toMatchObject({ status: "failed", code: "invalid_response" });
      expect(await manager.listProfiles()).toEqual([]);
    } finally {
      await manager.close();
    }
  });

  it("redeems a one-use project pairing, mints only a Responses envelope, and hides disconnected aliases", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    await config.update((current) => ({ ...current, oauthModels: [{ alias: "chatgpt-model", profileId }] }));
    const signer = await createSigner();
    const expiresAt = Math.floor(Date.now() / 1000) + 1_800;
    const envelope = {
      v: 1,
      alg: "A256GCM",
      kid: "test-key",
      credentialId: "credential_123",
      userId: "user_123",
      projectId: "project_123",
      provider: "openai",
      exp: expiresAt,
      nonce: "A".repeat(16),
      ciphertext: "A".repeat(22),
    };
    const identityCalls: Array<{ path: string; body?: Record<string, unknown>; authorization?: string }> = [];
    let revokedToken = "";
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        const body = new URLSearchParams(String(init?.body ?? ""));
        expect(body.get("grant_type")).toBe("refresh_token");
        expect(body.get("refresh_token")).toBe(REFRESH);
        return jsonResponse({
          access_token: await signer.accessToken(CLIENT_ID, SUBJECT),
          refresh_token: ROTATED_REFRESH,
          expires_in: 3600,
          scope: SCOPES,
        });
      }
      if (url.origin === "https://identity.example.test") {
        const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined;
        const authorization = new Headers(init?.headers).get("authorization") ?? undefined;
        identityCalls.push({ path: url.pathname, ...(body ? { body } : {}), ...(authorization ? { authorization } : {}) });
        if (url.pathname === "/api/oauth/pairing/redeem") {
          return jsonResponse({ grant: { connectorId: "chatgpt", provider: "openai", projectId: "project_123", expiresAt: Math.floor(Date.now() / 1000) + 120 } });
        }
        if (url.pathname === "/api/oauth/token-envelope") return jsonResponse({ credentialId: envelope.credentialId, provider: envelope.provider, expiresAt, envelope });
      }
      if (url.href === `${ISSUER}/.well-known/openid-configuration`) return jsonResponse({ revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke` });
      if (url.href === `${ISSUER}/api/accounts/oauth/revoke`) {
        revokedToken = new URLSearchParams(String(init?.body ?? "")).get("token") ?? "";
        return new Response(null, { status: 200 });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const grant = await manager.redeemPairing(`ogt_${"A".repeat(43)}`, "machine-bearer-token-long-enough-for-tests");
      await manager.bindProfile(profileId, grant, "https://identity.example.test");
      await manager.bindModelProfile("chatgpt-model", profileId);
      expect(await manager.listOAuthModelAliases()).toEqual(["chatgpt-model"]);

      await expect(manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests", "chat.completions"))
        .rejects.toMatchObject({ code: "responses_required" });
      const minted = await manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests", "responses");
      expect(minted).toMatchObject({ credentialId: "credential_123", provider: "openai", projectId: "project_123" });
      expect(await manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests", "responses")).toBe(minted);
      const request = identityCalls.find((call) => call.path === "/api/oauth/token-envelope");
      expect(request?.authorization).toBe("Bearer machine-bearer-token-long-enough-for-tests");
      expect(request?.body).toMatchObject({ connectorId: "chatgpt", model: "chatgpt-model", accessToken: expect.any(String), expiresAt: expect.any(Number) });
      expect(Object.keys(request?.body ?? {}).sort()).toEqual(["accessToken", "connectorId", "expiresAt", "model"]);
      expect(request?.body?.accessToken).not.toBe(REFRESH);

      await config.update((current) => ({ ...current, identityUrl: "https://identity-repointed.example.test" }));
      await expect(manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests", "responses"))
        .rejects.toMatchObject({ code: "pairing_required" });
      expect(identityCalls.filter((call) => call.path === "/api/oauth/token-envelope")).toHaveLength(1);
      await config.update((current) => ({ ...current, identityUrl: "https://identity.example.test" }));

      const disconnected = await manager.disconnectWithStatus(profileId);
      expect(disconnected).toEqual({ localDisconnected: true, remoteRevoked: true });
      expect(revokedToken).toBe(ROTATED_REFRESH);
      expect(await manager.listOAuthModelAliases()).toEqual([]);
    } finally {
      await manager.close();
    }
  });

  it("revokes the rotated refresh token when logout overlaps an in-flight refresh", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    const signer = await createSigner();
    let markRefreshStarted!: () => void;
    const refreshStarted = new Promise<void>((resolve) => { markRefreshStarted = resolve; });
    let allowRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => { allowRefresh = resolve; });
    let revokedToken = "";
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        markRefreshStarted();
        await refreshGate;
        return jsonResponse({
          access_token: await signer.accessToken(CLIENT_ID, SUBJECT),
          refresh_token: ROTATED_REFRESH,
          expires_in: 3600,
          scope: SCOPES,
        });
      }
      if (url.href === `${ISSUER}/.well-known/openid-configuration`) return jsonResponse({ revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke` });
      if (url.href === `${ISSUER}/api/accounts/oauth/revoke`) {
        revokedToken = new URLSearchParams(String(init?.body ?? "")).get("token") ?? "";
        return new Response(null, { status: 200 });
      }
      if (url.href === RESOURCE + "/models") return jsonResponse({ models: [] });
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    const logoutManager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const discovery = manager.discoverModels(profileId);
      await refreshStarted;
      const logout = logoutManager.disconnectWithStatus(profileId);
      allowRefresh();

      const [discoveryResult, logoutResult] = await Promise.allSettled([discovery, logout]);
      expect(discoveryResult.status).toBe("fulfilled");
      expect(logoutResult).toMatchObject({ status: "fulfilled", value: { localDisconnected: true, remoteRevoked: true } });
      expect(revokedToken).toBe(ROTATED_REFRESH);
      expect((await manager.listProfiles())[0]?.connected).toBe(false);
    } finally {
      allowRefresh();
      await manager.close();
      await logoutManager.close();
    }
  });

  it("bounds model discovery to normalized API-visible catalog entries", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    const signer = await createSigner();
    const eligibleModels = Array.from({ length: 501 }, (_, index) => ({
      id: `model-${String(index).padStart(3, "0")}`,
      visibility: "list",
      supported_in_api: true,
      input_modalities: ["text", "private-value"],
      supported_reasoning_levels: [{ effort: "medium" }, { effort: "not valid" }],
      context_window: 128_000,
    }));
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        return jsonResponse({ access_token: await signer.accessToken(CLIENT_ID, SUBJECT), refresh_token: ROTATED_REFRESH, expires_in: 3600, scope: SCOPES });
      }
      if (url.href === `${RESOURCE}/models`) {
        expect(new Headers(init?.headers).get("authorization")).toMatch(/^Bearer /);
        return jsonResponse({ models: [
          { id: "hidden-model", visibility: "hidden", supported_in_api: true },
          { id: "unsupported-model", visibility: "list", supported_in_api: false },
          { id: "z-visible-model", visibility: "list", supported_in_api: true },
          ...eligibleModels,
        ] });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const models = await manager.discoverModels(profileId);
      expect(models).toHaveLength(500);
      expect(models[0]).toMatchObject({ id: "model-000", inputModalities: ["text"], reasoningEfforts: ["medium"], contextWindow: 128_000 });
      expect(models.at(-1)?.id).toBe("z-visible-model");
      expect(models.some((model) => model.id === "hidden-model" || model.id === "unsupported-model")).toBe(false);
      expect(await manager.readCachedModels(profileId)).toEqual(models);
    } finally {
      await manager.close();
    }
  });

  it("does not reuse an in-flight envelope when the profile is rebound to another project", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    await config.update((current) => ({ ...current, oauthModels: [{ alias: "chatgpt-model", profileId }] }));
    const signer = await createSigner();
    let redeemCount = 0;
    let markProjectAStarted!: () => void;
    const projectAStarted = new Promise<void>((resolve) => { markProjectAStarted = resolve; });
    let allowProjectA!: () => void;
    const projectAGate = new Promise<void>((resolve) => { allowProjectA = resolve; });
    const envelopeRequests: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        return jsonResponse({ access_token: await signer.accessToken(CLIENT_ID, SUBJECT), refresh_token: ROTATED_REFRESH, expires_in: 3600, scope: SCOPES });
      }
      if (url.origin === "https://identity.example.test" && url.pathname === "/api/oauth/pairing/redeem") {
        redeemCount += 1;
        const projectId = redeemCount === 1 ? "project_a" : "project_b";
        return jsonResponse({ grant: { connectorId: "chatgpt", provider: "openai", projectId, expiresAt: Math.floor(Date.now() / 1000) + 120 } });
      }
      if (url.origin === "https://identity.example.test" && url.pathname === "/api/oauth/token-envelope") {
        const body = JSON.parse(String(init?.body)) as { expiresAt: number };
        const projectId = envelopeRequests.length === 0 ? "project_a" : "project_b";
        envelopeRequests.push(projectId);
        if (projectId === "project_a") {
          markProjectAStarted();
          await projectAGate;
        }
        const envelope = {
          v: 1, alg: "A256GCM", kid: "test-key", credentialId: `credential_${projectId}`,
          userId: "user_123", projectId, provider: "openai", exp: body.expiresAt,
          nonce: "A".repeat(16), ciphertext: "A".repeat(22),
        };
        return jsonResponse({ credentialId: envelope.credentialId, provider: "openai", expiresAt: envelope.exp, envelope });
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const grantA = await manager.redeemPairing(`ogt_${"A".repeat(43)}`, "machine-bearer-token-long-enough-for-tests");
      await manager.bindProfile(profileId, grantA, "https://identity.example.test");
      await manager.bindModelProfile("chatgpt-model", profileId);
      const pendingA = manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests");
      await projectAStarted;

      const grantB = await manager.redeemPairing(`ogt_${"B".repeat(43)}`, "machine-bearer-token-long-enough-for-tests");
      await manager.bindProfile(profileId, grantB, "https://identity.example.test");
      const resultB = await manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests");
      expect(resultB?.projectId).toBe("project_b");
      allowProjectA();
      await expect(pendingA).rejects.toMatchObject({ code: "profile_disconnected" });
      expect(await manager.ensureModelEnvelope("chatgpt-model", "machine-bearer-token-long-enough-for-tests")).toBe(resultB);
      expect(envelopeRequests).toEqual(["project_a", "project_b"]);
    } finally {
      allowProjectA();
      await manager.close();
    }
  });

  it("reports refresh-token revocation as unconfirmed after provider 4xx responses", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    const revocations: string[] = [];
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/openid-configuration`) return jsonResponse({ revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke` });
      if (url.href === `${ISSUER}/api/accounts/oauth/revoke`) {
        revocations.push(new URLSearchParams(String(init?.body ?? "")).get("token") ?? "");
        return jsonResponse({ error: "invalid_token" }, 401);
      }
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const manager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      const result = await manager.disconnectWithStatus(profileId);
      expect(result).toEqual({ localDisconnected: true, remoteRevoked: false });
      expect(revocations).toEqual([REFRESH, REFRESH]);
      expect((await manager.listProfiles())[0]?.connected).toBe(false);
    } finally {
      await manager.close();
    }
  });

  it("observes logout performed by another adapter process before reusing a cached access token", async () => {
    const { config, profileId } = await fixture({ profile: { refreshToken: REFRESH } });
    const signer = await createSigner();
    let modelRequests = 0;
    const fetchImpl = vi.fn(async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.href === `${ISSUER}/.well-known/jwks.json`) return signer.jwks();
      if (url.href === `${ISSUER}/api/accounts/oauth/token`) {
        return jsonResponse({ access_token: await signer.accessToken(CLIENT_ID, SUBJECT), refresh_token: ROTATED_REFRESH, expires_in: 3600, scope: SCOPES });
      }
      if (url.href === `${RESOURCE}/models`) {
        modelRequests += 1;
        return jsonResponse({ models: [] });
      }
      if (url.href === `${ISSUER}/.well-known/openid-configuration`) return jsonResponse({ revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke` });
      if (url.href === `${ISSUER}/api/accounts/oauth/revoke`) return new Response(null, { status: 200 });
      throw new Error(`Unexpected OAuth URL ${url.origin}${url.pathname}`);
    });
    const servingManager = new ChatGptOAuthManager(config, fetchImpl);
    const cliManager = new ChatGptOAuthManager(config, fetchImpl);
    try {
      await servingManager.discoverModels(profileId);
      expect(modelRequests).toBe(1);
      await cliManager.disconnectWithStatus(profileId);
      await expect(servingManager.discoverModels(profileId)).rejects.toMatchObject({ code: "profile_disconnected" });
      expect(modelRequests).toBe(1);
    } finally {
      await servingManager.close();
      await cliManager.close();
    }
  });
});

async function fixture(options: { profile?: Partial<StoredChatGptProfile> } = {}): Promise<{ directory: string; config: ConfigStore; profileId: string }> {
  const directory = await mkdtemp(path.join(tmpdir(), "adapter-oauth-"));
  directories.push(directory);
  const config = new ConfigStore(path.join(directory, "adapter.json"));
  await config.save(createInitialConfig({
    identityUrl: "https://identity.example.test",
    gatewayUrl: "wss://gateway.example.test/v1/socket",
    auth: { type: "public", clientId: "machine-client", refreshToken: "machine-refresh-token" },
  }));
  const profileId = "P".repeat(32);
  const profile: StoredChatGptProfile = {
    profileId,
    clientId: CLIENT_ID,
    subject: SUBJECT,
    connectedAt: Math.floor(Date.now() / 1000),
    scopes: SCOPES.split(" "),
    ...options.profile,
  };
  await new OAuthProfileStore(config.filePath).update((storage) => ({ ...storage, profiles: [profile] }));
  return { directory, config, profileId };
}

async function createSigner(): Promise<{
  jwks: () => Response;
  accessToken: (clientId: string, subject: string, lifetimeSeconds?: number) => Promise<string>;
  idToken: (clientId: string, subject: string, nonce: string) => Promise<string>;
}> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const jwks = () => jsonResponse({ keys: [{ ...publicJwk, kid: "adapter-oauth-test", alg: "RS256", use: "sig" }] });
  const sign = (claims: Record<string, unknown>, lifetimeSeconds = 3600) => {
    const issuedAt = Math.floor(Date.now() / 1000);
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "adapter-oauth-test", typ: "JWT" })
      .setIssuer(ISSUER)
      .setIssuedAt(issuedAt)
      .setExpirationTime(issuedAt + lifetimeSeconds)
      .sign(privateKey);
  };
  return {
    jwks,
    accessToken: (clientId, subject, lifetimeSeconds) => sign({ aud: RESOURCE, sub: subject, client_id: clientId, scope: SCOPES }, lifetimeSeconds),
    idToken: (clientId, subject, nonce) => sign({ aud: clientId, sub: subject, nonce, email: "person@example.test", email_verified: true }),
  };
}

async function waitForStatus(manager: ChatGptOAuthManager, operationId: string): Promise<unknown> {
  for (let index = 0; index < 100; index += 1) {
    const status = manager.status(operationId);
    if (status.status !== "pending") return status;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("OAuth callback processing timed out in test");
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}
