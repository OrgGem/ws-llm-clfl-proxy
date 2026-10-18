import { env, reset, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { IdentityInternal } from "../apps/identity/src/identity-service.js";
import { handleOAuthApi } from "../apps/identity/src/oauth-api.js";
import { migrateIdentityDatabase, randomId, randomProviderSecret } from "./db-fixtures.js";

interface IdentityOAuthEnv {
  DB: D1Database;
  MACHINE_ISSUER: string;
  MACHINE_JWT_PRIVATE_JWK: string;
  MACHINE_JWT_PUBLIC_JWKS: string;
  PUBLIC_ORIGIN: string;
  ENVELOPE_KEYS: string;
  CHATGPT_OAUTH_REMOTE_ELIGIBILITY: string;
}

interface ActorFixture {
  userId: string;
  projectId: string;
  clientId: string;
  clientRowId: string;
  clientSecret: string;
  browserToken: string;
  csrfToken: string;
}

interface MachineTokenResponse { access_token: string; }
interface PairingResponse { pairingToken: string; expiresAt: number; }

const identityEnv = env as unknown as IdentityOAuthEnv;
let owner: ActorFixture;
let other: ActorFixture;
let ownerAccessToken: string;
let otherAccessToken: string;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(identityEnv.DB);
  owner = await seedActor("oauth-owner", true);
  other = await seedActor("oauth-other", false);
  ownerAccessToken = await machineToken(owner);
  otherAccessToken = await machineToken(other);
});

afterEach(() => {
  // Restore mutable globals used by Cloudflare's test runtime if a failure stubs them.
});

describe("Identity OAuth connector APIs", () => {
  it("allows loopback fetches only from the UI HTML CSP while keeping API and script CSP strict", async () => {
    const html = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/ui/`);
    expect(html.status).toBe(200);
    expect(html.headers.get("content-type")).toMatch(/^text\/html/i);
    const htmlPolicy = html.headers.get("content-security-policy") ?? "";
    expect(htmlPolicy).toContain("connect-src 'self' http://127.0.0.1:*");
    expect(htmlPolicy).toContain("script-src 'self'");
    expect(htmlPolicy).toContain("style-src 'self'");

    const script = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/ui/app.js`);
    expect(script.status).toBe(200);
    expect(script.headers.get("content-security-policy")).toContain("connect-src 'self'");
    expect(script.headers.get("content-security-policy")).not.toContain("127.0.0.1");

    const api = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/api/oauth/connectors`);
    expect(api.status).toBe(401);
    expect(api.headers.get("content-security-policy")).toContain("connect-src 'self'");
    expect(api.headers.get("content-security-policy")).not.toContain("127.0.0.1");
  });

  it("reports explicit connector capability state only to an authenticated browser", async () => {
    const unauthenticated = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/api/oauth/connectors`);
    expect(unauthenticated.status).toBe(401);

    const response = await browserRequest(owner, "/api/oauth/connectors");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ connectors: [
      {
        id: "chatgpt",
        provider: "openai",
        localOAuth: { enabled: true },
        remoteInference: { enabled: false, eligibilityState: "pending", reasonCode: "eligibility_pending" },
      },
      {
        id: "claude",
        provider: "anthropic",
        localOAuth: { enabled: false, reasonCode: "subscription_oauth_unavailable" },
        remoteInference: { enabled: false, reasonCode: "subscription_oauth_unavailable" },
      },
    ] });

    const verifiedStatus = await handleOAuthApi(new Request(`${identityEnv.PUBLIC_ORIGIN}/api/oauth/connectors`, {
      headers: {
        cookie: `__Host-identity_session=${encodeURIComponent(owner.browserToken)}; __Host-identity_csrf=${encodeURIComponent(owner.csrfToken)}`,
      },
    }), withEligibility("verified"));
    expect(verifiedStatus?.status).toBe(200);
    expect(await verifiedStatus!.json()).toMatchObject({ connectors: [
      { id: "chatgpt", remoteInference: { enabled: true, eligibilityState: "verified", verificationSource: "operator_config" } },
      { id: "claude", remoteInference: { enabled: false, reasonCode: "subscription_oauth_unavailable" } },
    ] });
  });

  it("requires same-origin CSRF before minting a user/project-bound local bridge grant", async () => {
    const missingCsrf = await browserRequest(owner, "/api/oauth/pairing", "POST", {
      projectId: owner.projectId,
      connectorId: "chatgpt",
    }, false);
    expect(missingCsrf.status).toBe(403);

    const foreignOrigin = await browserRequest(owner, "/api/oauth/pairing", "POST", {
      projectId: owner.projectId,
      connectorId: "chatgpt",
    }, true, "https://attacker.example");
    expect(foreignOrigin.status).toBe(403);

    const created = await browserRequest(owner, "/api/oauth/pairing", "POST", {
      projectId: owner.projectId,
      connectorId: "chatgpt",
    });
    expect(created.status).toBe(201);
    const grant = await created.json() as PairingResponse;
    expect(grant.pairingToken).toMatch(/^ogt_[A-Za-z0-9_-]{43}$/);
    expect(grant.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(grant.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 120);

    const savedHash = await sha256Base64Url(grant.pairingToken);
    const stored = await identityEnv.DB.prepare(
      "SELECT token_hash,user_id,project_id,provider,redeemed_at FROM oauth_bridge_grants WHERE token_hash=?",
    ).bind(savedHash).first<Record<string, unknown>>();
    expect(stored).toMatchObject({
      token_hash: savedHash,
      user_id: owner.userId,
      project_id: owner.projectId,
      provider: "openai",
      redeemed_at: null,
    });
    expect(JSON.stringify(stored)).not.toContain(grant.pairingToken);

    const wrongPrincipal = await machineRequest(otherAccessToken, "/api/oauth/pairing/redeem", { pairingToken: grant.pairingToken });
    expect(wrongPrincipal.status).toBe(403);
    const ownerRedeem = await machineRequest(ownerAccessToken, "/api/oauth/pairing/redeem", { pairingToken: grant.pairingToken });
    expect(ownerRedeem.status).toBe(200);
    const redeemed = await ownerRedeem.json() as { grant: Record<string, unknown> };
    expect(redeemed.grant).toEqual({
      connectorId: "chatgpt",
      provider: "openai",
      projectId: owner.projectId,
      expiresAt: grant.expiresAt,
    });
    const replay = await machineRequest(ownerAccessToken, "/api/oauth/pairing/redeem", { pairingToken: grant.pairingToken });
    expect(replay.status).toBe(410);
  });

  it("redeems a grant for a joined project even when the browser session defaulted to another project", async () => {
    const now = Math.floor(Date.now() / 1000);
    const projectId = randomId("prj");
    const clientRowId = randomId("client");
    const clientId = randomId("cli");
    const clientSecret = randomProviderSecret();
    const secretHash = await sha256Base64Url(clientSecret);
    await identityEnv.DB.prepare("INSERT INTO projects (id,owner_user_id,name,created_at) VALUES (?,?,?,?)")
      .bind(projectId, owner.userId, "Team project", now).run();
    await identityEnv.DB.prepare("INSERT INTO project_members (project_id,user_id,role,created_at) VALUES (?,?,'admin',?)")
      .bind(projectId, owner.userId, now).run();
    await identityEnv.DB.prepare(
      "INSERT INTO clients (id,client_identifier,project_id,created_by,name,kind,secret_hash,active,created_at) VALUES (?,?,?,?,'Team adapter','confidential',?,1,?)",
    ).bind(clientRowId, clientId, projectId, owner.userId, secretHash, now).run();
    const teamActor = { ...owner, projectId, clientRowId, clientId, clientSecret };
    const teamAccessToken = await machineToken(teamActor);

    const created = await browserRequest(owner, "/api/oauth/pairing", "POST", { projectId, connectorId: "chatgpt" });
    expect(created.status).toBe(201);
    const bridge = await created.json() as PairingResponse;
    const redeem = await machineRequest(teamAccessToken, "/api/oauth/pairing/redeem", { pairingToken: bridge.pairingToken });
    expect(redeem.status, await redeem.clone().text()).toBe(200);
    expect(await redeem.json()).toMatchObject({ grant: { projectId, provider: "openai", connectorId: "chatgpt" } });
  });

  it("rejects expired bridge grants without exposing provider or machine tokens", async () => {
    const created = await browserRequest(owner, "/api/oauth/pairing", "POST", {
      projectId: owner.projectId,
      connectorId: "chatgpt",
    });
    const grant = await created.json() as PairingResponse;
    const hash = await sha256Base64Url(grant.pairingToken);
    await identityEnv.DB.prepare("UPDATE oauth_bridge_grants SET expires_at=? WHERE token_hash=?")
      .bind(Math.floor(Date.now() / 1000) - 1, hash).run();
    const response = await machineRequest(ownerAccessToken, "/api/oauth/pairing/redeem", { pairingToken: grant.pairingToken });
    expect(response.status).toBe(410);
    const body = await response.text();
    expect(body).not.toContain(grant.pairingToken);
    expect(body).not.toContain(ownerAccessToken);
    expect(body).not.toContain(owner.clientSecret);
  });

  it("does not redeem a bridge grant after its issuing browser session is revoked", async () => {
    const created = await browserRequest(owner, "/api/oauth/pairing", "POST", {
      projectId: owner.projectId,
      connectorId: "chatgpt",
    });
    const grant = await created.json() as PairingResponse;
    const hash = await sha256Base64Url(grant.pairingToken);
    const row = await identityEnv.DB.prepare("SELECT browser_session_id FROM oauth_bridge_grants WHERE token_hash=?")
      .bind(hash).first<{ browser_session_id: string }>();
    await identityEnv.DB.prepare("UPDATE sessions SET revoked_at=? WHERE id=?")
      .bind(Math.floor(Date.now() / 1000), row!.browser_session_id).run();

    const response = await machineRequest(ownerAccessToken, "/api/oauth/pairing/redeem", { pairingToken: grant.pairingToken });
    expect(response.status).toBe(403);
    const saved = await identityEnv.DB.prepare("SELECT redeemed_at FROM oauth_bridge_grants WHERE token_hash=?")
      .bind(hash).first<{ redeemed_at: number | null }>();
    expect(saved?.redeemed_at).toBeNull();
  });

  it("fails closed for remote token envelopes until operator eligibility is explicitly verified", async () => {
    const accessToken = providerToken();
    const response = await machineRequest(ownerAccessToken, "/api/oauth/token-envelope", {
      connectorId: "chatgpt",
      model: "oauth-model",
      accessToken,
      expiresAt: Math.floor(Date.now() / 1000) + 1_800,
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "remote_inference_not_verified" });
    const row = await identityEnv.DB.prepare("SELECT COUNT(*) AS count FROM credentials WHERE credential_kind='oauth_access_token'")
      .first<{ count: number }>();
    expect(row?.count).toBe(0);
  });

  it("issues only bounded, model-authorized OAuth envelopes when explicitly enabled", async () => {
    await grantOpenAiModel(owner);
    const now = Math.floor(Date.now() / 1000);
    const accessToken = providerToken();
    const expiresAt = now + 7_200;
    const verifiedEnv = withEligibility("verified");
    const response = await callOAuthApi(verifiedEnv, ownerAccessToken, "/api/oauth/token-envelope", {
      connectorId: "chatgpt", model: "oauth-model", accessToken, expiresAt,
    });
    expect(response.status, await response.clone().text()).toBe(201);
    const issued = await response.json() as {
      credentialId: string;
      provider: string;
      expiresAt: number;
      envelope: { v: number; alg: string; kid: string; credentialId: string; userId: string; projectId: string; provider: string; exp: number; nonce: string; ciphertext: string };
    };
    expect(issued.provider).toBe("openai");
    expect(issued.expiresAt).toBeLessThanOrEqual(now + 3_600);
    expect(issued.expiresAt).toBeLessThanOrEqual(expiresAt);
    expect(issued.envelope).toMatchObject({
      v: 1,
      alg: "A256GCM",
      credentialId: issued.credentialId,
      userId: owner.userId,
      projectId: owner.projectId,
      provider: "openai",
      exp: issued.expiresAt,
    });
    expect(issued.envelope.ciphertext).not.toContain(accessToken);
    expect(JSON.stringify(issued)).not.toContain(accessToken);
    const credential = await identityEnv.DB.prepare(
      "SELECT user_id,project_id,provider,credential_kind,expires_at,revoked_at FROM credentials WHERE id=?",
    ).bind(issued.credentialId).first<Record<string, unknown>>();
    expect(credential).toEqual({
      user_id: owner.userId,
      project_id: owner.projectId,
      provider: "openai",
      credential_kind: "oauth_access_token",
      expires_at: issued.expiresAt,
      revoked_at: null,
    });

    const pendingInternal = new IdentityInternal({} as ExecutionContext, withEligibility("pending"));
    const pending = await pendingInternal.authorizeTokenRequest({
      accessToken: ownerAccessToken,
      credentialId: issued.credentialId,
      provider: "openai",
      model: "oauth-model",
    });
    expect(pending).toMatchObject({ allowed: false, reasonCode: "provider_oauth_not_verified" });

    const verifiedInternal = new IdentityInternal({} as ExecutionContext, verifiedEnv);
    const allowed = await verifiedInternal.authorizeTokenRequest({
      accessToken: ownerAccessToken,
      credentialId: issued.credentialId,
      provider: "openai",
      model: "oauth-model",
    });
    expect(allowed).toMatchObject({
      allowed: true,
      credentialMetadata: { credentialId: issued.credentialId, credentialKind: "oauth_access_token" },
      authorizedProvider: { id: "openai", protocol: "openai", baseUrl: "https://api.openai.com/v1/" },
    });
    const wrongProvider = await verifiedInternal.authorizeTokenRequest({
      accessToken: ownerAccessToken,
      credentialId: issued.credentialId,
      provider: "anthropic",
      model: "oauth-model",
    });
    expect(wrongProvider).toMatchObject({ allowed: false, reasonCode: "provider_or_model_not_allowed" });

    const shortExpiry = Math.floor(Date.now() / 1000) + 90;
    const shortToken = providerToken();
    const shortIssue = await callOAuthApi(verifiedEnv, ownerAccessToken, "/api/oauth/token-envelope", {
      connectorId: "chatgpt", model: "oauth-model", accessToken: shortToken, expiresAt: shortExpiry,
    });
    expect(shortIssue.status, await shortIssue.clone().text()).toBe(201);
    const shortCredential = await shortIssue.json() as { expiresAt: number };
    expect(shortCredential.expiresAt).toBeLessThanOrEqual(shortExpiry);

    const deniedOtherClient = await machineRequest(ownerAccessToken, "/api/oauth/token-envelope", {
      connectorId: "chatgpt", model: "not-granted", accessToken, expiresAt,
    }, verifiedEnv);
    expect(deniedOtherClient.status).toBe(403);
  });

  it("rejects refresh-token fields, extra owner/route fields, unsafe bearer strings, and expired expiry declarations", async () => {
    const verifiedEnv = withEligibility("verified");
    const base = {
      connectorId: "chatgpt",
      model: "oauth-model",
      accessToken: providerToken(),
      expiresAt: Math.floor(Date.now() / 1000) + 1_800,
    };
    const extra = await callOAuthApi(verifiedEnv, ownerAccessToken, "/api/oauth/token-envelope", {
      ...base,
      refreshToken: "do-not-store-me",
      userId: other.userId,
      baseUrl: "https://attacker.example/",
    });
    expect(extra.status).toBe(400);
    expect(await extra.text()).not.toContain("do-not-store-me");

    const unsafeBearer = await callOAuthApi(verifiedEnv, ownerAccessToken, "/api/oauth/token-envelope", {
      ...base,
      accessToken: "bad\r\nAuthorization: Bearer attacker",
    });
    expect(unsafeBearer.status).toBe(400);

    const expired = await callOAuthApi(verifiedEnv, ownerAccessToken, "/api/oauth/token-envelope", {
      ...base,
      expiresAt: Math.floor(Date.now() / 1000) - 1,
    });
    expect(expired.status).toBe(400);

    const rows = await identityEnv.DB.prepare("SELECT COUNT(*) AS count FROM credentials WHERE credential_kind='oauth_access_token'")
      .first<{ count: number }>();
    expect(rows?.count).toBe(0);
  });
});

async function seedActor(prefix: string, withModelGrant: boolean): Promise<ActorFixture> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = "https://accounts.integration.test";
  const subject = randomId("sub");
  const userId = randomId("usr");
  const projectId = randomId("prj");
  const clientRowId = randomId("client");
  const clientId = randomId("cli");
  const sessionId = randomId("ses");
  const browserSessionId = randomId("web");
  const clientSecret = randomProviderSecret();
  const browserToken = randomProviderSecret();
  const csrfToken = randomProviderSecret();
  const [secretHash, browserHash, csrfHash] = await Promise.all([
    sha256Base64Url(clientSecret), sha256Base64Url(browserToken), sha256Base64Url(csrfToken),
  ]);
  await identityEnv.DB.prepare(
    "INSERT INTO user_allowlist (issuer,subject,email,is_admin,approved_at,created_at) VALUES (?,?,?,0,?,?)",
  ).bind(issuer, subject, `${prefix}@integration.test`, now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO users (id,issuer,subject,email,display_name,active,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?)",
  ).bind(userId, issuer, subject, `${prefix}@integration.test`, prefix, now, now).run();
  await identityEnv.DB.prepare("INSERT INTO projects (id,owner_user_id,name,created_at) VALUES (?,?,?,?)")
    .bind(projectId, userId, `${prefix} project`, now).run();
  await identityEnv.DB.prepare("INSERT INTO project_members (project_id,user_id,role,created_at) VALUES (?,?,'owner',?)")
    .bind(projectId, userId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO clients (id,client_identifier,project_id,created_by,name,kind,secret_hash,active,created_at) VALUES (?,?,?,?,'OAuth integration client','confidential',?,1,?)",
  ).bind(clientRowId, clientId, projectId, userId, secretHash, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO sessions (id,user_id,project_id,kind,browser_token_hash,csrf_token_hash,device_name,created_at,expires_at,last_seen_at) VALUES (?,?,?,'web',?,?,?, ?,?,?)",
  ).bind(browserSessionId, userId, projectId, browserHash, csrfHash, `${prefix} browser`, now, now + 3600, now).run();
  if (withModelGrant) {
    await grantOpenAiModel({ userId, projectId, clientRowId, clientId });
  }
  return { userId, projectId, clientId, clientRowId, clientSecret, browserToken, csrfToken };
}

async function grantOpenAiModel(actor: Pick<ActorFixture, "userId" | "projectId" | "clientRowId" | "clientId">): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await identityEnv.DB.prepare(
    "INSERT OR IGNORE INTO provider_models (provider,alias,upstream_model,display_name,enabled,created_at) VALUES ('openai','oauth-model','gpt-oauth-test','OAuth test model',1,?)",
  ).bind(now).run();
  await identityEnv.DB.prepare(
    "INSERT OR IGNORE INTO project_permissions (project_id,provider,model,created_by,created_at) VALUES (?,'openai','oauth-model',?,?)",
  ).bind(actor.projectId, actor.userId, now).run();
  await identityEnv.DB.prepare(
    "INSERT OR IGNORE INTO client_permissions (client_id,provider,model,created_by,created_at) VALUES (?,'openai','oauth-model',?,?)",
  ).bind(actor.clientRowId, actor.userId, now).run();
}

async function machineToken(actor: ActorFixture): Promise<string> {
  const response = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/oauth/token`, {
    method: "POST",
    headers: {
      authorization: `Basic ${btoa(`${actor.clientId}:${actor.clientSecret}`)}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  }));
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json() as MachineTokenResponse).access_token;
}

function browserRequest(
  actor: ActorFixture,
  path: string,
  method = "GET",
  body?: unknown,
  includeCsrf = true,
  origin = identityEnv.PUBLIC_ORIGIN,
): Promise<Response> {
  const headers = new Headers({
    cookie: `__Host-identity_session=${encodeURIComponent(actor.browserToken)}; __Host-identity_csrf=${encodeURIComponent(actor.csrfToken)}`,
  });
  if (method !== "GET" && method !== "HEAD") {
    headers.set("origin", origin);
    headers.set("sec-fetch-site", "same-origin");
    if (includeCsrf) headers.set("x-csrf-token", actor.csrfToken);
  }
  if (body !== undefined) headers.set("content-type", "application/json");
  return SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

function machineRequest(
  token: string,
  path: string,
  body: unknown,
  overrideEnv: Env = env as unknown as Env,
): Promise<Response> {
  return callOAuthApi(overrideEnv, token, path, body);
}

function callOAuthApi(overrideEnv: Env, token: string, path: string, body: unknown): Promise<Response> {
  return handleOAuthApi(new Request(`${identityEnv.PUBLIC_ORIGIN}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  }), overrideEnv).then((response) => response ?? new Response(null, { status: 404 }));
}

function withEligibility(value: string): Env {
  const target = env as unknown as Env;
  return new Proxy(target, {
    get(object, key, receiver) {
      if (key === "CHATGPT_OAUTH_REMOTE_ELIGIBILITY") return value;
      return Reflect.get(object, key, receiver);
    },
  });
}

function providerToken(): string {
  return `provider-access-${randomProviderSecret()}`;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return encodeBase64Url(digest);
}
