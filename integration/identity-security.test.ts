import { env, reset, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { migrateIdentityDatabase, randomId, randomProviderSecret } from "./db-fixtures.js";

interface IdentitySecurityEnv {
  DB: D1Database;
  PUBLIC_ORIGIN: string;
  OIDC_PROVIDERS: string;
}

interface PairingStart {
  pairingId: string;
  deviceCode: string;
  userCode: string;
}

interface SecurityFixture {
  userId: string;
  projectId: string;
  browserToken: string;
  csrfToken: string;
}

const identityEnv = env as unknown as IdentitySecurityEnv;
let fixture: SecurityFixture;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(identityEnv.DB);
  fixture = await seedBrowserIdentity();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Identity security regressions", () => {
  it("does not consume a pairing request when polled with the wrong device code", async () => {
    const pairing = await startPairing();

    const wrongCode = await postJson("/pairing/token", {
      pairingId: pairing.pairingId,
      deviceCode: randomProviderSecret(),
    });
    expect(wrongCode.status).toBe(410);
    expect(await wrongCode.json()).toMatchObject({ error: "expired_or_delivered" });

    const rightCode = await postJson("/pairing/token", {
      pairingId: pairing.pairingId,
      deviceCode: pairing.deviceCode,
    });
    expect(rightCode.status).toBe(200);
    expect(await rightCode.json()).toEqual({ status: "pending" });
  });

  it("rejects a device code after its pairing request expires", async () => {
    const pairing = await startPairing();
    await identityEnv.DB.prepare("UPDATE pairing_requests SET expires_at = ? WHERE id = ?")
      .bind(Math.floor(Date.now() / 1000) - 1, pairing.pairingId)
      .run();

    const response = await postJson("/pairing/token", {
      pairingId: pairing.pairingId,
      deviceCode: pairing.deviceCode,
    });
    expect(response.status).toBe(410);
    expect(await response.json()).toMatchObject({ error: "expired_or_delivered" });

    const session = await identityEnv.DB.prepare("SELECT id FROM sessions WHERE kind = 'refresh'").first();
    expect(session).toBeNull();
  });

  it("rejects a browser pairing approval without the CSRF header", async () => {
    const pairing = await startPairing();
    const response = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/api/pairing/approve`, {
      method: "POST",
      headers: {
        cookie: browserCookies(),
        origin: identityEnv.PUBLIC_ORIGIN,
        "content-type": "application/json",
      },
      body: JSON.stringify({ userCode: pairing.userCode, projectId: fixture.projectId, models: [] }),
    }));
    expect(response.status).toBe(403);

    const request = await identityEnv.DB.prepare("SELECT status FROM pairing_requests WHERE id = ?")
      .bind(pairing.pairingId)
      .first<{ status: string }>();
    expect(request?.status).toBe("pending");
  });

  it("derives the OIDC provider from the one-time state transaction without a provider query", async () => {
    const providerConfig = JSON.parse(identityEnv.OIDC_PROVIDERS) as Array<{
      id: string;
      issuer: string;
      redirectUri: string;
    }>;
    const provider = providerConfig.find((item) => item.id === "provider-b");
    expect(provider).toBeDefined();
    const state = randomProviderSecret();
    const now = Math.floor(Date.now() / 1000);
    await identityEnv.DB.prepare(
      "INSERT INTO oidc_transactions (state_hash, provider_key, code_verifier, nonce, redirect_uri, return_to, expires_at) VALUES (?, ?, ?, ?, ?, '/', ?)",
    ).bind(
      await sha256Base64Url(state),
      "provider-b",
      randomProviderSecret(),
      randomProviderSecret(),
      provider!.redirectUri,
      now + 600,
    ).run();

    const observedRequests: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      observedRequests.push(input instanceof Request ? input.url : String(input));
      return new Response("provider unavailable", { status: 503 });
    });

    const callbackUrl = new URL(`${identityEnv.PUBLIC_ORIGIN}/auth/oidc/callback`);
    callbackUrl.searchParams.set("code", "authorization-code");
    callbackUrl.searchParams.set("state", state);
    const response = await SELF.fetch(new Request(callbackUrl, {
      headers: { cookie: `__Host-oidc_${state}=${state}` },
    }));

    expect(response.status).toBe(401);
    expect(observedRequests.some((url) => url.startsWith("https://oidc-b.integration.test/"))).toBe(true);
    expect(observedRequests.some((url) => url.startsWith("https://oidc-a.integration.test/"))).toBe(false);
    expect(callbackUrl.searchParams.has("provider")).toBe(false);
    const consumed = await identityEnv.DB.prepare("SELECT state_hash FROM oidc_transactions WHERE state_hash = ?")
      .bind(await sha256Base64Url(state))
      .first();
    expect(consumed).toBeNull();
  });
});

async function seedBrowserIdentity(): Promise<SecurityFixture> {
  const now = Math.floor(Date.now() / 1000);
  const userId = randomId("usr");
  const projectId = randomId("prj");
  const browserSessionId = randomId("web");
  const userIssuer = "https://accounts.integration.test";
  const subject = randomId("sub");
  const email = "identity-security@integration.test";
  const browserToken = randomProviderSecret();
  const csrfToken = randomProviderSecret();

  await identityEnv.DB.prepare(
    "INSERT INTO user_allowlist (issuer, subject, email, is_admin, approved_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
  ).bind(userIssuer, subject, email, now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO users (id, issuer, subject, email, display_name, active, created_at, updated_at) VALUES (?, ?, ?, ?, 'Security Test User', 1, ?, ?)",
  ).bind(userId, userIssuer, subject, email, now, now).run();
  await identityEnv.DB.prepare("INSERT INTO projects (id, owner_user_id, name, created_at) VALUES (?, ?, 'Security Test Project', ?)")
    .bind(projectId, userId, now)
    .run();
  await identityEnv.DB.prepare("INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)")
    .bind(projectId, userId, now)
    .run();
  await identityEnv.DB.prepare(
    "INSERT INTO sessions (id, user_id, project_id, kind, browser_token_hash, csrf_token_hash, device_name, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, 'web', ?, ?, 'security test browser', ?, ?, ?)",
  ).bind(
    browserSessionId,
    userId,
    projectId,
    await sha256Base64Url(browserToken),
    await sha256Base64Url(csrfToken),
    now,
    now + 3_600,
    now,
  ).run();

  return { userId, projectId, browserToken, csrfToken };
}

async function startPairing(): Promise<PairingStart> {
  const response = await postJson("/pairing/start", { clientName: "Security test adapter" });
  expect(response.status).toBe(201);
  return await response.json() as PairingStart;
}

function postJson(path: string, body: unknown): Promise<Response> {
  return SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }));
}

function browserCookies(): string {
  return `__Host-identity_session=${encodeURIComponent(fixture.browserToken)}; __Host-identity_csrf=${encodeURIComponent(fixture.csrfToken)}`;
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
