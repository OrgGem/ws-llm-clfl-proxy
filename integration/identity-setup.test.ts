import { env, reset, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { handleSetupApi } from "../apps/identity/src/bootstrap.js";
import { sha256Base64Url } from "../apps/identity/src/security.js";
import { decodeBase64Url, migrateIdentityDatabase, randomId, randomProviderSecret } from "./db-fixtures.js";

interface IdentitySetupTestEnv {
  DB: D1Database;
  PUBLIC_ORIGIN: string;
  OIDC_PROVIDERS: string;
  OIDC_ISSUER_ALLOWLIST: string;
  BOOTSTRAP_ADMIN_EMAILS: string;
  ENVELOPE_KEYS: string;
  BOOTSTRAP_PASSWORD_HASH: string;
  BOOTSTRAP_PASSWORD_EXPIRES_AT: string;
  INTEGRATION_BOOTSTRAP_PASSWORD: string;
}

interface SetupLoginResponse {
  csrfToken: string;
  expiresAt: number;
}

interface SetupConfig {
  providers: Array<{
    id: string;
    label: string;
    issuer: string;
    clientId: string;
    redirectUri: string;
    hasClientSecret: boolean;
    clientSecret?: string;
  }>;
  bootstrapAdminEmails: string[];
  allowedIssuers: string[];
  redirectUri: string;
}

interface SetupSession {
  cookie: string;
  csrfToken: string;
  setupCookieHeader: string;
}

const setupEnv = env as unknown as IdentitySetupTestEnv;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(setupEnv.DB);
});

describe("Identity bootstrap-password setup integration", () => {
  it("keeps setup disabled when the password hash is absent or expired", async () => {
    const handler = handleSetupApi as unknown as (
      request: Request,
      env: Record<string, unknown>,
    ) => Promise<Response | null>;
    const absentEnv = directSetupEnvironment();
    delete absentEnv.BOOTSTRAP_PASSWORD_HASH;

    for (const testEnv of [
      absentEnv,
      directSetupEnvironment({ BOOTSTRAP_PASSWORD_EXPIRES_AT: String(Math.floor(Date.now() / 1000) - 1) }),
    ]) {
      const statusResponse = await handler(new Request(`${setupEnv.PUBLIC_ORIGIN}/api/setup/status`), testEnv);
      expect(statusResponse).not.toBeNull();
      expect(await statusResponse!.json()).toMatchObject({ bootstrapAvailable: false });

      const loginResponse = await handler(new Request(`${setupEnv.PUBLIC_ORIGIN}/api/setup/login`, {
        method: "POST",
        headers: {
          origin: setupEnv.PUBLIC_ORIGIN,
          "content-type": "application/json",
        },
        body: JSON.stringify({ password: setupEnv.INTEGRATION_BOOTSTRAP_PASSWORD }),
      }), testEnv);
      expect(loginResponse).not.toBeNull();
      expect(loginResponse!.status).toBe(401);
      expect(await loginResponse!.json()).toMatchObject({ error: "invalid_credentials" });
    }
  });

  it("rejects hostile-origin and wrong-password logins, then issues only a setup session", async () => {
    const hostileOrigin = await SELF.fetch(new Request(`${setupEnv.PUBLIC_ORIGIN}/api/setup/login`, {
      method: "POST",
      headers: { origin: "https://attacker.example", "content-type": "application/json" },
      body: JSON.stringify({ password: setupEnv.INTEGRATION_BOOTSTRAP_PASSWORD }),
    }));
    expect(hostileOrigin.status).toBe(403);
    expect(await hostileOrigin.json()).toMatchObject({ error: "forbidden" });

    const wrongPassword = await postSetupLogin(randomProviderSecret());
    expect(wrongPassword.status).toBe(401);
    expect(await wrongPassword.json()).toMatchObject({ error: "invalid_credentials" });

    const response = await postSetupLogin(setupEnv.INTEGRATION_BOOTSTRAP_PASSWORD);
    expect(response.status).toBe(200);
    const body = await response.json() as SetupLoginResponse;
    expect(body.csrfToken).toMatch(/^[A-Za-z0-9_-]{40,64}$/);
    expect(body.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(body.expiresAt).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 30 * 60);

    const setupCookie = cookieValue(response.headers, "__Host-setup");
    const csrfCookie = cookieValue(response.headers, "__Host-setup_csrf");
    expect(setupCookie).toBeTruthy();
    expect(csrfCookie).toBe(body.csrfToken);
    const setupCookieLine = setCookieLines(response.headers).find((line) => line.startsWith("__Host-setup="));
    expect(setupCookieLine).toContain("HttpOnly");
    expect(setupCookieLine).toContain("Secure");
    expect(setupCookieLine).toContain("SameSite=Strict");
    expect(setupCookieLine).toContain("Max-Age=1800");

    const session = { cookie: setupCookie!, csrfToken: body.csrfToken, setupCookieHeader: `__Host-setup=${setupCookie}; __Host-setup_csrf=${csrfCookie}` };
    const status = await setupRequest("/api/setup/status", { session });
    expect(await status.json()).toMatchObject({ bootstrapAvailable: true, authenticated: true, authMode: "setup", csrfToken: body.csrfToken });

    const adminRoute = await SELF.fetch(new Request(`${setupEnv.PUBLIC_ORIGIN}/api/projects`, {
      headers: { cookie: session.setupCookieHeader },
    }));
    expect(adminRoute.status).toBe(401);
  });

  it("requires CSRF, rejects unsafe issuers, masks client secrets, and encrypts stored OIDC config", async () => {
    const session = await loginSetup();
    const providerSecret = randomProviderSecret();
    const validConfig = {
      providers: [{
        id: "google-integration",
        label: "Google Integration",
        issuer: "https://accounts.google.com",
        clientId: "integration-google-client",
        clientSecret: providerSecret,
      }],
      bootstrapAdminEmails: ["bootstrap-admin@integration.test"],
    };

    const noCsrf = await putOidcConfig(session, validConfig, { includeCsrf: false });
    expect(noCsrf.status).toBe(403);
    expect(await noCsrf.json()).toMatchObject({ error: "forbidden" });

    const unsafeIssuer = await putOidcConfig(session, {
      ...validConfig,
      providers: [{ ...validConfig.providers[0]!, issuer: "https://127.0.0.1/oidc" }],
    });
    expect(unsafeIssuer.status).toBe(400);
    expect(await unsafeIssuer.json()).toMatchObject({ error: "issuer_not_allowed" });

    await setupEnv.DB.prepare(
      "INSERT INTO oidc_transactions (state_hash,provider_key,code_verifier,nonce,redirect_uri,return_to,expires_at) VALUES (?,?,?,?,?,?,?)",
    ).bind("pending-transaction", "provider-a", "verifier", "nonce", `${setupEnv.PUBLIC_ORIGIN}/auth/oidc/callback`, "/", Math.floor(Date.now() / 1000) + 300).run();

    const saved = await putOidcConfig(session, validConfig);
    expect(saved.status).toBe(200);
    expect(await saved.json()).toMatchObject({
      providers: [{
        id: "google-integration",
        issuer: "https://accounts.google.com/",
        clientId: "integration-google-client",
        redirectUri: `${setupEnv.PUBLIC_ORIGIN}/auth/oidc/callback`,
        hasClientSecret: true,
      }],
      bootstrapAdminEmails: ["bootstrap-admin@integration.test"],
    });

    const getResponse = await setupRequest("/api/setup/oidc", { session });
    expect(getResponse.status).toBe(200);
    const getBody = await getResponse.text();
    expect(getBody).not.toContain(providerSecret);
    expect(getBody).not.toContain('"clientSecret"');
    const config = JSON.parse(getBody) as SetupConfig;
    expect(config.providers[0]).toMatchObject({ hasClientSecret: true });
    expect(config.providers[0]).not.toHaveProperty("clientSecret");

    const row = await setupEnv.DB.prepare(
      "SELECT key_id, nonce, ciphertext FROM identity_settings WHERE name = 'oidc'",
    ).first<{ key_id: string; nonce: string; ciphertext: string }>();
    expect(row).not.toBeNull();
    expect(JSON.stringify(row)).not.toContain(providerSecret);
    expect(JSON.stringify(row)).not.toContain("google-integration");

    const keyConfig = JSON.parse(setupEnv.ENVELOPE_KEYS) as { keys: Record<string, string> };
    const keyBytes = decodeBase64Url(keyConfig.keys[row!.key_id]!);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: decodeBase64Url(row!.nonce),
      additionalData: new TextEncoder().encode(`identity-oidc-config-v1\n${row!.key_id}`),
      tagLength: 128,
    }, key, decodeBase64Url(row!.ciphertext));
    const stored = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as {
      providers: Array<{ id: string; clientSecret: string }>;
    };
    expect(stored.providers).toMatchObject([{ id: "google-integration", clientSecret: providerSecret }]);

    const transaction = await setupEnv.DB.prepare("SELECT state_hash FROM oidc_transactions WHERE state_hash=?")
      .bind("pending-transaction").first<{ state_hash: string }>();
    expect(transaction).toBeNull();
  });

  it("fails closed for a corrupt encrypted OIDC row instead of using static providers", async () => {
    const session = await loginSetup();
    await setupEnv.DB.prepare(
      "INSERT INTO identity_settings (name,key_id,nonce,ciphertext,updated_at) VALUES ('oidc','missing-key','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAAAAAAAA',?)",
    ).bind(Math.floor(Date.now() / 1000)).run();

    const response = await setupRequest("/api/setup/oidc", { session });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "configuration_unavailable" });
  });

  it("rejects a setup write when the session expires between authorization and commit", async () => {
    const session = await loginSetup();
    const tokenHash = await sha256Base64Url(session.cookie);
    const originalBatch = setupEnv.DB.batch.bind(setupEnv.DB);
    const guardedDb = new Proxy(setupEnv.DB, {
      get(target, property) {
        if (property === "batch") {
          return async (statements: D1PreparedStatement[]) => {
            await setupEnv.DB.prepare("UPDATE setup_sessions SET expires_at=? WHERE token_hash=?")
              .bind(Math.floor(Date.now() / 1000) - 1, tokenHash).run();
            return originalBatch(statements);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const handler = handleSetupApi as unknown as (
      request: Request,
      env: Record<string, unknown>,
    ) => Promise<Response | null>;
    const body = {
      providers: [{ id: "google-integration", label: "Google", issuer: "https://accounts.google.com", clientId: "client", clientSecret: "secret" }],
      bootstrapAdminEmails: ["bootstrap-admin@integration.test"],
    };
    const response = await handler(oidcPutRequest(session, body), directSetupEnvironment({ DB: guardedDb }));

    expect(response).not.toBeNull();
    expect(response!.status).toBe(401);
    expect(await response!.json()).toMatchObject({ error: "unauthorized" });
    const row = await setupEnv.DB.prepare("SELECT name FROM identity_settings WHERE name='oidc'").first();
    expect(row).toBeNull();
  });

  it("fails closed when bootstrap state is missing or closed, including for existing setup cookies", async () => {
    const session = await loginSetup();
    await setupEnv.DB.prepare("DELETE FROM bootstrap_state WHERE singleton=1").run();

    const status = await setupRequest("/api/setup/status", { session });
    expect(await status.json()).toMatchObject({ bootstrapAvailable: false, authenticated: false });
    const writeWithoutState = await putOidcConfig(session, {
      providers: [{ id: "google-integration", label: "Google", issuer: "https://accounts.google.com", clientId: "client", clientSecret: "secret" }],
      bootstrapAdminEmails: ["bootstrap-admin@integration.test"],
    });
    expect(writeWithoutState.status).toBe(403);

    const loginWithoutState = await postSetupLogin(setupEnv.INTEGRATION_BOOTSTRAP_PASSWORD);
    expect(loginWithoutState.status).toBe(401);
    expect(await loginWithoutState.json()).toMatchObject({ error: "invalid_credentials" });
  });

  it("rejects writes after the bootstrap state is explicitly closed", async () => {
    const session = await loginSetup();
    await setupEnv.DB.prepare("UPDATE bootstrap_state SET disabled_at=? WHERE singleton=1")
      .bind(Math.floor(Date.now() / 1000)).run();

    const response = await putOidcConfig(session, {
      providers: [{ id: "google-integration", label: "Google", issuer: "https://accounts.google.com", clientId: "client", clientSecret: "secret" }],
      bootstrapAdminEmails: ["bootstrap-admin@integration.test"],
    });
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "forbidden" });
    const row = await setupEnv.DB.prepare("SELECT name FROM identity_settings WHERE name='oidc'").first();
    expect(row).toBeNull();
  });

  it("invalidates setup-session replay after an administrator has completed OIDC setup", async () => {
    const session = await loginSetup();
    const now = Math.floor(Date.now() / 1000);
    await setupEnv.DB.prepare(
      "INSERT INTO user_allowlist (issuer, subject, email, is_admin, approved_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
    ).bind("https://accounts.integration.test", randomId("admin-sub"), "completed-admin@integration.test", now, now).run();

    const replayedSession = await setupRequest("/api/setup/oidc", { session });
    expect(replayedSession.status).toBe(401);
    expect(await replayedSession.json()).toMatchObject({ error: "unauthorized" });

    const replayedWrite = await putOidcConfig(session, {
      providers: [{ id: "google-integration", label: "Google", issuer: "https://accounts.google.com", clientId: "client", clientSecret: "secret" }],
      bootstrapAdminEmails: ["bootstrap-admin@integration.test"],
    });
    expect(replayedWrite.status).toBe(403);

    const replayedPassword = await postSetupLogin(setupEnv.INTEGRATION_BOOTSTRAP_PASSWORD);
    expect(replayedPassword.status).toBe(401);
    expect(await replayedPassword.json()).toMatchObject({ error: "invalid_credentials" });
  });
});

function directSetupEnvironment(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    DB: setupEnv.DB,
    PUBLIC_ORIGIN: setupEnv.PUBLIC_ORIGIN,
    OIDC_PROVIDERS: setupEnv.OIDC_PROVIDERS,
    OIDC_ISSUER_ALLOWLIST: setupEnv.OIDC_ISSUER_ALLOWLIST,
    BOOTSTRAP_ADMIN_EMAILS: setupEnv.BOOTSTRAP_ADMIN_EMAILS,
    ENVELOPE_KEYS: setupEnv.ENVELOPE_KEYS,
    BOOTSTRAP_PASSWORD_HASH: setupEnv.BOOTSTRAP_PASSWORD_HASH,
    BOOTSTRAP_PASSWORD_EXPIRES_AT: setupEnv.BOOTSTRAP_PASSWORD_EXPIRES_AT,
    ...overrides,
  };
}

async function postSetupLogin(password: string): Promise<Response> {
  return SELF.fetch(new Request(`${setupEnv.PUBLIC_ORIGIN}/api/setup/login`, {
    method: "POST",
    headers: {
      origin: setupEnv.PUBLIC_ORIGIN,
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
    },
    body: JSON.stringify({ password }),
  }));
}

async function loginSetup(): Promise<SetupSession> {
  const response = await postSetupLogin(setupEnv.INTEGRATION_BOOTSTRAP_PASSWORD);
  expect(response.status).toBe(200);
  const body = await response.json() as SetupLoginResponse;
  const setupCookie = cookieValue(response.headers, "__Host-setup");
  const csrfCookie = cookieValue(response.headers, "__Host-setup_csrf");
  if (!setupCookie || !csrfCookie) throw new Error("Setup login did not issue setup session cookies");
  return {
    cookie: setupCookie,
    csrfToken: body.csrfToken,
    setupCookieHeader: `__Host-setup=${setupCookie}; __Host-setup_csrf=${csrfCookie}`,
  };
}

async function setupRequest(
  path: string,
  options: { session?: SetupSession; method?: string; body?: unknown } = {},
): Promise<Response> {
  const headers = new Headers();
  if (options.session) headers.set("cookie", options.session.setupCookieHeader);
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
    headers.set("origin", setupEnv.PUBLIC_ORIGIN);
    headers.set("sec-fetch-site", "same-origin");
    headers.set("x-csrf-token", options.session?.csrfToken ?? "");
  }
  return SELF.fetch(new Request(`${setupEnv.PUBLIC_ORIGIN}${path}`, {
    method: options.method ?? "GET",
    headers,
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  }));
}

async function putOidcConfig(
  session: SetupSession,
  body: unknown,
  options: { includeCsrf?: boolean } = {},
): Promise<Response> {
  return SELF.fetch(oidcPutRequest(session, body, options.includeCsrf !== false));
}

function oidcPutRequest(session: SetupSession, body: unknown, includeCsrf = true): Request {
  const headers = new Headers({
    cookie: session.setupCookieHeader,
    origin: setupEnv.PUBLIC_ORIGIN,
    "sec-fetch-site": "same-origin",
    "content-type": "application/json",
  });
  if (includeCsrf) headers.set("x-csrf-token", session.csrfToken);
  return new Request(`${setupEnv.PUBLIC_ORIGIN}/api/setup/oidc`, {
    method: "PUT",
    headers,
    body: JSON.stringify(body),
  });
}

function setCookieLines(headers: Headers): string[] {
  const getSetCookie = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(headers);
  return (headers.get("set-cookie") ?? "").split(/,\s*(?=__Host-)/).filter(Boolean);
}

function cookieValue(headers: Headers, name: string): string | null {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const line = setCookieLines(headers).find((cookie) => cookie.startsWith(`${name}=`));
  const match = line?.match(new RegExp(`^${escaped}=([^;]*)`));
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}
