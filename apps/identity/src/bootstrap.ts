import { rateLimit } from "./db.js";
import { assertBrowserWrite, getWebActor, json, setCookie, sourceAddress, type WebActor } from "./http.js";
import { parseOidcProviders, type OidcProvider } from "./oidc.js";
import { constantTimeEqual, decodeBase64Url, newId, parseCookies, parseEnvelopeKeys, randomToken, readJson, sha256Base64Url } from "./security.js";

export type SetupEnv = Omit<Env, "OIDC_ISSUER_ALLOWLIST"> & {
  BOOTSTRAP_PASSWORD_HASH?: string;
  BOOTSTRAP_PASSWORD_EXPIRES_AT?: string;
  OIDC_ISSUER_ALLOWLIST?: string;
};

export interface StoredOidcProvider {
  id: string;
  label: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
}

export interface EffectiveOidcConfig {
  providers: OidcProvider[];
  bootstrapAdminEmails: string[];
}

interface OidcSettingsDocument {
  version: 1;
  providers: StoredOidcProvider[];
  bootstrapAdminEmails: string[];
}

interface IdentitySettingRow {
  key_id: string;
  nonce: string;
  ciphertext: string;
}

interface SetupAuth {
  kind: "setup" | "admin";
  csrfToken: string;
  expiresAt: number;
  setupSessionId?: string;
  actor?: WebActor;
}

const SETUP_COOKIE = "__Host-setup";
const SETUP_CSRF_COOKIE = "__Host-setup_csrf";
const SETUP_TTL_SECONDS = 30 * 60;
const OIDC_SETTING_NAME = "oidc";
const OIDC_SETTING_AAD_PREFIX = "identity-oidc-config-v1\n";
const PROVIDER_ID = /^[a-z][a-z0-9_-]{0,31}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function parseAllowlistedIssuers(raw: string | undefined): Set<string> {
  let configured: unknown = ["https://accounts.google.com"];
  if (raw !== undefined) {
    if (raw.length > 16_384) throw new Error("OIDC issuer allowlist is invalid");
    try { configured = JSON.parse(raw); } catch { throw new Error("OIDC issuer allowlist is invalid"); }
  }
  if (!Array.isArray(configured) || configured.length < 1 || configured.length > 32) {
    throw new Error("OIDC issuer allowlist is invalid");
  }
  const issuers = new Set<string>();
  for (const value of configured) {
    if (typeof value !== "string" || value.length > 2048) throw new Error("OIDC issuer allowlist is invalid");
    const url = parsePublicIssuer(value);
    issuers.add(url.href);
  }
  return issuers;
}

function parsePublicIssuer(raw: string): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("OIDC issuer URL is invalid"); }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (
    url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
    !hostname || hostname === "localhost" || hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") || hostname.endsWith(".internal") ||
    !hostname.includes(".") || hostname.includes(":") || /^\d+(?:\.\d+){3}$/.test(hostname)
  ) throw new Error("OIDC issuer must be an allowlisted public HTTPS URL");
  return url;
}

function callbackUri(env: SetupEnv): string {
  const origin = env.PUBLIC_ORIGIN ? new URL(env.PUBLIC_ORIGIN).origin : "https://identity.invalid";
  return `${origin}/auth/oidc/callback`;
}

function parseEmails(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > 20) return null;
  const emails: string[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string" || item.length > 320) return null;
    const email = item.trim().toLowerCase();
    if (!EMAIL.test(email) || seen.has(email)) return null;
    seen.add(email);
    emails.push(email);
  }
  return emails;
}

function storedFromRawProviders(
  raw: unknown,
  allowedIssuers: Set<string>,
  redirectUri: string,
): StoredOidcProvider[] | null {
  if (!Array.isArray(raw) || raw.length > 8) return null;
  const output: StoredOidcProvider[] = [];
  const ids = new Set<string>();
  for (const candidate of raw) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
    const item = candidate as Record<string, unknown>;
    if (
      typeof item.id !== "string" || !PROVIDER_ID.test(item.id) || ids.has(item.id) ||
      (item.label !== undefined && (typeof item.label !== "string" || item.label.trim().length < 1 || item.label.length > 80)) ||
      typeof item.issuer !== "string" || typeof item.clientId !== "string" || item.clientId.length < 1 || item.clientId.length > 512 ||
      typeof item.clientSecret !== "string" || item.clientSecret.length < 1 || item.clientSecret.length > 2048
    ) return null;
    let issuer: URL;
    try { issuer = parsePublicIssuer(item.issuer); } catch { return null; }
    if (!allowedIssuers.has(issuer.href)) return null;
    ids.add(item.id);
    output.push({
      id: item.id,
      label: typeof item.label === "string" ? item.label.trim() : item.id,
      issuer: issuer.href,
      clientId: item.clientId,
      clientSecret: item.clientSecret,
    });
  }
  return output;
}

function providersForConfig(stored: StoredOidcProvider[], redirectUri: string): OidcProvider[] {
  const raw = stored.map((provider) => ({ ...provider, redirectUri }));
  return parseOidcProviders(JSON.stringify(raw));
}

function parseStoredDocument(value: unknown, allowlist: Set<string>, redirectUri: string): EffectiveOidcConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Stored OIDC settings are invalid");
  const doc = value as Partial<OidcSettingsDocument>;
  if (doc.version !== 1 || !Array.isArray(doc.providers)) throw new Error("Stored OIDC settings are invalid");
  const stored = storedFromRawProviders(doc.providers, allowlist, redirectUri);
  const emails = parseEmails(doc.bootstrapAdminEmails);
  if (!stored || !emails) throw new Error("Stored OIDC settings are invalid");
  const providers = providersForConfig(stored, redirectUri);
  if (providers.length !== stored.length) throw new Error("Stored OIDC settings are invalid");
  return { providers, bootstrapAdminEmails: emails };
}

async function decryptSettings(env: SetupEnv, row: IdentitySettingRow, allowlist: Set<string>): Promise<EffectiveOidcConfig> {
  const keys = parseEnvelopeKeys(env.ENVELOPE_KEYS);
  const encodedKey = keys.keys[row.key_id];
  if (!encodedKey) throw new Error("Stored OIDC settings key is unavailable");
  const keyBytes = decodeBase64Url(encodedKey);
  try {
    const nonce = decodeBase64Url(row.nonce);
    const ciphertext = decodeBase64Url(row.ciphertext);
    if (nonce.byteLength !== 12 || ciphertext.byteLength < 17 || ciphertext.byteLength > 32_768) {
      throw new Error("Stored OIDC settings are invalid");
    }
    const keyData = new Uint8Array(keyBytes);
    const iv = new Uint8Array(nonce);
    const additionalData = new TextEncoder().encode(`${OIDC_SETTING_AAD_PREFIX}${row.key_id}`);
    const encryptedBytes = new Uint8Array(ciphertext);
    const key = await crypto.subtle.importKey("raw", keyData.buffer, "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer, additionalData: new Uint8Array(additionalData).buffer, tagLength: 128 },
      key,
      encryptedBytes.buffer,
    );
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    return parseStoredDocument(parsed, allowlist, callbackUri(env));
  } finally {
    keyBytes.fill(0);
  }
}

/** Load encrypted D1 settings once configured; use the legacy secret bindings only before the first save. */
export async function loadEffectiveOidcConfig(env: SetupEnv): Promise<EffectiveOidcConfig> {
  const allowlist = parseAllowlistedIssuers(env.OIDC_ISSUER_ALLOWLIST);
  const row = await env.DB.prepare("SELECT key_id, nonce, ciphertext FROM identity_settings WHERE name = ?")
    .bind(OIDC_SETTING_NAME).first<IdentitySettingRow>();
  if (row) return decryptSettings(env, row, allowlist);

  let legacy: unknown = [];
  if (env.OIDC_PROVIDERS) {
    try { legacy = JSON.parse(env.OIDC_PROVIDERS); } catch { throw new Error("Legacy OIDC settings are invalid"); }
  }
  const stored = storedFromRawProviders(legacy, allowlist, callbackUri(env));
  if (!stored) throw new Error("Legacy OIDC settings are invalid or use a disallowed issuer");
  const emails = (env.BOOTSTRAP_ADMIN_EMAILS ?? "").split(",").map((value) => value.trim().toLowerCase()).filter(Boolean);
  if (emails.some((email) => email.length > 320 || !EMAIL.test(email))) throw new Error("Legacy OIDC administrator email settings are invalid");
  const providers = providersForConfig(stored, callbackUri(env));
  if (providers.length !== stored.length) throw new Error("Legacy OIDC settings are invalid");
  return { providers, bootstrapAdminEmails: [...new Set(emails)] };
}

async function settingsRowExists(env: SetupEnv): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 AS found FROM identity_settings WHERE name = ?")
    .bind(OIDC_SETTING_NAME).first<{ found: number }>();
  return Boolean(row);
}

async function bootstrapAvailable(env: SetupEnv, now: number): Promise<{ available: boolean; passwordExpiresAt: number }> {
  const configuredExpiry = Number(env.BOOTSTRAP_PASSWORD_EXPIRES_AT);
  if (!env.BOOTSTRAP_PASSWORD_HASH || !/^[A-Za-z0-9_-]{43}$/.test(env.BOOTSTRAP_PASSWORD_HASH) ||
      !Number.isSafeInteger(configuredExpiry) || configuredExpiry <= now || configuredExpiry > now + 86_400) {
    return { available: false, passwordExpiresAt: 0 };
  }
  const [state, historicalAdmin] = await Promise.all([
    env.DB.prepare("SELECT disabled_at FROM bootstrap_state WHERE singleton = 1").first<{ disabled_at: number | null }>(),
    env.DB.prepare("SELECT 1 AS found FROM user_allowlist WHERE is_admin = 1 LIMIT 1").first<{ found: number }>(),
  ]);
  return { available: Boolean(state && state.disabled_at === null && !historicalAdmin), passwordExpiresAt: configuredExpiry };
}

function setupCookie(token: string, maxAge: number): string {
  return `${SETUP_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function setupCsrfCookie(token: string, maxAge: number): string {
  return `${SETUP_CSRF_COOKIE}=${encodeURIComponent(token)}; Path=/; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function clearSetupCookies(): string[] {
  return [
    `${SETUP_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    `${SETUP_CSRF_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`,
  ];
}

function sameOriginWrite(request: Request, env: SetupEnv): boolean {
  const expectedOrigin = env.PUBLIC_ORIGIN ? new URL(env.PUBLIC_ORIGIN).origin : new URL(request.url).origin;
  if (request.headers.get("origin") !== expectedOrigin) return false;
  const site = request.headers.get("sec-fetch-site");
  return !site || site === "same-origin" || site === "none";
}

async function getSetupAuth(request: Request, env: SetupEnv, now: number, requireCsrf: boolean): Promise<SetupAuth | null> {
  const actor = await getWebActor(request, env as Env);
  if (actor) {
    if (!actor.isAdmin) return null;
    if (requireCsrf && !(await assertBrowserWrite(request, env as Env, actor))) return null;
    const row = await env.DB.prepare("SELECT expires_at FROM sessions WHERE id=? AND revoked_at IS NULL AND expires_at>? AND kind='web'")
      .bind(actor.sessionId, now).first<{ expires_at: number }>();
    return row ? { kind: "admin", csrfToken: actor.csrfToken, expiresAt: row.expires_at, actor } : null;
  }

  const available = await bootstrapAvailable(env, now);
  if (!available.available) return null;
  const cookies = parseCookies(request.headers.get("cookie"));
  const token = cookies[SETUP_COOKIE];
  const csrfToken = cookies[SETUP_CSRF_COOKIE];
  if (!token || !csrfToken || token.length > 256 || csrfToken.length > 256) return null;
  const tokenHash = await sha256Base64Url(token);
  const csrfHash = await sha256Base64Url(csrfToken);
  const row = await env.DB.prepare("SELECT id, csrf_token_hash, expires_at FROM setup_sessions WHERE token_hash=? AND revoked_at IS NULL AND expires_at>? LIMIT 1")
    .bind(tokenHash, now).first<{ id: string; csrf_token_hash: string; expires_at: number }>();
  if (!row || !constantTimeEqual(row.csrf_token_hash, csrfHash)) return null;
  if (requireCsrf) {
    const headerToken = request.headers.get("x-csrf-token");
    if (!sameOriginWrite(request, env) || !headerToken || !constantTimeEqual(headerToken, csrfToken)) return null;
  }
  return { kind: "setup", csrfToken, expiresAt: row.expires_at, setupSessionId: row.id };
}

function safeConfig(config: EffectiveOidcConfig, env: SetupEnv): Record<string, unknown> {
  const redirectUri = callbackUri(env);
  return {
    providers: config.providers.map(({ id, label, issuer, clientId, clientSecret }) => ({
      id,
      label,
      issuer: issuer.href,
      clientId,
      redirectUri,
      hasClientSecret: clientSecret.length > 0,
    })),
    bootstrapAdminEmails: config.bootstrapAdminEmails,
    allowedIssuers: [...parseAllowlistedIssuers(env.OIDC_ISSUER_ALLOWLIST)].sort(),
    redirectUri,
  };
}

async function encryptSettings(env: SetupEnv, document: OidcSettingsDocument): Promise<{ keyId: string; nonce: string; ciphertext: string }> {
  const keys = parseEnvelopeKeys(env.ENVELOPE_KEYS);
  const keyId = keys.current;
  const keyBytes = decodeBase64Url(keys.keys[keyId]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  try {
    const keyData = new Uint8Array(keyBytes);
    const iv = new Uint8Array(nonce);
    const additionalData = new TextEncoder().encode(`${OIDC_SETTING_AAD_PREFIX}${keyId}`);
    const plaintext = new TextEncoder().encode(JSON.stringify(document));
    const key = await crypto.subtle.importKey("raw", keyData.buffer, "AES-GCM", false, ["encrypt"]);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer, additionalData: new Uint8Array(additionalData).buffer, tagLength: 128 },
      key,
      new Uint8Array(plaintext).buffer,
    );
    const { encodeBase64Url } = await import("./security.js");
    return { keyId, nonce: encodeBase64Url(nonce), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
  } finally {
    keyBytes.fill(0);
  }
}

async function handleSetupLogin(request: Request, env: SetupEnv): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!sameOriginWrite(request, env)) return json({ error: "forbidden" }, 403);
  const now = nowSeconds();
  if (!(await rateLimit(env.DB, "setup_login", sourceAddress(request), 5, 900, now))) {
    return json({ error: "rate_limited" }, 429, { "retry-after": "900" });
  }
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return json({ error: "invalid_request" }, 415);
  const body = await readJson(request, 2048);
  if (typeof body.password !== "string" || body.password.length < 1 || body.password.length > 256) return json({ error: "invalid_credentials" }, 401);
  const available = await bootstrapAvailable(env, now);
  const suppliedHash = await sha256Base64Url(body.password);
  const expectedHash = available.available ? env.BOOTSTRAP_PASSWORD_HASH! : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  if (!available.available || !constantTimeEqual(suppliedHash, expectedHash)) return json({ error: "invalid_credentials" }, 401);

  const token = randomToken(32);
  const csrfToken = randomToken(32);
  const sessionId = newId("setup");
  const expiresAt = Math.min(now + SETUP_TTL_SECONDS, available.passwordExpiresAt);
  const maxAge = Math.max(1, expiresAt - now);
  const inserted = await env.DB.prepare(
    `INSERT INTO setup_sessions (id,token_hash,csrf_token_hash,created_at,expires_at)
     SELECT ?,?,?,?,?
     WHERE EXISTS (SELECT 1 FROM bootstrap_state WHERE singleton=1 AND disabled_at IS NULL)
       AND NOT EXISTS (SELECT 1 FROM user_allowlist WHERE is_admin=1)
     RETURNING id`,
  ).bind(sessionId, await sha256Base64Url(token), await sha256Base64Url(csrfToken), now, expiresAt).first<{ id: string }>();
  if (!inserted) return json({ error: "invalid_credentials" }, 401);
  let response = json({ csrfToken, expiresAt });
  response = setCookie(response, setupCookie(token, maxAge));
  return setCookie(response, setupCsrfCookie(csrfToken, maxAge));
}

async function handleSetupStatus(request: Request, env: SetupEnv): Promise<Response> {
  const now = nowSeconds();
  const available = await bootstrapAvailable(env, now);
  const [configured, auth] = await Promise.all([
    settingsRowExists(env).catch(() => false),
    getSetupAuth(request, env, now, false),
  ]);
  const config = await loadEffectiveOidcConfig(env).catch(() => null);
  const result: Record<string, unknown> = {
    bootstrapAvailable: available.available,
    oidcConfigured: config ? config.providers.length > 0 : configured,
    redirectUri: callbackUri(env),
    allowedIssuers: [...parseAllowlistedIssuers(env.OIDC_ISSUER_ALLOWLIST)].sort(),
    authenticated: Boolean(auth),
  };
  if (auth) {
    result.authMode = auth.kind;
    result.csrfToken = auth.csrfToken;
    result.expiresAt = auth.expiresAt;
  }
  return json(result);
}

async function resolveOidcSetupAuth(request: Request, env: SetupEnv, now: number, write: boolean): Promise<SetupAuth | null> {
  const actor = await getWebActor(request, env as Env);
  if (actor) {
    if (!actor.isAdmin) return null;
    if (write && !(await assertBrowserWrite(request, env as Env, actor))) return null;
    const row = await env.DB.prepare("SELECT expires_at FROM sessions WHERE id=? AND revoked_at IS NULL AND expires_at>? AND kind='web'")
      .bind(actor.sessionId, now).first<{ expires_at: number }>();
    return row ? { kind: "admin", csrfToken: actor.csrfToken, expiresAt: row.expires_at, actor } : null;
  }
  const auth = await getSetupAuth(request, env, now, write);
  return auth?.kind === "setup" ? auth : null;
}

async function handleGetOidc(request: Request, env: SetupEnv): Promise<Response> {
  const auth = await resolveOidcSetupAuth(request, env, nowSeconds(), false);
  if (!auth) return json({ error: "unauthorized" }, 401);
  try { return json(safeConfig(await loadEffectiveOidcConfig(env), env)); }
  catch { return json({ error: "configuration_unavailable" }, 503); }
}

async function handlePutOidc(request: Request, env: SetupEnv): Promise<Response> {
  if (request.method !== "PUT") return json({ error: "method_not_allowed" }, 405);
  const now = nowSeconds();
  const auth = await resolveOidcSetupAuth(request, env, now, true);
  if (!auth) return json({ error: "forbidden" }, 403);
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return json({ error: "invalid_request" }, 415);
  const body = await readJson(request, 16_384);
  const allowlist = parseAllowlistedIssuers(env.OIDC_ISSUER_ALLOWLIST);
  const redirectUri = callbackUri(env);
  const current = await loadEffectiveOidcConfig(env);
  const currentStored: StoredOidcProvider[] = current.providers.map(({ id, label, issuer, clientId, clientSecret }) => ({ id, label, issuer: issuer.href, clientId, clientSecret }));
  if (!Array.isArray(body.providers) || body.providers.length > 8) return json({ error: "invalid_providers" }, 400);
  const providers: StoredOidcProvider[] = [];
  const ids = new Set<string>();
  for (const candidate of body.providers) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return json({ error: "invalid_providers" }, 400);
    const item = candidate as Record<string, unknown>;
    if (
      typeof item.id !== "string" || !PROVIDER_ID.test(item.id) || ids.has(item.id) ||
      typeof item.label !== "string" || item.label.trim().length < 1 || item.label.length > 80 ||
      typeof item.issuer !== "string" || typeof item.clientId !== "string" || item.clientId.length < 1 || item.clientId.length > 512 ||
      (item.clientSecret !== undefined && typeof item.clientSecret !== "string") ||
      (typeof item.clientSecret === "string" && item.clientSecret.length > 2048)
    ) return json({ error: "invalid_providers" }, 400);
    let issuer: URL;
    try { issuer = parsePublicIssuer(item.issuer); } catch { return json({ error: "issuer_not_allowed" }, 400); }
    if (!allowlist.has(issuer.href)) return json({ error: "issuer_not_allowed" }, 400);
    const existing = currentStored.find((provider) => provider.id === item.id);
    let clientSecret = typeof item.clientSecret === "string" ? item.clientSecret : "";
    if (!clientSecret && existing && existing.issuer === issuer.href && existing.clientId === item.clientId) clientSecret = existing.clientSecret;
    if (!clientSecret) return json({ error: "client_secret_required" }, 400);
    ids.add(item.id);
    providers.push({ id: item.id, label: item.label.trim(), issuer: issuer.href, clientId: item.clientId, clientSecret });
  }
  const bootstrapAdminEmails = parseEmails(body.bootstrapAdminEmails);
  if (!bootstrapAdminEmails) return json({ error: "invalid_bootstrap_admin_emails" }, 400);
  const parsedProviders = providersForConfig(providers, redirectUri);
  if (parsedProviders.length !== providers.length) return json({ error: "invalid_providers" }, 400);

  const document: OidcSettingsDocument = { version: 1, providers, bootstrapAdminEmails };
  const encrypted = await encryptSettings(env, document);
  const commitNow = nowSeconds();
  const setupGuard = `EXISTS (SELECT 1 FROM bootstrap_state WHERE singleton=1 AND disabled_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM user_allowlist WHERE is_admin=1)
    AND EXISTS (SELECT 1 FROM setup_sessions WHERE id=? AND revoked_at IS NULL AND expires_at>?)`;
  const adminGuard = `EXISTS (SELECT 1 FROM sessions s
    JOIN users u ON u.id=s.user_id AND u.active=1
    JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject AND a.is_admin=1 AND a.revoked_at IS NULL
    WHERE s.id=? AND s.user_id=? AND s.kind='web' AND s.csrf_token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?)`;
  const guard = auth.kind === "admin" ? adminGuard : setupGuard;
  const binds: Array<string | number | null> = [OIDC_SETTING_NAME, encrypted.keyId, encrypted.nonce, encrypted.ciphertext, commitNow];
  if (auth.kind === "setup") binds.push(auth.setupSessionId ?? null, commitNow);
  else binds.push(auth.actor!.sessionId, auth.actor!.userId, await sha256Base64Url(auth.actor!.csrfToken), commitNow);
  if (auth.kind === "setup") binds.push(auth.setupSessionId ?? null, commitNow);
  else binds.push(auth.actor!.sessionId, auth.actor!.userId, await sha256Base64Url(auth.actor!.csrfToken), commitNow);
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO identity_settings (name,key_id,nonce,ciphertext,updated_at)
       SELECT ?,?,?,?,? WHERE ${guard}
       ON CONFLICT(name) DO UPDATE SET key_id=excluded.key_id, nonce=excluded.nonce, ciphertext=excluded.ciphertext, updated_at=excluded.updated_at
       WHERE ${guard}
       RETURNING name`,
    ).bind(...binds),
    env.DB.prepare(
      "DELETE FROM oidc_transactions WHERE EXISTS (SELECT 1 FROM identity_settings WHERE name=? AND key_id=? AND nonce=? AND ciphertext=? AND updated_at=?)",
    ).bind(OIDC_SETTING_NAME, encrypted.keyId, encrypted.nonce, encrypted.ciphertext, commitNow),
  ]);
  if (!results[0]?.results?.length) return json({ error: "unauthorized" }, 401);
  if (auth.actor) await import("./db.js").then(({ insertAudit }) => insertAudit(env.DB, auth.actor!.userId, "oidc.settings_updated", "identity_settings", OIDC_SETTING_NAME));
  return json(safeConfig({ providers: parsedProviders, bootstrapAdminEmails }, env));
}

async function handleSetupLogout(request: Request, env: SetupEnv): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!(await sameOriginWrite(request, env))) return json({ error: "forbidden" }, 403);
  const auth = await getSetupAuth(request, env, nowSeconds(), true);
  if (!auth || auth.kind !== "setup" || !auth.setupSessionId) return json({ error: "unauthorized" }, 401);
  await env.DB.prepare("UPDATE setup_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE id=?")
    .bind(nowSeconds(), auth.setupSessionId).run();
  let response = json({ ok: true });
  for (const cookie of clearSetupCookies()) response = setCookie(response, cookie);
  return response;
}

/** Handles setup-only routes. Return null for routes owned by the normal Identity API. */
export async function handleSetupApi(request: Request, env: SetupEnv): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (!path.startsWith("/api/setup/")) return null;
  if (path === "/api/setup/status" && request.method === "GET") return handleSetupStatus(request, env);
  if (path === "/api/setup/login") return handleSetupLogin(request, env);
  if (path === "/api/setup/logout") return handleSetupLogout(request, env);
  if (path === "/api/setup/oidc" && request.method === "GET") return handleGetOidc(request, env);
  if (path === "/api/setup/oidc" && request.method === "PUT") return handlePutOidc(request, env);
  return json({ error: "not_found" }, 404);
}

/** Called only after OIDC verification and allowlist approval for an administrator. */
export function bootstrapClosureStatements(db: D1Database, now: number): D1PreparedStatement[] {
  return [
    db.prepare("UPDATE bootstrap_state SET disabled_at=COALESCE(disabled_at,?) WHERE singleton=1").bind(now),
    db.prepare("UPDATE setup_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE revoked_at IS NULL").bind(now),
  ];
}

export function bootstrapEmailsForAllowlist(config: EffectiveOidcConfig): string {
  return config.bootstrapAdminEmails.join(",");
}
