import { parseCookies, randomToken, sha256Base64Url } from "./security.js";

export interface WebActor {
  userId: string;
  sessionId: string;
  email: string;
  displayName: string;
  isAdmin: boolean;
  csrfToken: string;
}

const SESSION_COOKIE = "__Host-identity_session";
const CSRF_COOKIE = "__Host-identity_csrf";

export function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json; charset=utf-8");
  responseHeaders.set("cache-control", "no-store, max-age=0");
  responseHeaders.set("pragma", "no-cache");
  return new Response(JSON.stringify(data), { status, headers: responseHeaders });
}

export function secureHeaders(response: Response, options: { allowLoopbackConnect?: boolean } = {}): Response {
  const headers = new Headers(response.headers);
  const connectSrc = options.allowLoopbackConnect ? "'self' http://127.0.0.1:*" : "'self'";
  headers.set("content-security-policy", `default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src ${connectSrc}`);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  headers.set("cross-origin-opener-policy", "same-origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function setCookie(response: Response, cookie: string): Response {
  const headers = new Headers(response.headers);
  headers.append("set-cookie", cookie);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function sessionCookie(token: string, maxAge: number): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function csrfCookie(token: string, maxAge: number): string {
  return `${CSRF_COOKIE}=${encodeURIComponent(token)}; Path=/; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

export function clearAuthCookies(): string[] {
  return [
    `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `${CSRF_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`,
  ];
}

export async function getWebActor(request: Request, env: Env): Promise<WebActor | null> {
  const cookies = parseCookies(request.headers.get("cookie"));
  const browserToken = cookies[SESSION_COOKIE];
  const csrfToken = cookies[CSRF_COOKIE];
  if (!browserToken || !csrfToken || browserToken.length > 256 || csrfToken.length > 256) return null;
  const [browserHash, csrfHash] = await Promise.all([sha256Base64Url(browserToken), sha256Base64Url(csrfToken)]);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    `SELECT s.id AS session_id, s.user_id, s.csrf_token_hash, s.last_seen_at,
            u.email, u.display_name, ua.is_admin
     FROM sessions s
     JOIN users u ON u.id = s.user_id AND u.active = 1
     JOIN user_allowlist ua ON ua.issuer = u.issuer AND ua.subject = u.subject AND ua.revoked_at IS NULL
     WHERE s.browser_token_hash = ? AND s.kind = 'web' AND s.revoked_at IS NULL AND s.expires_at > ?`,
  ).bind(browserHash, now).first<{
    session_id: string;
    user_id: string;
    csrf_token_hash: string;
    email: string;
    display_name: string;
    is_admin: number;
    last_seen_at: number;
  }>();
  if (!row || !(await constantHashEqual(csrfHash, row.csrf_token_hash))) return null;
  if (!row.session_id || !row.user_id || !row.email || !row.display_name) return null;
  if (now - row.last_seen_at >= 300) {
    await env.DB.prepare("UPDATE sessions SET last_seen_at=? WHERE id=? AND last_seen_at<=? AND revoked_at IS NULL")
      .bind(now, row.session_id, now - 300).run();
  }
  return {
    userId: row.user_id,
    sessionId: row.session_id,
    email: row.email,
    displayName: row.display_name,
    isAdmin: row.is_admin === 1,
    csrfToken,
  };
}

async function constantHashEqual(left: string, right: string): Promise<boolean> {
  const { constantTimeEqual } = await import("./security.js");
  return constantTimeEqual(left, right);
}

export async function assertBrowserWrite(request: Request, env: Env, actor: WebActor): Promise<boolean> {
  const origin = request.headers.get("origin");
  const expected = env.PUBLIC_ORIGIN ? new URL(env.PUBLIC_ORIGIN).origin : new URL(request.url).origin;
  if (!origin || origin !== expected) return false;
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") return false;
  const headerToken = request.headers.get("x-csrf-token");
  if (!headerToken || headerToken.length > 256) return false;
  const { constantTimeEqual } = await import("./security.js");
  return constantTimeEqual(headerToken, actor.csrfToken);
}

export function publicOrigin(request: Request, env: Env): string {
  const configured = env.PUBLIC_ORIGIN;
  if (configured) return new URL(configured).origin;
  return new URL(request.url).origin;
}

export function sourceAddress(request: Request): string {
  const source = request.headers.get("cf-connecting-ip") ?? "unknown";
  return source.slice(0, 128);
}

export function randomCsrfToken(): string {
  return randomToken(32);
}

export function unauthorized(): Response {
  return json({ error: "unauthorized" }, 401);
}

export function forbidden(): Response {
  return json({ error: "forbidden" }, 403);
}
