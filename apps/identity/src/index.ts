import { IdentityInternal } from "./identity-service.js";
import { cleanupTransientRows, decideOidcAllowlist, ensureOidcUser, insertAudit, rateLimit } from "./db.js";
import { handleBrowserApi, handleLogout, handlePublicPairing, handleTokenRequest, sessionResponse, handleBodyError } from "./api.js";
import { assertBrowserWrite, clearAuthCookies, csrfCookie, getWebActor, json, publicOrigin, secureHeaders, sessionCookie, setCookie } from "./http.js";
import { createOidcAuthorizationRequest, OidcCallbackFailure, parseOidcProviders, processOidcCallback, safeReturnTo, type OidcTransaction } from "./oidc.js";
import { constantTimeEqual, newId, randomToken, sha256Base64Url } from "./security.js";
import { bootstrapClosureStatements, bootstrapEmailsForAllowlist, handleSetupApi, loadEffectiveOidcConfig, type SetupEnv } from "./bootstrap.js";

export { IdentityInternal };

const WEB_SESSION_TTL_SECONDS = 12 * 60 * 60;

function redirect(location: string, status = 303): Response {
  return new Response(null, {
    status,
    headers: {
      location,
      "cache-control": "no-store, max-age=0",
      "referrer-policy": "no-referrer",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    },
  });
}

function textResponse(message: string, status: number): Response {
  return new Response(message, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store, max-age=0",
      "referrer-policy": "no-referrer",
    },
  });
}

async function beginOidc(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const providerId = url.searchParams.get("provider");
  let providers;
  try { providers = (await loadEffectiveOidcConfig(env as SetupEnv)).providers; }
  catch { return textResponse("Sign-in is not available for this provider.", 503); }
  const provider = providers.find((candidate) => candidate.id === providerId) ?? (providerId ? undefined : providers[0]);
  if (!provider) return redirect("/");
  const now = Math.floor(Date.now() / 1000);
  if (!(await rateLimit(env.DB, "oidc_start", request.headers.get("cf-connecting-ip") ?? "unknown", 30, 3600, now))) {
    return textResponse("Sign-in is temporarily unavailable. Try again later.", 429);
  }
  let authorization;
  try {
    authorization = await createOidcAuthorizationRequest(provider);
  } catch {
    return textResponse("Sign-in is not available for this provider.", 503);
  }
  const returnTo = safeReturnTo(url.searchParams.get("returnTo"));
  await env.DB.prepare(
    "INSERT INTO oidc_transactions (state_hash,provider_key,code_verifier,nonce,redirect_uri,return_to,expires_at) VALUES (?,?,?,?,?,?,?)",
  ).bind(authorization.stateHash, provider.id, authorization.codeVerifier, authorization.nonce, provider.redirectUri, returnTo, now + 600).run();
  const cookieName = `__Host-oidc_${authorization.state}`;
  const response = redirect(authorization.authorizationUrl);
  return setCookie(response, `${cookieName}=${encodeURIComponent(authorization.state)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`);
}

async function completeOidc(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get("state") ?? "";
  if (!/^[A-Za-z0-9_-]{20,256}$/.test(state)) {
    return textResponse("Sign-in could not be completed. Please start again.", 400);
  }
  let oidcConfig;
  try { oidcConfig = await loadEffectiveOidcConfig(env as SetupEnv); }
  catch { return textResponse("Sign-in could not be completed. Please start again.", 503); }
  const providers = oidcConfig.providers;
  const cookieName = `__Host-oidc_${state}`;
  const cookieValue = readCookie(request.headers.get("cookie"), cookieName);
  if (!cookieValue || !constantTimeEqual(cookieValue, state)) {
    return textResponse("Sign-in could not be completed. Please start again.", 400);
  }
  const stateHash = await sha256Base64Url(state);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "DELETE FROM oidc_transactions WHERE state_hash=? AND expires_at>? RETURNING provider_key, code_verifier, nonce, redirect_uri, return_to, expires_at",
  ).bind(stateHash, now).first<{
    provider_key: string;
    code_verifier: string;
    nonce: string;
    redirect_uri: string;
    return_to: string;
    expires_at: number;
  }>();
  if (!row) return textResponse("Sign-in could not be completed. Please start again.", 400);
  const provider = providers.find((candidate) => candidate.id === row.provider_key);
  if (!provider) return textResponse("Sign-in could not be completed. Please start again.", 400);
  let identity;
  try {
    identity = await processOidcCallback(provider, url, {
      stateHash,
      state,
      provider,
      codeVerifier: row.code_verifier,
      nonce: row.nonce,
      redirectUri: row.redirect_uri,
      returnTo: row.return_to,
      expiresAt: row.expires_at,
    } satisfies OidcTransaction, cookieValue);
  } catch (error) {
    const friendlyMessage = "Sign-in could not be verified. Please start again.";
    const response = textResponse(
      error instanceof OidcCallbackFailure ? `${friendlyMessage} Reference: ${error.stage}:${error.reason}${error.claim ? `:${error.claim}` : ""}.` : friendlyMessage,
      401,
    );
    if (error instanceof OidcCallbackFailure) {
      const classification = [error.stage, error.reason, error.claim].filter(Boolean).join(":");
      response.headers.set("x-oidc-error", classification);
    }
    return setCookie(response, `${cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
  }
  let decision;
  try {
    decision = await decideOidcAllowlist(env.DB, identity, bootstrapEmailsForAllowlist(oidcConfig), now);
  } catch {
    return textResponse("Identity could not complete sign-in right now.", 503);
  }
  if (!decision.allowed) {
    const response = textResponse(decision.revoked ? "This sign-in identity has been revoked." : "This identity is awaiting administrator approval.", decision.revoked ? 403 : 403);
    return setCookie(response, `${cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
  }

  try {
    const user = await ensureOidcUser(env.DB, identity, now);
    const browserToken = randomToken(32);
    const csrfToken = randomToken(32);
    const sessionId = newId("web");
    const createSession = env.DB.prepare(
      "INSERT INTO sessions (id,user_id,project_id,kind,browser_token_hash,csrf_token_hash,device_name,created_at,expires_at,last_seen_at) VALUES (?,?,?,'web',?,?,?, ?,?,?)",
    ).bind(sessionId, user.id, user.projectId, await sha256Base64Url(browserToken), await sha256Base64Url(csrfToken), "browser", now, now + WEB_SESSION_TTL_SECONDS, now);
    if (user.isAdmin) await env.DB.batch([createSession, ...bootstrapClosureStatements(env.DB, now)]);
    else await createSession.run();
    await insertAudit(env.DB, user.id, "session.created", "session", sessionId, { kind: "web" });
    let response = redirect(safeReturnTo(row.return_to));
    response = setCookie(response, `${cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
    response = setCookie(response, sessionCookie(browserToken, WEB_SESSION_TTL_SECONDS));
    response = setCookie(response, csrfCookie(csrfToken, WEB_SESSION_TTL_SECONDS));
    return response;
  } catch {
    return textResponse("Identity could not provision your account right now.", 503);
  }
}

function readCookie(header: string | null, wanted: string): string | null {
  for (const piece of (header ?? "").split(";")) {
    const index = piece.indexOf("=");
    if (index < 1 || piece.slice(0, index).trim() !== wanted) continue;
    try { return decodeURIComponent(piece.slice(index + 1).trim()); } catch { return null; }
  }
  return null;
}

async function serveAsset(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/pair" || url.pathname === "/ui" || url.pathname === "/ui/") {
    url.pathname = "/";
  } else if (url.pathname.startsWith("/ui/")) {
    url.pathname = url.pathname.slice(3);
  }
  const assetRequest = new Request(url, request);
  const response = await env.ASSETS.fetch(assetRequest);
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store, max-age=0");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("content-security-policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function fetchIdentity(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/" && (request.method === "GET" || request.method === "HEAD")) return redirect("/ui");
  if (path.startsWith("/internal/")) return json({ error: "not_found" }, 404);
  if ((path === "/.well-known/jwks.json" || path === "/.well-known/jwks") && request.method === "GET") {
    try {
      const { publicJwksResponse } = await import("./security.js");
      return publicJwksResponse(env.MACHINE_JWT_PUBLIC_JWKS);
    } catch {
      return json({ error: "temporarily_unavailable" }, 503);
    }
  }
  if (path === "/health" && request.method === "GET") return json({ status: "ok" });
  if ((path === "/auth/oidc/start" || path === "/auth/login") && request.method === "GET") return beginOidc(request, env);
  if (path === "/auth/oidc/callback" && request.method === "GET") return completeOidc(request, env);
  if (path.startsWith("/api/setup/")) {
    const setupResponse = await handleSetupApi(request, env as SetupEnv);
    if (setupResponse) return setupResponse;
  }
  if (path === "/oauth/token") return handleTokenRequest(request, env);
  if (path === "/pairing/start" || path === "/pairing/token") return handlePublicPairing(request, env);
  if (path === "/api/session" && request.method === "GET") return sessionResponse(request, env);
  if (path === "/api/logout") {
    const actor = await getWebActor(request, env);
    return handleLogout(request, env, actor);
  }
  if (path.startsWith("/api/")) return handleBrowserApi(request, env);
  if (request.method === "GET" || request.method === "HEAD") return serveAsset(request, env);
  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return secureHeaders(await fetchIdentity(request, env));
    } catch (error) {
      const bodyFailure = handleBodyError(error);
      if (bodyFailure) return secureHeaders(bodyFailure);
      return secureHeaders(json({ error: "internal_error" }, 500));
    }
  },
  scheduled(_controller: ScheduledController, env: Env, context: ExecutionContext): void {
    context.waitUntil(cleanupTransientRows(env.DB, Math.floor(Date.now() / 1000)));
  },
};
