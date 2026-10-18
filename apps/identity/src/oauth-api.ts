import { createCredentialEnvelope, newId, randomToken, readJson, RequestBodyError, sha256Base64Url } from "./security.js";
import { rateLimit } from "./db.js";
import { assertBrowserWrite, forbidden, getWebActor, json, type WebActor } from "./http.js";
import { validateMachineToken } from "./identity-service.js";

const PAIRING_TTL_SECONDS = 2 * 60;
const OAUTH_CREDENTIAL_MAX_TTL_SECONDS = 60 * 60;
const safeProjectId = /^[A-Za-z0-9._:-]{1,128}$/;
const bearerTokenPattern = /^[A-Za-z0-9._~+/-]+=*$/;

function isChatGptRemoteVerified(env: Env): boolean {
  // This is an explicit operator attestation, not an automatic vendor-eligibility inference.
  return env.CHATGPT_OAUTH_REMOTE_ELIGIBILITY === "verified";
}

function connectorResponse(env: Env): Response {
  const verified = isChatGptRemoteVerified(env);
  return json({
    connectors: [
      {
        id: "chatgpt",
        provider: "openai",
        localOAuth: { enabled: true },
        remoteInference: {
          enabled: verified,
          eligibilityState: verified ? "verified" : "pending",
          ...(verified ? { verificationSource: "operator_config" } : {}),
          ...(verified ? {} : { reasonCode: "eligibility_pending" }),
        },
      },
      {
        id: "claude",
        provider: "anthropic",
        localOAuth: { enabled: false, reasonCode: "subscription_oauth_unavailable" },
        remoteInference: { enabled: false, reasonCode: "subscription_oauth_unavailable" },
      },
    ],
  });
}

function hasExactKeys(body: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(body);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(body, key));
}

async function webActor(request: Request, env: Env): Promise<WebActor | Response> {
  const actor = await getWebActor(request, env);
  if (!actor) return json({ error: "unauthorized" }, 401);
  if (!(await assertBrowserWrite(request, env, actor))) return forbidden();
  return actor;
}

async function machinePrincipal(request: Request, env: Env) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer ([A-Za-z0-9._~-]{20,16384})$/);
  if (!match) return null;
  return validateMachineToken(env, match[1]!);
}

async function createPairingGrant(request: Request, env: Env): Promise<Response> {
  const actorOrResponse = await webActor(request, env);
  if (actorOrResponse instanceof Response) return actorOrResponse;
  const actor = actorOrResponse;

  let body: Record<string, unknown>;
  try { body = await readJson(request, 2_048); }
  catch (error) { return json({ error: "invalid_request" }, error instanceof RequestBodyError ? error.status : 400); }
  if (!hasExactKeys(body, ["projectId", "connectorId"]) ||
      typeof body.projectId !== "string" || !safeProjectId.test(body.projectId) || body.connectorId !== "chatgpt") {
    return json({ error: "invalid_request" }, 400);
  }
  if (!(await rateLimit(env.DB, "oauth_bridge_create", actor.userId, 20, 3600))) {
    return json({ error: "rate_limited" }, 429);
  }

  const rawToken = `ogt_${randomToken(32)}`;
  const tokenHash = await sha256Base64Url(rawToken);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + PAIRING_TTL_SECONDS;
  const result = await env.DB.prepare(
    `INSERT INTO oauth_bridge_grants (token_hash,user_id,project_id,browser_session_id,connector_id,provider,created_at,expires_at)
     SELECT ?,?,?,?, 'chatgpt','openai',?,?
     WHERE EXISTS (
       SELECT 1 FROM users u
       JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject AND a.revoked_at IS NULL
       JOIN sessions s ON s.user_id=u.id AND s.id=? AND s.kind='web' AND s.revoked_at IS NULL AND s.expires_at>?
       JOIN project_members pm ON pm.project_id=? AND pm.user_id=u.id
       JOIN projects p ON p.id=pm.project_id
       JOIN providers provider ON provider.provider='openai' AND provider.protocol='openai'
         AND provider.custom=0 AND provider.base_url='https://api.openai.com/v1/'
       WHERE u.id=? AND u.active=1
     )`,
  ).bind(tokenHash, actor.userId, body.projectId, actor.sessionId, now, expiresAt, actor.sessionId, now, body.projectId, actor.userId).run();
  if (!result.meta.changes) return forbidden();
  return json({ pairingToken: rawToken, expiresAt }, 201);
}

interface BridgeGrantRow {
  user_id: string;
  project_id: string;
  browser_session_id: string;
  connector_id: string;
  provider: string;
  expires_at: number;
  redeemed_at: number | null;
}

async function redeemPairingGrant(request: Request, env: Env): Promise<Response> {
  const validated = await machinePrincipal(request, env);
  if (!validated) return json({ error: "unauthorized" }, 401);
  if (!(await rateLimit(env.DB, "oauth_bridge_redeem", validated.principal.clientId, 30, 3600))) {
    return json({ error: "rate_limited" }, 429);
  }
  let body: Record<string, unknown>;
  try { body = await readJson(request, 2_048); }
  catch (error) { return json({ error: "invalid_request" }, error instanceof RequestBodyError ? error.status : 400); }
  if (!hasExactKeys(body, ["pairingToken"]) || typeof body.pairingToken !== "string" ||
      !/^ogt_[A-Za-z0-9_-]{43}$/.test(body.pairingToken)) return json({ error: "invalid_request" }, 400);

  const tokenHash = await sha256Base64Url(body.pairingToken);
  const now = Math.floor(Date.now() / 1000);
  const grant = await env.DB.prepare(
    "SELECT user_id,project_id,browser_session_id,connector_id,provider,expires_at,redeemed_at FROM oauth_bridge_grants WHERE token_hash=?",
  ).bind(tokenHash).first<BridgeGrantRow>();
  if (!grant || grant.redeemed_at !== null || grant.expires_at <= now) return json({ error: "grant_unavailable" }, 410);
  if (grant.user_id !== validated.principal.userId || grant.project_id !== validated.principal.projectId ||
      grant.connector_id !== "chatgpt" || grant.provider !== "openai") return forbidden();

  const auditId = `aud_${crypto.randomUUID()}`;
  const consumeNow = Math.floor(Date.now() / 1000);
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE oauth_bridge_grants SET redeemed_at=?
       WHERE token_hash=? AND user_id=? AND project_id=? AND connector_id='chatgpt' AND provider='openai'
         AND redeemed_at IS NULL AND expires_at>?
         AND EXISTS (
           SELECT 1 FROM users u
           JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject AND a.revoked_at IS NULL
           JOIN project_members pm ON pm.user_id=u.id AND pm.project_id=oauth_bridge_grants.project_id
           JOIN sessions s ON s.user_id=u.id AND s.id=? AND s.project_id=oauth_bridge_grants.project_id
             AND s.kind IN ('refresh','client_credentials') AND s.revoked_at IS NULL AND s.expires_at>?
           JOIN clients c ON c.id=s.client_id AND c.active=1 AND c.created_by=u.id
             AND c.project_id=s.project_id AND c.client_identifier=?
           WHERE u.id=? AND u.active=1
         )
         AND EXISTS (
           SELECT 1 FROM sessions web
           WHERE web.id=oauth_bridge_grants.browser_session_id AND web.user_id=oauth_bridge_grants.user_id
             AND web.kind='web'
             AND web.revoked_at IS NULL AND web.expires_at>?
         )`,
    ).bind(consumeNow, tokenHash, grant.user_id, grant.project_id, consumeNow,
      validated.principal.sessionId, consumeNow, validated.principal.clientId, validated.principal.userId, consumeNow),
    env.DB.prepare(
      `INSERT INTO audit_events (id,actor_user_id,action,target_type,target_id,details_json,created_at)
       SELECT ?,?,'oauth.local_pairing_redeemed','project',?,json_object('connectorId','chatgpt','provider','openai'),?
       WHERE changes()=1`,
    ).bind(auditId, grant.user_id, grant.project_id, consumeNow),
  ]);
  if (!results[0]?.meta.changes) {
    const refreshed = await env.DB.prepare("SELECT redeemed_at,expires_at FROM oauth_bridge_grants WHERE token_hash=?")
      .bind(tokenHash).first<{ redeemed_at: number | null; expires_at: number }>();
    if (!refreshed || refreshed.redeemed_at !== null || refreshed.expires_at <= Math.floor(Date.now() / 1000)) {
      return json({ error: "grant_unavailable" }, 410);
    }
    return forbidden();
  }
  return json({
    grant: {
      connectorId: grant.connector_id,
      provider: grant.provider,
      projectId: grant.project_id,
      expiresAt: grant.expires_at,
    },
  });
}

async function hasOpenAiModelGrant(
  env: Env,
  validated: NonNullable<Awaited<ReturnType<typeof machinePrincipal>>>,
  model: string,
  now: number,
): Promise<boolean> {
  const row = await env.DB.prepare(
    `SELECT 1 AS allowed
     FROM providers p
     JOIN provider_models pm ON pm.provider=p.provider AND pm.enabled=1
     JOIN project_permissions pp ON pp.provider=pm.provider AND pp.model=pm.alias
     JOIN client_permissions cp ON cp.provider=pm.provider AND cp.model=pm.alias
     JOIN clients c ON c.id=cp.client_id AND c.active=1
     JOIN sessions s ON s.client_id=c.id AND s.id=? AND s.user_id=? AND s.project_id=?
       AND s.revoked_at IS NULL AND s.expires_at>?
     JOIN users u ON u.id=s.user_id AND u.active=1
     JOIN user_allowlist ua ON ua.issuer=u.issuer AND ua.subject=u.subject AND ua.revoked_at IS NULL
     JOIN project_members member ON member.project_id=s.project_id AND member.user_id=u.id
     WHERE p.provider='openai' AND p.enabled=1 AND p.custom=0 AND p.protocol='openai'
       AND p.base_url='https://api.openai.com/v1/' AND pm.alias=?
       AND pp.project_id=s.project_id AND c.id=? AND c.project_id=s.project_id
       AND c.created_by=u.id AND c.client_identifier=?
       AND s.kind IN ('refresh','client_credentials')`,
  ).bind(
    validated.principal.sessionId,
    validated.principal.userId,
    validated.principal.projectId,
    now,
    model,
    validated.clientRowId,
    validated.principal.clientId,
  ).first<{ allowed: number }>();
  return Boolean(row?.allowed);
}

async function issueTokenEnvelope(request: Request, env: Env): Promise<Response> {
  const validated = await machinePrincipal(request, env);
  if (!validated) return json({ error: "unauthorized" }, 401);
  if (!isChatGptRemoteVerified(env)) return json({ error: "remote_inference_not_verified" }, 403);

  let body: Record<string, unknown>;
  try { body = await readJson(request, 12_288); }
  catch (error) { return json({ error: "invalid_request" }, error instanceof RequestBodyError ? error.status : 400); }
  if (!hasExactKeys(body, ["connectorId", "model", "accessToken", "expiresAt"]) ||
      body.connectorId !== "chatgpt" || typeof body.model !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.model) ||
      typeof body.accessToken !== "string" || body.accessToken.length < 1 ||
      body.accessToken.length > 8_192 || !bearerTokenPattern.test(body.accessToken) ||
      typeof body.expiresAt !== "number" ||
      !Number.isSafeInteger(body.expiresAt)) return json({ error: "invalid_request" }, 400);

  const accessToken = body.accessToken;
  const now = Math.floor(Date.now() / 1000);
  if (body.expiresAt <= now) {
    return json({ error: "invalid_provider_token" }, 400);
  }
  // The connector validates the provider response locally. Identity treats its expiry as a
  // declaration and applies a strict system maximum; it does not claim provider token validation.
  const expiresAt = Math.min(body.expiresAt, now + OAUTH_CREDENTIAL_MAX_TTL_SECONDS);
  if (expiresAt <= now) return json({ error: "invalid_provider_token" }, 400);
  if (!(await rateLimit(env.DB, "oauth_envelope_issue", validated.principal.clientId, 20, 3600, now))) {
    return json({ error: "rate_limited" }, 429);
  }
  if (!(await hasOpenAiModelGrant(env, validated, body.model, now))) return forbidden();

  const credentialId = newId("cred");
  const envelope = await createCredentialEnvelope(
    accessToken,
    { credentialId, userId: validated.principal.userId, projectId: validated.principal.projectId, provider: "openai", exp: expiresAt },
    env.ENVELOPE_KEYS,
  );
  body.accessToken = "";

  const commitNow = Math.floor(Date.now() / 1000);
  if (expiresAt <= commitNow) return json({ error: "invalid_provider_token" }, 400);
  const statements = [
    env.DB.prepare(
      `INSERT INTO credentials (id,user_id,project_id,provider,key_version,expires_at,created_at,credential_kind)
       SELECT ?,?,?,'openai',?,?,?,'oauth_access_token'
       WHERE ? > ? AND EXISTS (
         SELECT 1
         FROM providers p
         JOIN provider_models pm ON pm.provider=p.provider AND pm.enabled=1
         JOIN project_permissions pp ON pp.provider=pm.provider AND pp.model=pm.alias
         JOIN client_permissions cp ON cp.provider=pm.provider AND cp.model=pm.alias
         JOIN clients c ON c.id=cp.client_id AND c.active=1
         JOIN sessions s ON s.client_id=c.id AND s.id=? AND s.user_id=? AND s.project_id=?
           AND s.revoked_at IS NULL AND s.expires_at>?
         JOIN users u ON u.id=s.user_id AND u.active=1
         JOIN user_allowlist ua ON ua.issuer=u.issuer AND ua.subject=u.subject AND ua.revoked_at IS NULL
         JOIN project_members member ON member.project_id=s.project_id AND member.user_id=u.id
         WHERE p.provider='openai' AND p.enabled=1 AND p.custom=0 AND p.protocol='openai'
           AND p.base_url='https://api.openai.com/v1/' AND pm.alias=?
           AND pp.project_id=s.project_id AND c.id=? AND c.project_id=s.project_id
           AND c.created_by=u.id AND c.client_identifier=?
           AND s.kind IN ('refresh','client_credentials')
       )`,
    ).bind(
      credentialId,
      validated.principal.userId,
      validated.principal.projectId,
      envelope.kid,
      expiresAt,
      commitNow,
      expiresAt,
      commitNow,
      validated.principal.sessionId,
      validated.principal.userId,
      validated.principal.projectId,
      commitNow,
      body.model,
      validated.clientRowId,
      validated.principal.clientId,
    ),
    env.DB.prepare(
      `INSERT INTO audit_events (id,actor_user_id,action,target_type,target_id,details_json,created_at)
       SELECT ?,?,'credential.oauth_access_token_issued','credential',?,json_object('projectId',?,'provider','openai','model',?,'expiresAt',?),?
       WHERE changes()=1`,
    ).bind(`aud_${crypto.randomUUID()}`, validated.principal.userId, credentialId, validated.principal.projectId, body.model, expiresAt, commitNow),
  ];
  const results = await env.DB.batch(statements);
  if (!results[0]?.meta.changes) return forbidden();
  return json({ credentialId, provider: "openai", expiresAt, envelope }, 201);
}

export async function handleOAuthApi(request: Request, env: Env): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (!path.startsWith("/api/oauth/")) return null;
  if (path === "/api/oauth/connectors" && request.method === "GET") {
    const actor = await getWebActor(request, env);
    return actor ? connectorResponse(env) : json({ error: "unauthorized" }, 401);
  }
  if (path === "/api/oauth/pairing" && request.method === "POST") return createPairingGrant(request, env);
  if (path === "/api/oauth/pairing/redeem" && request.method === "POST") return redeemPairingGrant(request, env);
  if (path === "/api/oauth/token-envelope" && request.method === "POST") return issueTokenEnvelope(request, env);
  return json({ error: "not_found" }, 404);
}
