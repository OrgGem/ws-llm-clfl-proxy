import { ProviderEndpointSecurityError } from "@ws-proxy/shared";
import { createCredentialEnvelope, newId, randomToken, readJson, readTextBody, RequestBodyError, sha256Base64Url, constantTimeEqual, envelopeKeyVersions } from "./security.js";
import { insertAudit, rateLimit } from "./db.js";
import { assertBrowserWrite, forbidden, getWebActor, json, publicOrigin, sourceAddress, type WebActor } from "./http.js";
import { handleManagementApi } from "./management.js";
import { loadEffectiveOidcConfig, type SetupEnv } from "./bootstrap.js";
import { assertProviderBaseUrlPublic, isCanonicalBuiltinProvider, isCustomProviderId, normalizeAndCheckProviderBaseUrl, normalizeProviderBaseUrl } from "./provider-registry.js";

const SESSION_MAX_AGE = 12 * 60 * 60;
const REFRESH_MAX_AGE = 30 * 24 * 60 * 60;
const CREDENTIAL_TTL = 30 * 24 * 60 * 60;
const safeId = /^[A-Za-z0-9._:-]{1,128}$/;
const providerId = /^[a-z][a-z0-9_-]{0,31}$/;
const modelId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const upstreamModelId = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

interface ModelPermission {
  provider: string;
  model: string;
}

interface ProjectRoleRow { role: "owner" | "admin" | "member"; }

function text(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function parseModels(value: unknown): ModelPermission[] | null {
  if (!Array.isArray(value) || value.length > 128) return null;
  const models: ModelPermission[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    const model = item as Record<string, unknown>;
    if (!text(model.provider, 32) || !providerId.test(model.provider) || !text(model.model, 128) || !modelId.test(model.model)) return null;
    const key = `${model.provider}\n${model.model}`;
    if (seen.has(key)) continue;
    seen.add(key);
    models.push({ provider: model.provider, model: model.model });
  }
  return models;
}

async function projectRole(env: Env, actor: WebActor, projectId: string): Promise<ProjectRoleRow | null> {
  if (!safeId.test(projectId)) return null;
  return env.DB.prepare(
    `SELECT pm.role FROM project_members pm
     JOIN projects p ON p.id = pm.project_id
     WHERE pm.project_id = ? AND pm.user_id = ?`,
  ).bind(projectId, actor.userId).first<ProjectRoleRow>();
}

async function requireProjectWrite(env: Env, actor: WebActor, projectId: string): Promise<boolean> {
  const role = await projectRole(env, actor, projectId);
  return role?.role === "owner" || role?.role === "admin";
}

async function projectModels(env: Env, projectId: string): Promise<ModelPermission[]> {
  const { results } = await env.DB.prepare(
    "SELECT provider, model FROM project_permissions WHERE project_id = ? ORDER BY provider, model",
  ).bind(projectId).all<ModelPermission>();
  return results ?? [];
}

async function modelExists(env: Env, provider: string, alias: string): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT 1 AS found FROM providers p JOIN provider_models pm ON pm.provider = p.provider WHERE p.provider = ? AND pm.alias = ? AND p.enabled = 1 AND pm.enabled = 1",
  ).bind(provider, alias).first<{ found: number }>();
  return Boolean(row);
}

async function canUseProjectModel(env: Env, projectId: string, provider: string, model: string): Promise<boolean> {
  const row = await env.DB.prepare(
    `SELECT 1 AS found FROM providers p
     JOIN provider_models pm ON pm.provider = p.provider AND pm.enabled = 1
     JOIN project_permissions pp ON pp.provider = pm.provider AND pp.model = pm.alias
     WHERE p.provider = ? AND p.enabled = 1 AND pm.alias = ? AND pp.project_id = ?`,
  ).bind(provider, model, projectId).first<{ found: number }>();
  return Boolean(row);
}

async function userProjects(env: Env, actor: WebActor): Promise<Array<{ id: string; name: string; role: string }>> {
  const { results } = await env.DB.prepare(
    `SELECT p.id, p.name, pm.role FROM project_members pm JOIN projects p ON p.id = pm.project_id
     WHERE pm.user_id = ? ORDER BY p.created_at, p.name`,
  ).bind(actor.userId).all<{ id: string; name: string; role: string }>();
  return results ?? [];
}

export async function sessionResponse(request: Request, env: Env): Promise<Response> {
  let providers: Array<{ id: string; label: string }>;
  try {
    providers = (await loadEffectiveOidcConfig(env as SetupEnv)).providers.map(({ id, label }) => ({ id, label }));
  } catch {
    return json({ error: "configuration_unavailable" }, 503);
  }
  const actor = await getWebActor(request, env);
  if (!actor) return json({ authenticated: false, loginProviders: providers, authSetupRequired: providers.length === 0 });
  const projects = await userProjects(env, actor);
  const session = await env.DB.prepare(
    `SELECT id, kind, device_name AS deviceName, created_at AS createdAt, expires_at AS expiresAt, last_seen_at AS lastSeenAt
     FROM sessions WHERE id = ? AND revoked_at IS NULL`,
  ).bind(actor.sessionId).first<Record<string, unknown>>();
  return json({
    authenticated: true,
    user: { id: actor.userId, email: actor.email, displayName: actor.displayName, isAdmin: actor.isAdmin },
    projects,
    activeProjectId: projects[0]?.id ?? null,
    csrfToken: actor.csrfToken,
    session,
    loginProviders: providers,
  });
}

export async function handleBrowserApi(request: Request, env: Env): Promise<Response> {
  const actor = await getWebActor(request, env);
  if (!actor) return json({ error: "unauthorized" }, 401);
  const method = request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD" && !(await assertBrowserWrite(request, env, actor))) return forbidden();
  const managementResponse = await handleManagementApi(request, env, actor);
  if (managementResponse) return managementResponse;
  const url = new URL(request.url);
  let path: string;
  try { path = decodeURIComponent(url.pathname); } catch { return json({ error: "invalid_request" }, 400); }

  if (method === "GET" && path === "/api/dashboard") {
    const projectId = url.searchParams.get("projectId") ?? "";
    if (!(await projectRole(env, actor, projectId))) return forbidden();
    const [providers, credentials, clients, sessions] = await Promise.all([
      getProviders(env, projectId),
      env.DB.prepare("SELECT id, provider, key_version AS keyVersion, created_at AS createdAt, expires_at AS expiresAt, revoked_at AS revokedAt FROM credentials WHERE project_id = ? ORDER BY created_at DESC").bind(projectId).all<Record<string, unknown>>(),
      env.DB.prepare("SELECT COUNT(*) AS count FROM clients WHERE project_id = ? AND active = 1").bind(projectId).first<{ count: number }>(),
      env.DB.prepare("SELECT COUNT(*) AS count FROM sessions s JOIN clients c ON c.id = s.client_id WHERE s.project_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND c.active = 1").bind(projectId, Math.floor(Date.now() / 1000)).first<{ count: number }>(),
    ]);
    return json({
      summary: { activeClients: clients?.count ?? 0, activeSessions: sessions?.count ?? 0 },
      providers,
      credentials: credentials.results ?? [],
    });
  }

  if (method === "GET" && path === "/api/clients") {
    const projectId = url.searchParams.get("projectId") ?? "";
    if (!(await projectRole(env, actor, projectId))) return forbidden();
    const [clients, models] = await Promise.all([
      env.DB.prepare("SELECT id, client_identifier AS clientIdentifier, created_by AS createdBy, name, kind, active, created_at AS createdAt, rotated_at AS rotatedAt FROM clients WHERE project_id = ? ORDER BY created_at DESC").bind(projectId).all<Record<string, unknown>>(),
      getModelCatalog(env),
    ]);
    const clientList = await Promise.all((clients.results ?? []).map(async (client) => ({
      ...client,
      canManage: client.createdBy === actor.userId,
      models: await clientModels(env, String(client.id)),
    })));
    return json({ clients: clientList, models });
  }

  if (method === "POST" && path === "/api/clients") {
    const body = await readJson(request);
    const projectId = body.projectId;
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const kind = body.kind === "confidential" || body.kind === "public" ? body.kind : null;
    const models = parseModels(body.models);
    if (!text(projectId, 128) || !safeId.test(projectId) || !text(name, 80) || name.trim() !== name || !kind || !models) return json({ error: "invalid_request" }, 400);
    if (kind === "public") return json({ error: "pairing_required" }, 400);
    if (!(await requireProjectWrite(env, actor, projectId))) return forbidden();
    if (!(await rateLimit(env.DB, "client_create", actor.userId, 30, 3600))) return json({ error: "rate_limited" }, 429);
    const clientRowId = newId("client");
    const clientIdentifier = newId("cli");
    const secret = kind === "confidential" ? `csec-${randomToken(32)}` : null;
    const secretHash = secret ? await sha256Base64Url(secret) : null;
    const now = Math.floor(Date.now() / 1000);
    const statements = [env.DB.prepare(
      "INSERT INTO clients (id, client_identifier, project_id, created_by, name, kind, secret_hash, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
    ).bind(clientRowId, clientIdentifier, projectId, actor.userId, name, kind, secretHash, now)];
    for (const model of models) {
      if (!(await modelExists(env, model.provider, model.model))) return json({ error: "invalid_model" }, 400);
      statements.push(env.DB.prepare(
        "INSERT INTO client_permissions (client_id, provider, model, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
      ).bind(clientRowId, model.provider, model.model, actor.userId, now));
    }
    await env.DB.batch(statements);
    await insertAudit(env.DB, actor.userId, "client.created", "client", clientRowId, { kind, projectId });
    return json({ client: { id: clientRowId, clientIdentifier, name, kind, active: true, models }, ...(secret ? { clientSecret: secret } : {}) }, 201);
  }

  const clientMatch = path.match(/^\/api\/clients\/([A-Za-z0-9._:-]{1,128})(?:\/(models|rotate|revoke))?$/);
  if (clientMatch) {
    const id = clientMatch[1]!;
    const action = clientMatch[2];
    const client = await env.DB.prepare("SELECT id, project_id, name, kind, active FROM clients WHERE id = ?").bind(id).first<{ id: string; project_id: string; name: string; kind: string; active: number }>();
    if (!client) return json({ error: "not_found" }, 404);
    if (!(await requireProjectWrite(env, actor, client.project_id))) return forbidden();
    if (action === "models" && method === "PUT") {
      const owner = await env.DB.prepare("SELECT created_by FROM clients WHERE id=?").bind(id).first<{ created_by: string }>();
      if (owner?.created_by !== actor.userId) return forbidden();
      const body = await readJson(request);
      const models = parseModels(body.models);
      if (!models) return json({ error: "invalid_request" }, 400);
      for (const model of models) if (!(await modelExists(env, model.provider, model.model))) return json({ error: "invalid_model" }, 400);
      const now = Math.floor(Date.now() / 1000);
      const statements = [env.DB.prepare("DELETE FROM client_permissions WHERE client_id = ?").bind(id)];
      for (const model of models) statements.push(env.DB.prepare("INSERT INTO client_permissions (client_id, provider, model, created_by, created_at) VALUES (?, ?, ?, ?, ?)").bind(id, model.provider, model.model, actor.userId, now));
      await env.DB.batch(statements);
      await insertAudit(env.DB, actor.userId, "client.permissions_updated", "client", id, { models: models.length });
      return json({ ok: true, models });
    }
    if (action === "rotate" && method === "POST") {
      if (client.kind !== "confidential") return json({ error: "invalid_client_type" }, 400);
      const owner = await env.DB.prepare("SELECT created_by FROM clients WHERE id=?").bind(id).first<{ created_by: string }>();
      if (owner?.created_by !== actor.userId) return forbidden();
      if (client.active !== 1) return json({ error: "client_inactive" }, 409);
      const secret = `csec-${randomToken(32)}`;
      const now = Math.floor(Date.now() / 1000);
      const secretHash = await sha256Base64Url(secret);
      const results = await env.DB.batch([
        env.DB.prepare("UPDATE clients SET secret_hash = ?, rotated_at = ? WHERE id = ? AND active = 1").bind(secretHash, now, id),
        env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM clients WHERE id = ? AND active = 1 AND secret_hash = ?)").bind(now, id, id, secretHash),
      ]);
      if (!results[0]?.meta.changes) return json({ error: "client_inactive" }, 409);
      await insertAudit(env.DB, actor.userId, "client.secret_rotated", "client", id);
      return json({ clientSecret: secret });
    }
    if (action === "revoke" && method === "POST") {
      const now = Math.floor(Date.now() / 1000);
      await env.DB.batch([
        env.DB.prepare("UPDATE clients SET active = 0 WHERE id = ?").bind(id),
        env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL").bind(now, id),
      ]);
      await insertAudit(env.DB, actor.userId, "client.revoked", "client", id);
      return json({ ok: true });
    }
  }

  if (method === "GET" && path === "/api/providers") {
    const projectId = url.searchParams.get("projectId") ?? "";
    if (!(await projectRole(env, actor, projectId))) return forbidden();
    const [providers, credentials] = await Promise.all([
      getProviders(env, projectId),
      env.DB.prepare("SELECT id, provider, key_version AS keyVersion, created_at AS createdAt, expires_at AS expiresAt, revoked_at AS revokedAt FROM credentials WHERE project_id = ? ORDER BY created_at DESC").bind(projectId).all<Record<string, unknown>>(),
    ]);
    return json({ providers, credentials: credentials.results ?? [] });
  }

  if (method === "POST" && path === "/api/providers") {
    if (!actor.isAdmin) return forbidden();
    if (!(await rateLimit(env.DB, "provider_registry_create", actor.userId, 10, 60))) return json({ error: "rate_limited" }, 429);
    const body = await readJson(request, 8_192);
    const fields = Object.keys(body);
    if (fields.length !== 4 || !["id", "displayName", "baseUrl", "protocol"].every((field) => fields.includes(field)) ||
        !text(body.id, 32) || !providerId.test(body.id) || !text(body.displayName, 80) || body.displayName.trim() !== body.displayName || /[\u0000-\u001f\u007f]/.test(body.displayName) ||
        typeof body.baseUrl !== "string" || body.baseUrl.length < 1 || body.baseUrl.length > 2_048 || body.baseUrl.trim() !== body.baseUrl || body.protocol !== "openai") {
      return json({ error: "invalid_request" }, 400);
    }
    const alreadyRegistered = await env.DB.prepare("SELECT 1 AS found FROM providers WHERE provider=?")
      .bind(body.id).first<{ found: number }>();
    if (alreadyRegistered) return json({ error: "provider_exists" }, 409);

    let baseUrl: string;
    try {
      baseUrl = await normalizeAndCheckProviderBaseUrl(env, body.baseUrl);
    } catch (error) {
      return json({ error: "endpoint_not_allowed", ...(error instanceof ProviderEndpointSecurityError ? { reason: error.code, stage: error.stage } : {}) }, 400);
    }

    const now = Math.floor(Date.now() / 1000);
    const inserted = await env.DB.prepare(
      `INSERT INTO providers(provider,display_name,enabled,protocol,base_url,custom)
       SELECT ?,?,1,'openai',?,1
       WHERE EXISTS (
         SELECT 1 FROM users u
         JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject
         JOIN sessions s ON s.user_id=u.id
         WHERE u.id=? AND u.active=1 AND a.is_admin=1 AND a.revoked_at IS NULL
           AND s.id=? AND s.kind='web' AND s.revoked_at IS NULL AND s.expires_at>?
       ) AND (SELECT COUNT(*) FROM providers WHERE custom=1)<128
       ON CONFLICT(provider) DO NOTHING
       RETURNING provider,display_name,protocol,base_url,custom,enabled`,
    ).bind(body.id, body.displayName, baseUrl, actor.userId, actor.sessionId, now)
      .first<{ provider: string; display_name: string; protocol: "openai" | "anthropic"; base_url: string; custom: number; enabled: number }>();
    if (!inserted) {
      const existing = await env.DB.prepare("SELECT 1 AS found FROM providers WHERE provider=?").bind(body.id).first<{ found: number }>();
      if (existing) return json({ error: "provider_exists" }, 409);
      const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM providers WHERE custom=1").first<{ count: number }>();
      if ((count?.count ?? 0) >= 128) return json({ error: "provider_limit_reached" }, 409);
      return forbidden();
    }
    await insertAudit(env.DB, actor.userId, "provider.created", "provider", inserted.provider, { protocol: inserted.protocol });
    return json({ provider: {
      id: inserted.provider,
      displayName: inserted.display_name,
      baseUrl: inserted.base_url,
      protocol: inserted.protocol,
      custom: inserted.custom === 1,
      enabled: inserted.enabled === 1,
    } }, 201);
  }

  const providerMatch = path.match(/^\/api\/providers\/([a-z][a-z0-9_-]{0,31})$/);
  if (providerMatch && method === "PUT") {
    if (!actor.isAdmin) return forbidden();
    if (!(await rateLimit(env.DB, "provider_registry_update", actor.userId, 10, 60))) return json({ error: "rate_limited" }, 429);
    const body = await readJson(request, 8_192);
    const fields = Object.keys(body);
    const enabledUpdate = fields.length === 1 && fields[0] === "enabled" && typeof body.enabled === "boolean";
    const baseUrlUpdate = fields.length === 2 && fields.includes("baseUrl") && fields.includes("expectedBaseUrl") &&
      typeof body.baseUrl === "string" && typeof body.expectedBaseUrl === "string" &&
      body.baseUrl.length > 0 && body.baseUrl.length <= 2_048 && body.baseUrl.trim() === body.baseUrl &&
      body.expectedBaseUrl.length > 0 && body.expectedBaseUrl.length <= 2_048 && body.expectedBaseUrl.trim() === body.expectedBaseUrl;
    if (!enabledUpdate && !baseUrlUpdate) return json({ error: "invalid_request" }, 400);
    const existingProvider = await env.DB.prepare(
      "SELECT enabled,protocol,base_url AS baseUrl,custom,display_name AS displayName FROM providers WHERE provider=?",
    ).bind(providerMatch[1]!).first<{ enabled: number; protocol: "openai" | "anthropic"; baseUrl: string; custom: number; displayName: string }>();
    if (!existingProvider) return json({ error: "not_found" }, 404);
    if ((existingProvider.protocol !== "openai" && existingProvider.protocol !== "anthropic") ||
        !(isCanonicalBuiltinProvider(providerMatch[1]!, existingProvider.protocol, existingProvider.baseUrl, existingProvider.custom) ||
          isCustomProviderId(providerMatch[1]!, existingProvider.custom))) return forbidden();

    if (baseUrlUpdate) {
      if (!isCustomProviderId(providerMatch[1]!, existingProvider.custom)) return forbidden();
      let expectedBaseUrl: string;
      try {
        expectedBaseUrl = normalizeProviderBaseUrl(env, body.expectedBaseUrl as string);
      } catch {
        return json({ error: "invalid_request" }, 400);
      }
      if (expectedBaseUrl !== existingProvider.baseUrl) return json({ error: "provider_conflict" }, 409);

      let nextBaseUrl: string;
      try {
        nextBaseUrl = normalizeProviderBaseUrl(env, body.baseUrl as string);
      } catch (error) {
        return json({ error: "endpoint_not_allowed", ...(error instanceof ProviderEndpointSecurityError ? { reason: error.code, stage: error.stage } : {}) }, 400);
      }

      const currentProvider = {
        id: providerMatch[1]!,
        displayName: existingProvider.displayName,
        baseUrl: existingProvider.baseUrl,
        protocol: existingProvider.protocol,
        custom: true,
        enabled: existingProvider.enabled === 1,
      };
      if (nextBaseUrl === expectedBaseUrl) {
        const liveAdmin = await env.DB.prepare(
          `SELECT 1 AS allowed FROM users u
           JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject
           JOIN sessions s ON s.user_id=u.id
           WHERE u.id=? AND u.active=1 AND a.is_admin=1 AND a.revoked_at IS NULL
             AND s.id=? AND s.kind='web' AND s.revoked_at IS NULL AND s.expires_at>?`,
        ).bind(actor.userId, actor.sessionId, Math.floor(Date.now() / 1000)).first<{ allowed: number }>();
        if (!liveAdmin) return forbidden();
        const latest = await env.DB.prepare(
          "SELECT display_name AS displayName,base_url AS baseUrl,enabled FROM providers WHERE provider=? AND custom=1 AND protocol=?",
        ).bind(providerMatch[1]!, existingProvider.protocol).first<{ displayName: string; baseUrl: string; enabled: number }>();
        if (!latest) return json({ error: "not_found" }, 404);
        if (latest.baseUrl !== expectedBaseUrl) return json({ error: "provider_conflict" }, 409);
        return json({ provider: { ...currentProvider, displayName: latest.displayName, baseUrl: latest.baseUrl, enabled: latest.enabled === 1 }, revokedCredentialCount: 0 });
      }

      try {
        await assertProviderBaseUrlPublic(nextBaseUrl);
      } catch (error) {
        return json({ error: "endpoint_not_allowed", ...(error instanceof ProviderEndpointSecurityError ? { reason: error.code, stage: error.stage } : {}) }, 400);
      }

      const oldOrigin = new URL(expectedBaseUrl).origin;
      const newOrigin = new URL(nextBaseUrl).origin;
      const originChanged = oldOrigin !== newOrigin;
      const now = Math.floor(Date.now() / 1000);
      const statements = [
        env.DB.prepare(
          `UPDATE providers SET base_url=? WHERE provider=? AND custom=1 AND protocol=? AND base_url=? AND EXISTS (
            SELECT 1 FROM users u
            JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject
            JOIN sessions s ON s.user_id=u.id
            WHERE u.id=? AND u.active=1 AND a.is_admin=1 AND a.revoked_at IS NULL
              AND s.id=? AND s.kind='web' AND s.revoked_at IS NULL AND s.expires_at>?
          )`,
        ).bind(nextBaseUrl, providerMatch[1]!, existingProvider.protocol, expectedBaseUrl, actor.userId, actor.sessionId, now),
        env.DB.prepare(
          `INSERT INTO audit_events (id,actor_user_id,action,target_type,target_id,details_json,created_at)
           SELECT ?,?,'provider.base_url_updated','provider',?,json_object(
             'oldBaseUrl',?,'newBaseUrl',?,'originChanged',json(?),
             'revokedCredentialCount',CASE WHEN ?=1 THEN (SELECT COUNT(*) FROM credentials WHERE provider=? AND revoked_at IS NULL) ELSE 0 END
           ),? WHERE changes()=1`,
        ).bind(`aud_${crypto.randomUUID()}`, actor.userId, providerMatch[1]!, expectedBaseUrl, nextBaseUrl, originChanged ? "true" : "false", originChanged ? 1 : 0, providerMatch[1]!, now),
      ];
      if (originChanged) {
        statements.push(env.DB.prepare(
          "UPDATE credentials SET revoked_at=? WHERE provider=? AND revoked_at IS NULL AND changes()=1",
        ).bind(now, providerMatch[1]!));
      }
      const results = await env.DB.batch(statements);
      if (!results[0]?.meta.changes) {
        const latest = await env.DB.prepare("SELECT base_url AS baseUrl FROM providers WHERE provider=?").bind(providerMatch[1]!).first<{ baseUrl: string }>();
        if (!latest) return json({ error: "not_found" }, 404);
        if (latest.baseUrl !== expectedBaseUrl) return json({ error: "provider_conflict" }, 409);
        return forbidden();
      }
      return json({
        provider: {
          id: providerMatch[1]!,
          displayName: existingProvider.displayName,
          baseUrl: nextBaseUrl,
          protocol: existingProvider.protocol,
          custom: true,
          enabled: existingProvider.enabled === 1,
        },
        revokedCredentialCount: originChanged ? (results[2]?.meta.changes ?? 0) : 0,
      });
    }

    if (body.enabled === true && existingProvider.custom === 1) {
      try {
        const normalized = normalizeProviderBaseUrl(env, existingProvider.baseUrl);
        if (normalized !== existingProvider.baseUrl) return json({ error: "endpoint_not_allowed" }, 400);
        await assertProviderBaseUrlPublic(normalized);
      } catch (error) {
        return json({ error: "endpoint_not_allowed", ...(error instanceof ProviderEndpointSecurityError ? { reason: error.code, stage: error.stage } : {}) }, 400);
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const updated = await env.DB.prepare(
      `UPDATE providers SET enabled=? WHERE provider=? AND (
        (custom=1 AND provider NOT IN ('openai','anthropic')) OR
        (custom=0 AND (
          (provider='openai' AND protocol='openai' AND base_url='https://api.openai.com/v1/') OR
          (provider='anthropic' AND protocol='anthropic' AND base_url='https://api.anthropic.com/v1/')
        ))
      ) AND protocol=? AND base_url=? AND custom=? AND EXISTS (
        SELECT 1 FROM users u
        JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject
        JOIN sessions s ON s.user_id=u.id
        WHERE u.id=? AND u.active=1 AND a.is_admin=1 AND a.revoked_at IS NULL
          AND s.id=? AND s.kind='web' AND s.revoked_at IS NULL AND s.expires_at>?
      ) RETURNING provider,display_name,enabled,protocol,base_url,custom`,
    ).bind(body.enabled === true ? 1 : 0, providerMatch[1]!, existingProvider.protocol, existingProvider.baseUrl, existingProvider.custom, actor.userId, actor.sessionId, now)
      .first<{ provider: string; display_name: string; enabled: number; protocol: "openai" | "anthropic"; base_url: string; custom: number }>();
    if (!updated) {
      const exists = await env.DB.prepare("SELECT 1 AS found FROM providers WHERE provider=?").bind(providerMatch[1]!).first<{ found: number }>();
      return exists ? forbidden() : json({ error: "not_found" }, 404);
    }
    await insertAudit(env.DB, actor.userId, updated.enabled ? "provider.enabled" : "provider.disabled", "provider", updated.provider);
    return json({ provider: {
      id: updated.provider,
      displayName: updated.display_name,
      baseUrl: updated.base_url,
      protocol: updated.protocol,
      custom: updated.custom === 1,
      enabled: updated.enabled === 1,
    } });
  }

  if (method === "POST" && path === "/api/credentials") {
    const body = await readJson(request, 16_384);
    const projectId = body.projectId;
    const provider = body.provider;
    let apiKey = body.apiKey;
    if (!text(projectId, 128) || !safeId.test(projectId) || !text(provider, 32) || !providerId.test(provider) || typeof apiKey !== "string" || apiKey.length < 1 || new TextEncoder().encode(apiKey).byteLength > 8_192) return json({ error: "invalid_request" }, 400);
    if (!(await requireProjectWrite(env, actor, projectId))) return forbidden();
    const activeProvider = await env.DB.prepare("SELECT provider,protocol,base_url AS baseUrl,custom FROM providers WHERE provider = ? AND enabled = 1")
      .bind(provider).first<{ provider: string; protocol: string; baseUrl: string; custom: number }>();
    if (!activeProvider) return json({ error: "provider_disallowed" }, 400);
    if (activeProvider.custom === 1) {
      if (typeof body.expectedBaseUrl !== "string" || body.expectedBaseUrl.length < 1 || body.expectedBaseUrl.length > 2_048 || body.expectedBaseUrl.trim() !== body.expectedBaseUrl) {
        return json({ error: "provider_conflict" }, 409);
      }
      let expectedBaseUrl: string;
      try {
        expectedBaseUrl = normalizeProviderBaseUrl(env, body.expectedBaseUrl);
      } catch {
        return json({ error: "provider_conflict" }, 409);
      }
      if (expectedBaseUrl !== activeProvider.baseUrl) return json({ error: "provider_conflict" }, 409);
    }
    if (!(await rateLimit(env.DB, "credential_create", actor.userId, 20, 3600))) return json({ error: "rate_limited" }, 429);
    const credentialId = newId("cred");
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + CREDENTIAL_TTL;
    const envelope = await createCredentialEnvelope(apiKey, { credentialId, userId: actor.userId, projectId, provider, exp: expiresAt }, env.ENVELOPE_KEYS);
    apiKey = "";
    body.apiKey = "";
    const inserted = await env.DB.prepare(
      `INSERT INTO credentials (id,user_id,project_id,provider,key_version,expires_at,created_at)
       SELECT ?,?,?,?,?,?,? WHERE EXISTS (
         SELECT 1 FROM providers WHERE provider=? AND enabled=1 AND protocol=? AND base_url=?
       )`,
    ).bind(credentialId, actor.userId, projectId, provider, envelope.kid, expiresAt, now, provider, activeProvider.protocol, activeProvider.baseUrl).run();
    apiKey = "";
    body.apiKey = "";
    if (!inserted.meta.changes) return json({ error: "provider_conflict" }, 409);
    await insertAudit(env.DB, actor.userId, "credential.created", "credential", credentialId, { projectId, provider, keyVersion: envelope.kid });
    return json({ credential: { id: credentialId, provider, keyVersion: envelope.kid, expiresAt }, envelope }, 201);
  }

  const credentialMatch = path.match(/^\/api\/credentials\/([A-Za-z0-9._:-]{1,128})\/revoke$/);
  if (credentialMatch && method === "POST") {
    const id = credentialMatch[1]!;
    const row = await env.DB.prepare("SELECT project_id, user_id FROM credentials WHERE id = ?").bind(id).first<{ project_id: string; user_id: string }>();
    if (!row) return json({ error: "not_found" }, 404);
    if (!(await requireProjectWrite(env, actor, row.project_id))) return forbidden();
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare("UPDATE credentials SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?").bind(now, id).run();
    await insertAudit(env.DB, actor.userId, "credential.revoked", "credential", id, { providerOwner: row.user_id });
    return json({ ok: true });
  }

  if (method === "POST" && path === "/api/permissions") {
    const body = await readJson(request);
    if (!text(body.projectId, 128) || !safeId.test(body.projectId) || !text(body.provider, 32) || !providerId.test(body.provider) || !text(body.model, 128) || !modelId.test(body.model) || typeof body.allowed !== "boolean") return json({ error: "invalid_request" }, 400);
    if (!(await requireProjectWrite(env, actor, body.projectId))) return forbidden();
    if (!(await modelExists(env, body.provider, body.model))) return json({ error: "invalid_model" }, 400);
    if (body.allowed) {
      await env.DB.prepare("INSERT OR IGNORE INTO project_permissions (project_id, provider, model, created_by, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(body.projectId, body.provider, body.model, actor.userId, Math.floor(Date.now() / 1000)).run();
    } else {
      await env.DB.prepare("DELETE FROM project_permissions WHERE project_id = ? AND provider = ? AND model = ?")
        .bind(body.projectId, body.provider, body.model).run();
    }
    await insertAudit(env.DB, actor.userId, body.allowed ? "project.model_allowed" : "project.model_revoked", "project", body.projectId, { provider: body.provider, model: body.model });
    return json({ ok: true });
  }

  if (method === "POST" && path === "/api/providers/models") {
    const body = await readJson(request);
    if (!text(body.provider, 32) || !providerId.test(body.provider) || !text(body.alias, 128) || !modelId.test(body.alias) || !text(body.upstreamModel, 128) || !upstreamModelId.test(body.upstreamModel) || !text(body.displayName, 128)) return json({ error: "invalid_request" }, 400);
    const provider = await env.DB.prepare("SELECT provider FROM providers WHERE provider = ? AND enabled = 1").bind(body.provider).first<{ provider: string }>();
    if (!provider) return json({ error: "provider_disallowed" }, 400);
    const { results: projects } = await env.DB.prepare("SELECT project_id FROM project_members WHERE user_id = ? AND role IN ('owner','admin')").bind(actor.userId).all<{ project_id: string }>();
    if (!projects?.length && !actor.isAdmin) return forbidden();
    if (actor.isAdmin) {
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare("INSERT INTO provider_models (provider, alias, upstream_model, display_name, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT(provider,alias) DO UPDATE SET upstream_model=excluded.upstream_model, display_name=excluded.display_name, enabled=1")
        .bind(body.provider, body.alias, body.upstreamModel, body.displayName, now).run();
      await insertAudit(env.DB, actor.userId, "provider.model_added", "provider_model", `${body.provider}:${body.alias}`);
      return json({ ok: true }, 201);
    }
    return forbidden();
  }

  if (method === "GET" && path === "/api/sessions") {
    const { results } = await env.DB.prepare(
      `SELECT s.id, s.kind, s.device_name AS deviceName, s.created_at AS createdAt, s.expires_at AS expiresAt,
              s.last_seen_at AS lastSeenAt, s.revoked_at AS revokedAt, c.name AS clientName
       FROM sessions s LEFT JOIN clients c ON c.id = s.client_id
       WHERE s.user_id = ? ORDER BY s.created_at DESC LIMIT 100`,
    ).bind(actor.userId).all<Record<string, unknown>>();
    return json({ sessions: results ?? [] });
  }

  const sessionMatch = path.match(/^\/api\/sessions\/([A-Za-z0-9._:-]{1,128})\/revoke$/);
  if (sessionMatch && method === "POST") {
    const id = sessionMatch[1]!;
    const result = await env.DB.prepare("UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND user_id = ?")
      .bind(Math.floor(Date.now() / 1000), id, actor.userId).run();
    if (!result.meta.changes) return json({ error: "not_found" }, 404);
    await insertAudit(env.DB, actor.userId, "session.revoked", "session", id);
    return json({ ok: true });
  }

  if (method === "GET" && path === "/api/pairing/lookup") {
    const userCode = normalizeUserCode(url.searchParams.get("userCode") ?? "");
    if (!userCode || !(await rateLimit(env.DB, "pair_lookup", sourceAddress(request), 30, 60))) return json({ error: "not_found" }, 404);
    const userCodeHash = await sha256Base64Url(userCode);
    const row = await env.DB.prepare("SELECT id, client_name, created_at, expires_at, status FROM pairing_requests WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ?")
      .bind(userCodeHash, Math.floor(Date.now() / 1000)).first<{ id: string; client_name: string; created_at: number; expires_at: number; status: string }>();
    if (!row) return json({ error: "not_found" }, 404);
    return json({ pairing: { id: row.id, clientName: row.client_name, createdAt: row.created_at, expiresAt: row.expires_at, status: row.status } });
  }

  if (method === "POST" && (path === "/api/pairing/approve" || path === "/api/pairing/deny")) {
    if (!(await rateLimit(env.DB, "pair_action", `${actor.userId}:${sourceAddress(request)}`, 10, 60))) return json({ error: "rate_limited" }, 429);
    const body = await readJson(request);
    const userCode = normalizeUserCode(typeof body.userCode === "string" ? body.userCode : "");
    if (!userCode) return json({ error: "invalid_request" }, 400);
    const pair = await env.DB.prepare("SELECT id, client_name, expires_at FROM pairing_requests WHERE user_code_hash = ? AND status = 'pending' AND expires_at > ?")
      .bind(await sha256Base64Url(userCode), Math.floor(Date.now() / 1000)).first<{ id: string; client_name: string; expires_at: number }>();
    if (!pair) return json({ error: "not_found" }, 404);
    if (path.endsWith("/deny")) {
      const updated = await env.DB.prepare("UPDATE pairing_requests SET status = 'denied', user_id = ? WHERE id = ? AND status = 'pending'")
        .bind(actor.userId, pair.id).run();
      if (!updated.meta.changes) return json({ error: "conflict" }, 409);
      await insertAudit(env.DB, actor.userId, "pairing.denied", "pairing", pair.id);
      return json({ ok: true });
    }
    const projectId = body.projectId;
    const models = parseModels(body.models);
    if (!text(projectId, 128) || !safeId.test(projectId) || !models) return json({ error: "invalid_request" }, 400);
    if (!(await requireProjectWrite(env, actor, projectId))) return forbidden();
    for (const model of models) if (!(await canUseProjectModel(env, projectId, model.provider, model.model))) return json({ error: "model_disallowed" }, 400);
    const clientRowId = newId("client");
    const clientIdentifier = newId("cli");
    const now = Math.floor(Date.now() / 1000);
    const statements = [
      env.DB.prepare("INSERT INTO clients (id, client_identifier, project_id, created_by, name, kind, secret_hash, active, created_at) SELECT ?, ?, ?, ?, ?, 'public', NULL, 1, ? WHERE EXISTS (SELECT 1 FROM pairing_requests WHERE id=? AND status='pending' AND expires_at > ?)")
        .bind(clientRowId, clientIdentifier, projectId, actor.userId, pair.client_name, now, pair.id, now),
      env.DB.prepare("UPDATE pairing_requests SET status='approved', user_id=?, project_id=?, client_id=? WHERE id=? AND status='pending' AND expires_at > ? AND EXISTS (SELECT 1 FROM clients WHERE id=? AND client_identifier=?)")
        .bind(actor.userId, projectId, clientRowId, pair.id, now, clientRowId, clientIdentifier),
    ];
    for (const model of models) statements.push(env.DB.prepare(
      "INSERT INTO client_permissions (client_id, provider, model, created_by, created_at) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM clients WHERE id=?)",
    ).bind(clientRowId, model.provider, model.model, actor.userId, now, clientRowId));
    const result = await env.DB.batch(statements);
    if (!(result[1]?.meta.changes)) return json({ error: "conflict" }, 409);
    await insertAudit(env.DB, actor.userId, "pairing.approved", "pairing", pair.id, { projectId, clientId: clientIdentifier, modelCount: models.length });
    return json({ ok: true });
  }

  if (method === "GET" && path === "/api/security") {
    if (!actor.isAdmin) return forbidden();
    const [pending, allowlisted, audit] = await Promise.all([
      env.DB.prepare("SELECT issuer, subject, email, display_name AS displayName, first_seen_at AS firstSeenAt, last_seen_at AS lastSeenAt FROM pending_identities ORDER BY last_seen_at DESC LIMIT 100").all<Record<string, unknown>>(),
      env.DB.prepare("SELECT ua.issuer, ua.subject, ua.email, ua.is_admin AS isAdmin, ua.approved_at AS approvedAt, ua.revoked_at AS revokedAt, u.display_name AS displayName FROM user_allowlist ua LEFT JOIN users u ON u.issuer=ua.issuer AND u.subject=ua.subject ORDER BY ua.created_at DESC LIMIT 200").all<Record<string, unknown>>(),
      env.DB.prepare("SELECT a.action, a.target_type AS targetType, a.target_id AS targetId, a.created_at AS createdAt, a.actor_user_id AS actorUserId, u.email AS actorEmail FROM audit_events a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 100").all<Record<string, unknown>>(),
    ]);
    const keys = envelopeKeyVersions(env.ENVELOPE_KEYS);
    const jwks = JSON.parse(env.MACHINE_JWT_PUBLIC_JWKS) as { keys?: Array<{ kid?: string }> };
    let currentKid: string | null = null;
    try {
      const privateJwk = env.MACHINE_JWT_PRIVATE_JWK ? JSON.parse(env.MACHINE_JWT_PRIVATE_JWK) as { kid?: unknown } : {};
      if (typeof privateJwk.kid === "string") currentKid = privateJwk.kid;
    } catch {
      currentKid = null;
    }
    return json({
      identity: { issuer: env.MACHINE_ISSUER },
      keyVersions: (jwks.keys ?? []).filter((key) => typeof key.kid === "string").map((key) => ({ kid: key.kid, active: key.kid === currentKid })),
      envelopeKeyVersions: keys,
      pendingIdentities: pending.results ?? [],
      allowlistedUsers: allowlisted.results ?? [],
      audit: audit.results ?? [],
    });
  }

  if (method === "POST" && path === "/api/security/approve") {
    if (!actor.isAdmin) return forbidden();
    const body = await readJson(request);
    if (!text(body.issuer, 1024) || !text(body.subject, 512) || typeof body.isAdmin !== "boolean") return json({ error: "invalid_request" }, 400);
    const pending = await env.DB.prepare("SELECT email FROM pending_identities WHERE issuer=? AND subject=?")
      .bind(body.issuer, body.subject).first<{ email: string }>();
    if (!pending) return json({ error: "not_found" }, 404);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO user_allowlist (issuer,subject,email,is_admin,approved_at,created_by,created_at,revoked_at) VALUES (?,?,?,?,?,?,?,NULL) ON CONFLICT(issuer,subject) DO UPDATE SET email=excluded.email,is_admin=excluded.is_admin,approved_at=excluded.approved_at,created_by=excluded.created_by,revoked_at=NULL")
        .bind(body.issuer, body.subject, pending.email, body.isAdmin ? 1 : 0, now, actor.userId, now),
      env.DB.prepare("UPDATE users SET active=1, email=?, updated_at=? WHERE issuer=? AND subject=?")
        .bind(pending.email, now, body.issuer, body.subject),
      env.DB.prepare("DELETE FROM pending_identities WHERE issuer=? AND subject=?").bind(body.issuer, body.subject),
    ]);
    await insertAudit(env.DB, actor.userId, "identity.approved", "identity", `${body.issuer}|${body.subject}`, { isAdmin: body.isAdmin });
    return json({ ok: true });
  }

  if (method === "POST" && path === "/api/security/revoke") {
    if (!actor.isAdmin) return forbidden();
    const body = await readJson(request);
    if (!text(body.issuer, 1024) || !text(body.subject, 512)) return json({ error: "invalid_request" }, 400);
    const now = Math.floor(Date.now() / 1000);
    const results = await env.DB.batch([
      env.DB.prepare(`UPDATE user_allowlist SET revoked_at=? WHERE issuer=? AND subject=? AND revoked_at IS NULL
        AND (is_admin=0 OR EXISTS (SELECT 1 FROM user_allowlist other WHERE other.is_admin=1 AND other.revoked_at IS NULL AND (other.issuer<>? OR other.subject<>?)))`)
        .bind(now, body.issuer, body.subject, body.issuer, body.subject),
      env.DB.prepare("UPDATE users SET active=0, updated_at=? WHERE issuer=? AND subject=? AND EXISTS (SELECT 1 FROM user_allowlist WHERE issuer=? AND subject=? AND revoked_at=?)")
        .bind(now, body.issuer, body.subject, body.issuer, body.subject, now),
      env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE user_id IN (SELECT id FROM users WHERE issuer=? AND subject=?) AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM user_allowlist WHERE issuer=? AND subject=? AND revoked_at=?)")
        .bind(now, body.issuer, body.subject, body.issuer, body.subject, now),
    ]);
    if (!results[0]?.meta.changes) {
      const exists = await env.DB.prepare("SELECT is_admin FROM user_allowlist WHERE issuer=? AND subject=?").bind(body.issuer, body.subject).first<{ is_admin: number }>();
      if (!exists) return json({ error: "not_found" }, 404);
      return json({ error: exists.is_admin === 1 ? "last_admin" : "not_found" }, 409);
    }
    await insertAudit(env.DB, actor.userId, "identity.revoked", "identity", `${body.issuer}|${body.subject}`);
    return json({ ok: true });
  }

  return json({ error: "not_found" }, 404);
}

async function getProviders(env: Env, projectId: string): Promise<Array<Record<string, unknown>>> {
  const { results } = await env.DB.prepare(
    "SELECT provider, display_name AS displayName, enabled, protocol, base_url AS baseUrl, custom FROM providers ORDER BY display_name",
  ).all<{ provider: string; displayName: string; enabled: number; protocol: "openai" | "anthropic"; baseUrl: string; custom: number }>();
  return Promise.all((results ?? []).filter((provider) =>
    isCanonicalBuiltinProvider(provider.provider, provider.protocol, provider.baseUrl, provider.custom) ||
    isCustomProviderId(provider.provider, provider.custom),
  ).map(async (provider) => {
    const models = await env.DB.prepare(
      `SELECT pm.alias, pm.upstream_model AS upstreamModel, pm.display_name AS displayName, pm.enabled,
              CASE WHEN pp.project_id IS NULL THEN 0 ELSE 1 END AS projectAllowed
       FROM provider_models pm LEFT JOIN project_permissions pp
         ON pp.provider=pm.provider AND pp.model=pm.alias AND pp.project_id=?
       WHERE pm.provider=? ORDER BY pm.display_name`,
    ).bind(projectId, provider.provider).all<Record<string, unknown>>();
    return {
      ...provider,
      id: provider.provider,
      enabled: provider.enabled === 1,
      custom: provider.custom === 1,
      models: models.results ?? [],
    };
  }));
}

async function getModelCatalog(env: Env): Promise<ModelPermission[]> {
  const { results } = await env.DB.prepare("SELECT provider, alias AS model FROM provider_models WHERE enabled=1 ORDER BY provider, alias").all<ModelPermission>();
  return results ?? [];
}

async function clientModels(env: Env, clientId: string): Promise<ModelPermission[]> {
  const { results } = await env.DB.prepare("SELECT provider, model FROM client_permissions WHERE client_id=? ORDER BY provider, model").bind(clientId).all<ModelPermission>();
  return results ?? [];
}

function normalizeUserCode(value: string): string | null {
  const normalized = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return /^[A-HJ-NP-Z2-9]{8}$/.test(normalized) ? normalized : null;
}

export async function handlePublicPairing(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const now = Math.floor(Date.now() / 1000);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (url.pathname === "/pairing/start") {
    if (request.headers.has("origin") && request.headers.get("origin") !== publicOrigin(request, env)) return forbidden();
    if (!(await rateLimit(env.DB, "pair_start", sourceAddress(request), 20, 3600, now))) return json({ error: "rate_limited" }, 429);
    const body = await readJson(request);
    const clientName = typeof body.clientName === "string" ? body.clientName.trim() : "";
    if (!text(clientName, 80) || !clientName) return json({ error: "invalid_request" }, 400);
    const pairingId = newId("pair");
    const deviceCode = randomToken(32);
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    const userCode = Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
    const expiresAt = now + 600;
    await env.DB.prepare("INSERT INTO pairing_requests (id, device_code_hash, user_code_hash, client_name, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)")
      .bind(pairingId, await sha256Base64Url(deviceCode), await sha256Base64Url(userCode), clientName, now, expiresAt).run();
    return json({ pairingId, deviceCode, userCode: `${userCode.slice(0, 4)}-${userCode.slice(4)}`, verificationUri: `${publicOrigin(request, env)}/pair`, expiresIn: 600, interval: 5 }, 201);
  }
  if (url.pathname === "/pairing/token") {
    if (request.headers.has("origin") && request.headers.get("origin") !== publicOrigin(request, env)) return forbidden();
    if (!(await rateLimit(env.DB, "pair_poll", sourceAddress(request), 120, 3600, now))) return json({ error: "rate_limited" }, 429);
    const body = await readJson(request);
    if (!text(body.pairingId, 128) || !safeId.test(body.pairingId) || !text(body.deviceCode, 128)) return json({ error: "invalid_request" }, 400);
    const deviceHash = await sha256Base64Url(body.deviceCode);
    const row = await env.DB.prepare("SELECT id, status, expires_at, user_id, project_id, client_id FROM pairing_requests WHERE id=? AND device_code_hash=?")
      .bind(body.pairingId, deviceHash).first<{ id: string; status: string; expires_at: number; user_id: string | null; project_id: string | null; client_id: string | null }>();
    if (!row || row.expires_at <= now || row.status === "expired" || row.status === "delivered") return json({ error: "expired_or_delivered" }, 410);
    if (row.status === "denied") return json({ error: "denied" }, 403);
    if (row.status !== "approved" || !row.user_id || !row.project_id || !row.client_id) return json({ status: "pending" });
    const client = await env.DB.prepare("SELECT client_identifier FROM clients WHERE id=? AND active=1 AND kind='public'").bind(row.client_id).first<{ client_identifier: string }>();
    if (!client) return json({ error: "client_unavailable" }, 410);
    const refreshToken = `rfr-${randomToken(32)}`;
    const sessionId = newId("ses");
    const delivered = await env.DB.prepare("UPDATE pairing_requests SET status='delivered', session_id=? WHERE id=? AND device_code_hash=? AND status='approved' AND expires_at>? RETURNING id")
      .bind(sessionId, row.id, deviceHash, now).first<{ id: string }>();
    if (!delivered) return json({ error: "expired_or_delivered" }, 410);
    try {
      await env.DB.prepare("INSERT INTO sessions (id,user_id,project_id,client_id,kind,refresh_token_hash,device_name,created_at,expires_at,last_seen_at) VALUES (?,?,?,?,'refresh',?,?,?,?,?)")
        .bind(sessionId, row.user_id, row.project_id, row.client_id, await sha256Base64Url(refreshToken), "paired adapter", now, now + REFRESH_MAX_AGE, now).run();
    } catch {
      await env.DB.prepare("UPDATE pairing_requests SET status='approved', session_id=NULL WHERE id=? AND session_id=? AND status='delivered'").bind(row.id, sessionId).run();
      return json({ error: "temporarily_unavailable" }, 503);
    }
    return json({ status: "approved", client_id: client.client_identifier, refresh_token: refreshToken });
  }
  return json({ error: "not_found" }, 404);
}

export async function handleTokenRequest(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return json({ error: "invalid_request" }, 405, { allow: "POST" });
  if (request.headers.has("origin") && request.headers.get("origin") !== publicOrigin(request, env)) return forbidden();
  if (!(await rateLimit(env.DB, "oauth_token", sourceAddress(request), 120, 3600))) return json({ error: "temporarily_unavailable" }, 429);
  const contentType = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") return json({ error: "invalid_request" }, 400);
  let raw: string;
  try {
    raw = await readTextBody(request, 4096);
  } catch (error) {
    const bodyFailure = handleBodyError(error);
    if (bodyFailure) return bodyFailure;
    throw error;
  }
  const form = new URLSearchParams(raw);
  const grantType = form.get("grant_type");
  const now = Math.floor(Date.now() / 1000);
  if (grantType === "client_credentials") {
    const auth = parseBasicAuth(request.headers.get("authorization"));
    if (!auth) return json({ error: "invalid_client" }, 401, { "www-authenticate": "Basic realm=identity" });
    const client = await env.DB.prepare("SELECT id, client_identifier, project_id, created_by, secret_hash, kind, name FROM clients WHERE client_identifier=? AND active=1")
      .bind(auth.clientId).first<{ id: string; client_identifier: string; project_id: string; created_by: string; secret_hash: string | null; kind: string; name: string }>();
    if (!client || client.kind !== "confidential" || !client.secret_hash || !constantTimeEqual(await sha256Base64Url(auth.clientSecret), client.secret_hash)) return json({ error: "invalid_client" }, 401, { "www-authenticate": "Basic realm=identity" });
    const user = await env.DB.prepare("SELECT u.id FROM users u JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject JOIN project_members pm ON pm.user_id=u.id AND pm.project_id=? WHERE u.id=? AND u.active=1 AND a.revoked_at IS NULL")
      .bind(client.project_id, client.created_by).first<{ id: string }>();
    if (!user) return json({ error: "invalid_client" }, 401);
    if (!(await rateLimit(env.DB, "client_token", client.id, 300, 3600, now))) return json({ error: "temporarily_unavailable" }, 429);
    const sessionId = newId("ses");
    const accessToken = await signForClient(env, client.created_by, sessionId, client.project_id, client.client_identifier, now);
    await env.DB.prepare("INSERT INTO sessions (id,user_id,project_id,client_id,kind,device_name,created_at,expires_at,last_seen_at) VALUES (?,?,?,?,'client_credentials',?,?,?,?)")
      .bind(sessionId, client.created_by, client.project_id, client.id, client.name, now, now + 3600, now).run();
    return json({ access_token: accessToken, token_type: "Bearer", expires_in: 300 });
  }
  if (grantType === "refresh_token") {
    const clientIdentifier = form.get("client_id");
    const refreshToken = form.get("refresh_token");
    if (!clientIdentifier || !refreshToken || refreshToken.length > 256) return json({ error: "invalid_grant" }, 400);
    const client = await env.DB.prepare("SELECT id, client_identifier, active, kind FROM clients WHERE client_identifier=?")
      .bind(clientIdentifier).first<{ id: string; client_identifier: string; active: number; kind: string }>();
    if (!client || client.active !== 1 || client.kind !== "public") return json({ error: "invalid_grant" }, 400);
    const oldHash = await sha256Base64Url(refreshToken);
    const session = await env.DB.prepare("SELECT s.id,s.user_id,s.project_id,s.expires_at FROM sessions s JOIN project_members pm ON pm.project_id=s.project_id AND pm.user_id=s.user_id WHERE s.client_id=? AND s.refresh_token_hash=? AND s.kind='refresh' AND s.revoked_at IS NULL AND s.expires_at>? AND s.user_id IN (SELECT u.id FROM users u JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject WHERE u.active=1 AND a.revoked_at IS NULL)")
      .bind(client.id, oldHash, now).first<{ id: string; user_id: string; project_id: string; expires_at: number }>();
    if (!session) return json({ error: "invalid_grant" }, 400);
    const newRefreshToken = `rfr-${randomToken(32)}`;
    const accessToken = await signForClient(env, session.user_id, session.id, session.project_id, client.client_identifier, now);
    const updated = await env.DB.prepare("UPDATE sessions SET refresh_token_hash=?,last_seen_at=? WHERE id=? AND refresh_token_hash=? AND revoked_at IS NULL AND expires_at>? RETURNING id")
      .bind(await sha256Base64Url(newRefreshToken), now, session.id, oldHash, now).first<{ id: string }>();
    if (!updated) return json({ error: "invalid_grant" }, 400);
    return json({ access_token: accessToken, token_type: "Bearer", expires_in: 300, refresh_token: newRefreshToken });
  }
  return json({ error: "unsupported_grant_type" }, 400);
}

function parseBasicAuth(header: string | null): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith("Basic ") || header.length > 4096) return null;
  let decoded: string;
  try { decoded = atob(header.slice(6)); } catch { return null; }
  const separator = decoded.indexOf(":");
  if (separator < 1) return null;
  try {
    const clientId = decodeURIComponent(decoded.slice(0, separator));
    const clientSecret = decodeURIComponent(decoded.slice(separator + 1));
    if (!clientId || !clientSecret || clientId.length > 256 || clientSecret.length > 512) return null;
    return { clientId, clientSecret };
  } catch { return null; }
}

async function signForClient(env: Env, userId: string, sessionId: string, projectId: string, clientId: string, now: number): Promise<string> {
  const { signMachineAccessToken } = await import("./security.js");
  return signMachineAccessToken({ userId, sessionId, projectId, clientId, tokenId: newId("jti") }, env, now);
}

export async function handleLogout(request: Request, env: Env, actor: WebActor | null): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!actor || !(await assertBrowserWrite(request, env, actor))) return forbidden();
  await env.DB.prepare("UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND user_id=?")
    .bind(Math.floor(Date.now() / 1000), actor.sessionId, actor.userId).run();
  await insertAudit(env.DB, actor.userId, "session.logged_out", "session", actor.sessionId);
  const { clearAuthCookies, setCookie } = await import("./http.js");
  let response = json({ ok: true });
  for (const cookie of clearAuthCookies()) response = setCookie(response, cookie);
  return response;
}

export function handleBodyError(error: unknown): Response | null {
  if (!(error instanceof RequestBodyError)) return null;
  return json({ error: error.code }, error.status);
}
