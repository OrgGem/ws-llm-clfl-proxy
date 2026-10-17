import { decryptCredentialEnvelope, CredentialEnvelopeSchema } from "@ws-proxy/shared";
import { insertAudit, rateLimit } from "./db.js";
import { forbidden, json, type WebActor } from "./http.js";
import { decodeBase64Url, newId, parseEnvelopeKeys, readJson } from "./security.js";

export interface ProjectLimits {
  maxPayloadBytes: number;
  maxConcurrency: number;
  maxSessionSeconds: number;
}
const DEFAULT_LIMITS: ProjectLimits = { maxPayloadBytes: 1_048_576, maxConcurrency: 8, maxSessionSeconds: 300 };

export async function getProjectLimits(env: Env, projectId: string): Promise<ProjectLimits> {
  const row = await env.DB.prepare(
    "SELECT max_payload_bytes AS maxPayloadBytes, max_concurrency AS maxConcurrency, max_session_seconds AS maxSessionSeconds FROM project_limits WHERE project_id=?",
  ).bind(projectId).first<ProjectLimits>();
  return row ?? { ...DEFAULT_LIMITS };
}

async function role(env: Env, projectId: string, userId: string): Promise<string | null> {
  const result = await env.DB.prepare("SELECT role FROM project_members WHERE project_id=? AND user_id=?")
    .bind(projectId, userId).first<{ role: string }>();
  return result?.role ?? null;
}
const canManage = (value: string | null) => value === "owner" || value === "admin";

/** Called only after the main router has authenticated the browser and checked write CSRF. */
export async function handleManagementApi(request: Request, env: Env, actor: WebActor): Promise<Response | null> {
  const url = new URL(request.url);
  const method = request.method;
  const now = Math.floor(Date.now() / 1000);
  if (url.pathname === "/api/projects" && method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT p.id,p.name,p.owner_user_id AS ownerUserId,m.role FROM projects p JOIN project_members m ON m.project_id=p.id WHERE m.user_id=? ORDER BY p.created_at,p.id",
    ).bind(actor.userId).all();
    return json({ projects: rows.results ?? [] });
  }
  if (url.pathname === "/api/projects" && method === "POST") {
    const body = await readJson(request);
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) return json({ error: "invalid_request" }, 400);
    if (!(await rateLimit(env.DB, "project_create", actor.userId, 10, 3600, now))) return json({ error: "rate_limited" }, 429);
    const id = newId("prj");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO projects(id,owner_user_id,name,created_at) VALUES(?,?,?,?)").bind(id, actor.userId, name, now),
      env.DB.prepare("INSERT INTO project_members(project_id,user_id,role,created_at) VALUES(?,?,'owner',?)").bind(id, actor.userId, now),
    ]);
    await insertAudit(env.DB, actor.userId, "project.created", "project", id);
    return json({ project: { id, name, role: "owner", limits: { ...DEFAULT_LIMITS } } }, 201);
  }
  const projectMatch = /^\/api\/projects\/([A-Za-z0-9._:-]{1,128})\/(members|limits)(?:\/([A-Za-z0-9._:-]{1,128}))?$/.exec(url.pathname);
  if (projectMatch) {
    const projectId = projectMatch[1]!;
    const action = projectMatch[2];
    const targetUserId = projectMatch[3];
    const actorRole = await role(env, projectId, actor.userId);
    if (!actorRole) return forbidden();
    if (action === "limits" && !targetUserId) {
      if (method === "GET") return json({ limits: await getProjectLimits(env, projectId) });
      if (method === "PUT") {
        if (!canManage(actorRole)) return forbidden();
        const body = await readJson(request);
        const { maxPayloadBytes, maxConcurrency, maxSessionSeconds } = body;
        if (typeof maxPayloadBytes !== "number" || !Number.isInteger(maxPayloadBytes) || maxPayloadBytes < 1024 || maxPayloadBytes > 1_048_576 ||
            typeof maxConcurrency !== "number" || !Number.isInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > 8 ||
            typeof maxSessionSeconds !== "number" || !Number.isInteger(maxSessionSeconds) || maxSessionSeconds < 30 || maxSessionSeconds > 300) {
          return json({ error: "invalid_request" }, 400);
        }
        const saved = await env.DB.prepare(
          `INSERT INTO project_limits(project_id,max_payload_bytes,max_concurrency,max_session_seconds,updated_by,updated_at)
           SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM project_members a WHERE a.project_id=? AND a.user_id=? AND a.role IN ('owner','admin'))
           ON CONFLICT(project_id) DO UPDATE SET max_payload_bytes=excluded.max_payload_bytes,
           max_concurrency=excluded.max_concurrency,max_session_seconds=excluded.max_session_seconds,updated_by=excluded.updated_by,updated_at=excluded.updated_at
           WHERE EXISTS (SELECT 1 FROM project_members a WHERE a.project_id=? AND a.user_id=? AND a.role IN ('owner','admin'))`,
        ).bind(projectId, maxPayloadBytes, maxConcurrency, maxSessionSeconds, actor.userId, now, projectId, actor.userId, projectId, actor.userId).run();
        if (!saved.meta.changes) return forbidden();
        await insertAudit(env.DB, actor.userId, "project.limits_updated", "project", projectId);
        return json({ limits: { maxPayloadBytes, maxConcurrency, maxSessionSeconds } });
      }
    }
    if (action === "members") {
      if (method === "GET" && !targetUserId) {
        const members = await env.DB.prepare(
          "SELECT u.id AS userId,u.issuer,u.subject,u.email,u.display_name AS displayName,m.role FROM project_members m JOIN users u ON u.id=m.user_id WHERE m.project_id=? ORDER BY m.created_at,u.id",
        ).bind(projectId).all();
        return json({ members: members.results ?? [] });
      }
      if (method === "POST" && !targetUserId) {
        if (!canManage(actorRole)) return forbidden();
        const body = await readJson(request);
        if (typeof body.issuer !== "string" || body.issuer.length < 1 || body.issuer.length > 1024 || typeof body.subject !== "string" || body.subject.length < 1 || body.subject.length > 512 || (body.role !== "member" && body.role !== "admin")) return json({ error: "invalid_request" }, 400);
        if (body.role === "admin" && actorRole !== "owner") return forbidden();
        const user = await env.DB.prepare(
          "SELECT u.id FROM users u JOIN user_allowlist a ON a.issuer=u.issuer AND a.subject=u.subject WHERE u.issuer=? AND u.subject=? AND u.active=1 AND a.revoked_at IS NULL",
        ).bind(body.issuer, body.subject).first<{ id: string }>();
        if (!user) return json({ error: "user_unavailable" }, 400);
        const existingRole = await role(env, projectId, user.id);
        if (existingRole === "owner" || (existingRole === "admin" && actorRole !== "owner")) return forbidden();
        const saved = await env.DB.prepare(
          `INSERT INTO project_members(project_id,user_id,role,created_at) SELECT ?,?,?,?
           WHERE EXISTS (SELECT 1 FROM project_members a WHERE a.project_id=? AND a.user_id=? AND
             (a.role='owner' OR (a.role='admin' AND ?='member')))
           ON CONFLICT(project_id,user_id) DO UPDATE SET role=excluded.role
           WHERE project_members.role!='owner' AND EXISTS (SELECT 1 FROM project_members a WHERE a.project_id=? AND a.user_id=? AND
             (a.role='owner' OR (a.role='admin' AND ?='member' AND project_members.role!='admin')))`,
        ).bind(projectId, user.id, body.role, now, projectId, actor.userId, body.role, projectId, actor.userId, body.role).run();
        if (!saved.meta.changes) return forbidden();
        await insertAudit(env.DB, actor.userId, "project.member_added", "project", projectId, { userId: user.id, role: body.role });
        return json({ member: { userId: user.id, issuer: body.issuer, subject: body.subject, role: body.role } }, 201);
      }
      if (method === "DELETE" && targetUserId) {
        if (!canManage(actorRole)) return forbidden();
        const targetRole = await role(env, projectId, targetUserId);
        if (!targetRole) return json({ error: "not_found" }, 404);
        if (targetRole === "owner" || (targetRole === "admin" && actorRole !== "owner")) return forbidden();
        const removed = await env.DB.batch([
          env.DB.prepare(`DELETE FROM project_members WHERE project_id=? AND user_id=? AND role!='owner'
            AND EXISTS (SELECT 1 FROM project_members a WHERE a.project_id=? AND a.user_id=? AND
              (a.role='owner' OR (a.role='admin' AND project_members.role!='admin')))`)
            .bind(projectId, targetUserId, projectId, actor.userId),
          env.DB.prepare(`UPDATE sessions SET revoked_at=COALESCE(revoked_at,?) WHERE project_id=? AND user_id=?
            AND NOT EXISTS (SELECT 1 FROM project_members WHERE project_id=? AND user_id=?)`)
            .bind(now, projectId, targetUserId, projectId, targetUserId),
        ]);
        if (!removed[0]?.meta.changes) return forbidden();
        await insertAudit(env.DB, actor.userId, "project.member_removed", "project", projectId, { userId: targetUserId });
        return json({ ok: true });
      }
    }
    return json({ error: "method_not_allowed" }, 405);
  }
  const bootstrap = /^\/api\/clients\/([A-Za-z0-9._:-]{1,128})\/bootstrap$/.exec(url.pathname);
  if (bootstrap && method === "GET") {
    const client = await env.DB.prepare(
      "SELECT id,client_identifier AS clientId,project_id AS projectId,kind,created_by AS createdBy FROM clients WHERE id=? AND active=1",
    ).bind(bootstrap[1]!).first<{ id: string; clientId: string; projectId: string; kind: string; createdBy: string }>();
    if (!client || !(await role(env, client.projectId, actor.userId))) return forbidden();
    const modelRows = await env.DB.prepare(
      `SELECT c.provider,c.model AS id FROM client_permissions c
       JOIN project_permissions p ON p.project_id=? AND p.provider=c.provider AND p.model=c.model
       JOIN providers r ON r.provider=c.provider AND r.enabled=1
       JOIN provider_models m ON m.provider=c.provider AND m.alias=c.model AND m.enabled=1 WHERE c.client_id=? ORDER BY c.provider,c.model`,
    ).bind(client.projectId, client.id).all();
    const identityUrl = new URL(env.MACHINE_ISSUER);
    const gatewayUrl = new URL(env.GATEWAY_URL);
    if ((identityUrl.protocol !== "https:" && !isLocalUrl(identityUrl)) || (gatewayUrl.protocol !== "wss:" && !isLocalUrl(gatewayUrl)) || gatewayUrl.search || gatewayUrl.hash || gatewayUrl.username || gatewayUrl.password) {
      return json({ error: "bootstrap_not_configured" }, 503);
    }
    const contents = {
      version: 1,
      identityUrl: identityUrl.href.replace(/\/$/, ""),
      gatewayUrl: gatewayUrl.href,
      client: { clientId: client.clientId, kind: client.kind },
      projectId: client.projectId,
      models: modelRows.results ?? [],
      limits: await getProjectLimits(env, client.projectId),
    };
    return json(contents, 200, { "content-disposition": 'attachment; filename="ws-llm-bootstrap.json"' });
  }
  const test = /^\/api\/credentials\/([A-Za-z0-9._:-]{1,128})\/test$/.exec(url.pathname);
  if (test && method === "POST") {
    if (!(await rateLimit(env.DB, "provider_test", actor.userId, 10, 60, now))) return json({ error: "rate_limited" }, 429);
    const body = await readJson(request, 16_384);
    const parsed = CredentialEnvelopeSchema.safeParse(body.envelope);
    if (!parsed.success) return json({ error: "credential_invalid" }, 400);
    const envelope = parsed.data;
    const metadata = await env.DB.prepare(
      "SELECT id,user_id,project_id,provider,key_version,expires_at FROM credentials WHERE id=? AND revoked_at IS NULL AND expires_at>?",
    ).bind(test[1]!, now).first<{ id: string; user_id: string; project_id: string; provider: string; key_version: string; expires_at: number }>();
    if (!metadata || metadata.user_id !== actor.userId || !canManage(await role(env, metadata.project_id, actor.userId))) return forbidden();
    if (envelope.credentialId !== metadata.id || envelope.userId !== metadata.user_id || envelope.projectId !== metadata.project_id || envelope.provider !== metadata.provider || envelope.kid !== metadata.key_version || envelope.exp !== metadata.expires_at) {
      return json({ error: "credential_invalid" }, 400);
    }
    const provider = await env.DB.prepare("SELECT enabled FROM providers WHERE provider=?").bind(metadata.provider).first<{ enabled: number }>();
    if (provider?.enabled !== 1 || !["openai", "anthropic"].includes(metadata.provider)) return forbidden();
    let plaintext: Uint8Array | undefined;
    let keyBytes: Uint8Array | undefined;
    try {
      const keys = parseEnvelopeKeys(env.ENVELOPE_KEYS);
      const encoded = keys.keys[envelope.kid];
      if (!encoded) return json({ error: "credential_invalid" }, 400);
      keyBytes = decodeBase64Url(encoded);
      const decrypted = await decryptCredentialEnvelope(envelope, keyBytes, { now });
      plaintext = decrypted.plaintext;
      const apiKey = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      if (!/^[\x21-\x7e]{1,8192}$/.test(apiKey)) return json({ error: "credential_invalid" }, 400);
      const response = await fetch(metadata.provider === "openai" ? "https://api.openai.com/v1/models" : "https://api.anthropic.com/v1/models", {
        method: "GET",
        headers: metadata.provider === "openai" ? { authorization: `Bearer ${apiKey}` } : { "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      });
      await response.body?.cancel();
      await insertAudit(env.DB, actor.userId, "credential.connection_tested", "credential", metadata.id, { provider: metadata.provider, status: response.status });
      return json({ ok: response.ok, provider: metadata.provider, checkedAt: now }, response.ok ? 200 : 502);
    } catch {
      return json({ error: "provider_connection_failed" }, 502);
    } finally {
      plaintext?.fill(0);
      keyBytes?.fill(0);
    }
  }
  return null;
}

function isLocalUrl(url: URL): boolean {
  return ["http:", "ws:"].includes(url.protocol) && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}
