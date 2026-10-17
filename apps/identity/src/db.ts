import { sha256Base64Url } from "./security.js";

export interface OidcProfile {
  issuer: string;
  subject: string;
  email: string;
  displayName: string;
}

export interface AllowlistDecision {
  allowed: boolean;
  isAdmin: boolean;
  revoked: boolean;
  pending: boolean;
}

export async function decideOidcAllowlist(
  db: D1Database,
  identity: OidcProfile,
  bootstrapAdminEmails: string | undefined,
  now: number,
): Promise<AllowlistDecision> {
  const exact = await db
    .prepare("SELECT is_admin, revoked_at FROM user_allowlist WHERE issuer = ? AND subject = ?")
    .bind(identity.issuer, identity.subject)
    .first<{ is_admin: number; revoked_at: number | null }>();
  if (exact) {
    if (exact.revoked_at !== null) return { allowed: false, isAdmin: false, revoked: true, pending: false };
    await db
      .prepare("UPDATE user_allowlist SET email = ? WHERE issuer = ? AND subject = ? AND revoked_at IS NULL")
      .bind(identity.email, identity.issuer, identity.subject)
      .run();
    return { allowed: true, isAdmin: exact.is_admin === 1, revoked: false, pending: false };
  }

  const bootstrapEmails = new Set(
    (bootstrapAdminEmails ?? "")
      .split(",")
      .map((email) => email.trim().toLowerCase())
      .filter(Boolean),
  );
  if (bootstrapEmails.has(identity.email)) {
    const result = await db
      .prepare(
        `INSERT INTO user_allowlist (issuer, subject, email, is_admin, approved_at, created_by, created_at)
         SELECT ?, ?, ?, 1, ?, NULL, ?
         WHERE NOT EXISTS (SELECT 1 FROM user_allowlist WHERE is_admin = 1)
           AND NOT EXISTS (SELECT 1 FROM user_allowlist WHERE issuer = ? AND subject = ?)
         RETURNING is_admin`,
      )
      .bind(identity.issuer, identity.subject, identity.email, now, now, identity.issuer, identity.subject)
      .first<{ is_admin: number }>();
    if (result) return { allowed: true, isAdmin: true, revoked: false, pending: false };
    const afterBootstrap = await db
      .prepare("SELECT is_admin, revoked_at FROM user_allowlist WHERE issuer = ? AND subject = ?")
      .bind(identity.issuer, identity.subject)
      .first<{ is_admin: number; revoked_at: number | null }>();
    if (afterBootstrap) {
      if (afterBootstrap.revoked_at !== null) return { allowed: false, isAdmin: false, revoked: true, pending: false };
      return { allowed: true, isAdmin: afterBootstrap.is_admin === 1, revoked: false, pending: false };
    }
  }

  await db
    .prepare(
      `INSERT INTO pending_identities (issuer, subject, email, display_name, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (issuer, subject) DO UPDATE SET
         email = excluded.email,
         display_name = excluded.display_name,
         last_seen_at = excluded.last_seen_at`,
    )
    .bind(identity.issuer, identity.subject, identity.email, identity.displayName, now, now)
    .run();
  return { allowed: false, isAdmin: false, revoked: false, pending: true };
}

export async function ensureOidcUser(db: D1Database, identity: OidcProfile, now: number): Promise<{
  id: string;
  email: string;
  displayName: string;
  projectId: string;
  isAdmin: boolean;
}> {
  const allowlist = await db
    .prepare("SELECT is_admin FROM user_allowlist WHERE issuer = ? AND subject = ? AND revoked_at IS NULL")
    .bind(identity.issuer, identity.subject)
    .first<{ is_admin: number }>();
  if (!allowlist) throw new Error("OIDC identity is not allowlisted");

  let user = await db
    .prepare("SELECT id, active FROM users WHERE issuer = ? AND subject = ?")
    .bind(identity.issuer, identity.subject)
    .first<{ id: string; active: number }>();
  if (user) {
    if (user.active !== 1) throw new Error("OIDC user is inactive");
    await db
      .prepare("UPDATE users SET email = ?, display_name = ?, updated_at = ? WHERE id = ?")
      .bind(identity.email, identity.displayName, now, user.id)
      .run();
  } else {
    const id = `usr-${crypto.randomUUID()}`;
    await db
      .prepare(
        `INSERT INTO users (id, issuer, subject, email, display_name, active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, ?, ?)
         ON CONFLICT (issuer, subject) DO NOTHING`,
      )
      .bind(id, identity.issuer, identity.subject, identity.email, identity.displayName, now, now)
      .run();
    user = await db
      .prepare("SELECT id, active FROM users WHERE issuer = ? AND subject = ?")
      .bind(identity.issuer, identity.subject)
      .first<{ id: string; active: number }>();
    if (!user || user.active !== 1) throw new Error("Could not provision OIDC user");
  }

  let project = await db
    .prepare("SELECT id FROM projects WHERE owner_user_id = ? AND name = 'Personal'")
    .bind(user.id)
    .first<{ id: string }>();
  if (!project) {
    const projectId = `prj-${crypto.randomUUID()}`;
    await db
      .prepare("INSERT OR IGNORE INTO projects (id, owner_user_id, name, created_at) VALUES (?, ?, 'Personal', ?)")
      .bind(projectId, user.id, now)
      .run();
    project = await db
      .prepare("SELECT id FROM projects WHERE owner_user_id = ? AND name = 'Personal'")
      .bind(user.id)
      .first<{ id: string }>();
    if (project) {
      await db
        .prepare("INSERT OR IGNORE INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)")
        .bind(project.id, user.id, now)
        .run();
    }
  }
  if (!project) throw new Error("Could not provision default project");
  await db
    .prepare("INSERT OR IGNORE INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)")
    .bind(project.id, user.id, now)
    .run();

  return {
    id: user.id,
    email: identity.email,
    displayName: identity.displayName,
    projectId: project.id,
    isAdmin: allowlist.is_admin === 1,
  };
}

export async function insertAudit(
  db: D1Database,
  actorUserId: string | null,
  action: string,
  targetType: string,
  targetId: string,
  details: Record<string, string | number | boolean | null> = {},
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(`aud_${crypto.randomUUID()}`, actorUserId, action, targetType, targetId, JSON.stringify(details), Math.floor(Date.now() / 1000))
    .run();
}

export async function rateLimit(
  db: D1Database,
  scope: string,
  source: string,
  limit: number,
  windowSeconds: number,
  now = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  const sourceKey = await sha256Base64Url(`${scope}\n${source}`);
  const windowStart = now - (now % windowSeconds);
  const row = await db
    .prepare(
      `INSERT INTO rate_limits (rate_key, window_start, hits) VALUES (?, ?, 1)
       ON CONFLICT (rate_key) DO UPDATE SET
         hits = CASE WHEN rate_limits.window_start < excluded.window_start THEN 1 ELSE rate_limits.hits + 1 END,
         window_start = CASE WHEN rate_limits.window_start < excluded.window_start THEN excluded.window_start ELSE rate_limits.window_start END
       RETURNING hits`,
    )
    .bind(sourceKey, windowStart)
    .first<{ hits: number }>();
  return Boolean(row && row.hits <= limit);
}

export async function cleanupTransientRows(db: D1Database, now: number): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM oidc_transactions WHERE expires_at <= ?").bind(now),
    db.prepare("DELETE FROM pairing_requests WHERE expires_at <= ?").bind(now - 86_400),
    db.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 3_600),
    db.prepare("DELETE FROM sessions WHERE expires_at <= ? OR revoked_at <= ?").bind(now - 2_592_000, now - 2_592_000),
  ]);
}

export async function requireProjectRole(db: D1Database, projectId: string, userId: string): Promise<"owner" | "admin" | "member" | null> {
  const row = await db
    .prepare("SELECT role FROM project_members WHERE project_id = ? AND user_id = ?")
    .bind(projectId, userId)
    .first<{ role: "owner" | "admin" | "member" }>();
  return row?.role ?? null;
}

export async function projectModelIsEnabled(
  db: D1Database,
  projectId: string,
  provider: string,
  model: string,
): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT 1 AS allowed FROM project_permissions pp
       JOIN providers p ON p.provider = pp.provider AND p.enabled = 1
       JOIN provider_models pm ON pm.provider = pp.provider AND pm.alias = pp.model AND pm.enabled = 1
       WHERE pp.project_id = ? AND pp.provider = ? AND pp.model = ?`,
    )
    .bind(projectId, provider, model)
    .first<{ allowed: number }>();
  return Boolean(row);
}
