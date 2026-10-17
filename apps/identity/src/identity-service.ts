import { WorkerEntrypoint } from "cloudflare:workers";
import type { GatewayAccessTokenClaims } from "@ws-proxy/shared";
import { verifyMachineAccessToken } from "./security.js";
import { getProjectLimits, type ProjectLimits } from "./management.js";

export interface AuthorizedPrincipal {
  userId: string;
  projectId: string;
  clientId: string;
  sessionId: string;
}

export interface CredentialMetadata {
  credentialId: string;
  userId: string;
  projectId: string;
  provider: string;
  expiresAt: number;
  keyVersion: string;
}

export interface IdentityValidationResult {
  valid: boolean;
  claims?: GatewayAccessTokenClaims & { iss: string; aud: string | string[]; exp: number };
  principal?: AuthorizedPrincipal;
  tokenExpiresAt?: number;
  limits?: ProjectLimits;
  reasonCode?: string;
}

export interface IdentityAuthorizationRequest {
  accessToken: string;
  credentialId: string;
  provider: string;
  model: string;
}

export interface IdentityAuthorizationResult {
  allowed: boolean;
  principal?: AuthorizedPrincipal;
  credentialMetadata?: CredentialMetadata;
  authorizedModel?: { alias: string; upstreamModel: string };
  limits?: ProjectLimits;
  reasonCode?: string;
}

interface ActiveSessionRow {
  user_id: string;
  project_id: string;
  session_id: string;
  client_row_id: string;
  client_identifier: string;
  last_seen_at: number;
}

async function loadActivePrincipal(
  env: Env,
  claims: GatewayAccessTokenClaims,
  now: number,
): Promise<{ principal: AuthorizedPrincipal; clientRowId: string } | null> {
  const row = await env.DB.prepare(
    `SELECT s.user_id, s.project_id, s.id AS session_id, s.last_seen_at, c.id AS client_row_id, c.client_identifier
     FROM sessions s
     JOIN users u ON u.id = s.user_id AND u.active = 1
     JOIN user_allowlist ua ON ua.issuer = u.issuer AND ua.subject = u.subject AND ua.revoked_at IS NULL
     JOIN project_members pm ON pm.project_id = s.project_id AND pm.user_id = s.user_id
     JOIN clients c ON c.id = s.client_id AND c.active = 1 AND c.created_by = s.user_id
     JOIN projects p ON p.id = s.project_id
     WHERE s.id = ? AND s.user_id = ? AND s.project_id = ?
       AND c.client_identifier = ? AND c.project_id = s.project_id
       AND s.kind IN ('refresh', 'client_credentials')
       AND s.revoked_at IS NULL AND s.expires_at > ?`,
  )
    .bind(claims.sid, claims.sub, claims.project_id, claims.client_id, now)
    .first<ActiveSessionRow>();
  if (!row) return null;
  if (now - row.last_seen_at >= 300) {
    await env.DB.prepare("UPDATE sessions SET last_seen_at=? WHERE id=? AND last_seen_at<=? AND revoked_at IS NULL")
      .bind(now, row.session_id, now - 300).run();
  }
  return {
    principal: {
      userId: row.user_id,
      projectId: row.project_id,
      clientId: row.client_identifier,
      sessionId: row.session_id,
    },
    clientRowId: row.client_row_id,
  };
}

async function validateMachineToken(env: Env, token: string): Promise<{
  claims: GatewayAccessTokenClaims & { iss: string; aud: string | string[]; exp: number };
  principal: AuthorizedPrincipal;
  clientRowId: string;
} | null> {
  if (typeof token !== "string" || token.length > 16_384 || token.length < 20) return null;
  try {
    const claims = await verifyMachineAccessToken(token, env) as GatewayAccessTokenClaims & {
      iss: string;
      aud: string | string[];
      exp: number;
    };
    const active = await loadActivePrincipal(env, claims, Math.floor(Date.now() / 1000));
    if (!active) return null;
    return { claims, principal: active.principal, clientRowId: active.clientRowId };
  } catch {
    return null;
  }
}

export class IdentityInternal extends WorkerEntrypoint<Env> {
  async validateToken(accessToken: string): Promise<IdentityValidationResult> {
    const validated = await validateMachineToken(this.env, accessToken);
    if (!validated) return { valid: false, reasonCode: "invalid_or_inactive_token" };
    return {
      valid: true,
      claims: validated.claims,
      principal: validated.principal,
      tokenExpiresAt: validated.claims.exp,
      limits: await getProjectLimits(this.env, validated.principal.projectId),
    };
  }

  async authorizeTokenRequest(input: IdentityAuthorizationRequest): Promise<IdentityAuthorizationResult> {
    if (
      !input ||
      typeof input !== "object" ||
      typeof input.accessToken !== "string" ||
      typeof input.credentialId !== "string" ||
      typeof input.provider !== "string" ||
      typeof input.model !== "string" ||
      input.credentialId.length > 128 ||
      input.provider.length > 64 ||
      input.model.length > 128
    ) return { allowed: false, reasonCode: "invalid_request" };

    const validated = await validateMachineToken(this.env, input.accessToken);
    if (!validated) return { allowed: false, reasonCode: "invalid_or_inactive_token" };

    const now = Math.floor(Date.now() / 1000);
    const credential = await this.env.DB.prepare(
      `SELECT id, user_id, project_id, provider, key_version, expires_at, revoked_at
       FROM credentials WHERE id = ?`,
    )
      .bind(input.credentialId)
      .first<{
        id: string;
        user_id: string;
        project_id: string;
        provider: string;
        key_version: string;
        expires_at: number;
        revoked_at: number | null;
      }>();
    if (!credential) return { allowed: false, reasonCode: "credential_unavailable" };
    if (credential.revoked_at !== null) return { allowed: false, reasonCode: "credential_revoked" };
    if (credential.expires_at <= now) return { allowed: false, reasonCode: "credential_expired" };
    if (
      credential.user_id !== validated.principal.userId ||
      credential.project_id !== validated.principal.projectId ||
      credential.provider !== input.provider
    ) return { allowed: false, reasonCode: "credential_owner_mismatch" };

    const model = await this.env.DB.prepare(
      `SELECT pm.alias, pm.upstream_model
       FROM providers p
       JOIN provider_models pm ON pm.provider = p.provider AND pm.enabled = 1
       JOIN project_permissions pp ON pp.provider = pm.provider AND pp.model = pm.alias
       JOIN client_permissions cp ON cp.provider = pm.provider AND cp.model = pm.alias
       WHERE p.provider = ? AND p.enabled = 1 AND pm.alias = ?
         AND pp.project_id = ? AND cp.client_id = ?`,
    )
      .bind(input.provider, input.model, validated.principal.projectId, validated.clientRowId)
      .first<{ alias: string; upstream_model: string }>();
    if (!model) return { allowed: false, reasonCode: "provider_or_model_not_allowed" };

    return {
      allowed: true,
      principal: validated.principal,
      credentialMetadata: {
        credentialId: credential.id,
        userId: credential.user_id,
        projectId: credential.project_id,
        provider: credential.provider,
        expiresAt: credential.expires_at,
        keyVersion: credential.key_version,
      },
      authorizedModel: { alias: model.alias, upstreamModel: model.upstream_model },
      limits: await getProjectLimits(this.env, validated.principal.projectId),
    };
  }
}
