import { GATEWAY_TOKEN_AUDIENCE, verifyGatewayAccessToken } from "@ws-proxy/shared";
import { env, reset, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { migrateIdentityDatabase, randomId, randomProviderSecret } from "./db-fixtures.js";

interface IdentityTestEnv {
  DB: D1Database;
  MACHINE_ISSUER: string;
  MACHINE_JWT_PRIVATE_JWK: string;
  MACHINE_JWT_PUBLIC_JWKS: string;
  PUBLIC_ORIGIN: string;
}

interface IdentityFixture {
  userId: string;
  projectId: string;
  confidentialClientId: string;
  confidentialClientSecret: string;
  confidentialClientRowId: string;
  publicClientId: string;
  foreignPublicClientId: string;
  refreshSessionId: string;
  refreshToken: string;
  browserToken: string;
  csrfToken: string;
}

const identityEnv = env as unknown as IdentityTestEnv;
let fixture: IdentityFixture;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(identityEnv.DB);
  fixture = await seedIdentityDatabase();
});

describe("Identity public Worker routes", () => {
  it("serves the control room and its module assets under /ui", async () => {
    const root = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/`, { redirect: "manual" });
    expect(root.status).toBe(303);
    expect(root.headers.get("location")).toBe("/ui");
    for (const path of ["/ui", "/ui/"]) {
      const page = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}${path}`);
      expect(page.status).toBe(200);
      const html = await page.text();
      expect(html).toContain('src="/ui/app.js"');
      expect(html).toContain('href="/ui/app.css"');
    }
    for (const path of ["app.js", "api.js", "bootstrap.js", "dates.js", "app.css"]) {
      const asset = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/ui/${path}`);
      expect(asset.status).toBe(200);
      expect(asset.headers.get("x-content-type-options")).toBe("nosniff");
    }
    const denied = await SELF.fetch(`${identityEnv.PUBLIC_ORIGIN}/ui/internal/authorize`);
    expect(denied.status).toBe(404);
  });
  it("issues a short-lived ES256 access token for a confidential client", async () => {
    const response = await postForm({ grant_type: "client_credentials" }, {
      authorization: `Basic ${btoa(`${fixture.confidentialClientId}:${fixture.confidentialClientSecret}`)}`,
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { access_token: string; token_type: string; expires_in: number };
    expect(body).toMatchObject({ token_type: "Bearer", expires_in: 300 });
    expect(body.access_token).toMatch(/^[A-Za-z0-9_-]+.[A-Za-z0-9_-]+.[A-Za-z0-9_-]+$/);

    const publicJwk = JSON.parse(identityEnv.MACHINE_JWT_PUBLIC_JWKS) as { keys: Array<JsonWebKey & { kid: string }> };
    const jwk = publicJwk.keys[0]!;
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const claims = await verifyGatewayAccessToken(body.access_token, () => key, {
      issuer: identityEnv.MACHINE_ISSUER,
      audience: GATEWAY_TOKEN_AUDIENCE,
    });
    expect(claims).toMatchObject({
      sub: fixture.userId,
      project_id: fixture.projectId,
      client_id: fixture.confidentialClientId,
    });
  });

  it("rotates refresh tokens once and rejects the old token", async () => {
    const rotated = await refresh(fixture.refreshToken);
    expect(rotated.status).toBe(200);
    const firstRotation = await rotated.json() as { access_token: string; refresh_token: string; expires_in: number };
    expect(firstRotation.refresh_token).not.toBe(fixture.refreshToken);
    expect(firstRotation.expires_in).toBe(300);

    const replay = await refresh(fixture.refreshToken);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ error: "invalid_grant" });

    const secondRotation = await refresh(firstRotation.refresh_token);
    expect(secondRotation.status).toBe(200);
  });

  it("does not let a different public client rotate another user's refresh token", async () => {
    const response = await refresh(fixture.refreshToken, fixture.foreignPublicClientId);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("revokes a refresh session through the authenticated browser route", async () => {
    const rotated = await refresh(fixture.refreshToken);
    expect(rotated.status).toBe(200);
    const refreshed = await rotated.json() as { refresh_token: string };
    const revoke = await SELF.fetch(new Request(
      `${identityEnv.PUBLIC_ORIGIN}/api/sessions/${fixture.refreshSessionId}/revoke`,
      {
        method: "POST",
        headers: {
          cookie: `__Host-identity_session=${encodeURIComponent(fixture.browserToken)}; __Host-identity_csrf=${encodeURIComponent(fixture.csrfToken)}`,
          origin: identityEnv.PUBLIC_ORIGIN,
          "x-csrf-token": fixture.csrfToken,
          "content-type": "application/json",
        },
        body: "{}",
      },
    ));
    expect(revoke.status).toBe(200);
    expect(await revoke.json()).toMatchObject({ ok: true });

    const afterRevoke = await refresh(refreshed.refresh_token);
    expect(afterRevoke.status).toBe(400);
    expect(await afterRevoke.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("updates project limits only through the authenticated management route", async () => {
    const limits = { maxPayloadBytes: 2_048, maxConcurrency: 2, maxSessionSeconds: 90 };
    const updated = await browserRequest(`/api/projects/${fixture.projectId}/limits`, "PUT", limits);
    expect(updated.status).toBe(200);
    expect(await updated.json()).toEqual({ limits });

    const readBack = await browserRequest(`/api/projects/${fixture.projectId}/limits`);
    expect(readBack.status).toBe(200);
    expect(await readBack.json()).toEqual({ limits });

    const invalid = await browserRequest(`/api/projects/${fixture.projectId}/limits`, "PUT", {
      ...limits,
      maxPayloadBytes: 1_023,
    });
    expect(invalid.status).toBe(400);
  });

  it("exports client bootstrap data without client or worker secrets", async () => {
    const response = await browserRequest(`/api/clients/${fixture.confidentialClientRowId}/bootstrap`);
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain(fixture.confidentialClientId);
    expect(body).not.toContain(fixture.confidentialClientSecret);
    expect(body).not.toContain("clientSecret");
    expect(body).not.toContain("MACHINE_JWT_PRIVATE_JWK");
    expect(body).not.toContain("ENVELOPE_KEYS");
    expect(JSON.parse(body)).toMatchObject({
      projectId: fixture.projectId,
      limits: { maxPayloadBytes: 1_048_576, maxConcurrency: 8, maxSessionSeconds: 300 },
    });
  });

  it("approves a pairing request and delivers exactly one refresh token", async () => {
    await identityEnv.DB.prepare(
      "INSERT INTO provider_models (provider, alias, upstream_model, display_name, enabled, created_at) VALUES ('openai', 'integration-model', 'integration-upstream', 'Integration Model', 1, ?)",
    ).bind(Math.floor(Date.now() / 1000)).run();
    await identityEnv.DB.prepare(
      "INSERT INTO project_permissions (project_id, provider, model, created_by, created_at) VALUES (?, 'openai', 'integration-model', ?, ?)",
    ).bind(fixture.projectId, fixture.userId, Math.floor(Date.now() / 1000)).run();

    const started = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/pairing/start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientName: "Paired integration client" }),
    }));
    expect(started.status).toBe(201);
    const pairing = await started.json() as { pairingId: string; deviceCode: string; userCode: string };

    const approved = await browserRequest("/api/pairing/approve", "POST", {
      userCode: pairing.userCode,
      projectId: fixture.projectId,
      models: [{ provider: "openai", model: "integration-model" }],
    });
    expect(approved.status).toBe(200);
    expect(await approved.json()).toMatchObject({ ok: true });

    const delivered = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/pairing/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pairingId: pairing.pairingId, deviceCode: pairing.deviceCode }),
    }));
    expect(delivered.status).toBe(200);
    const credentials = await delivered.json() as { status: string; client_id: string; refresh_token: string };
    expect(credentials).toMatchObject({ status: "approved" });
    expect(credentials.client_id).toMatch(/^cli_/);
    expect(credentials.refresh_token).toMatch(/^rfr-/);

    const secondDelivery = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/pairing/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pairingId: pairing.pairingId, deviceCode: pairing.deviceCode }),
    }));
    expect(secondDelivery.status).toBe(410);
    expect(await secondDelivery.json()).toMatchObject({ error: "expired_or_delivered" });
  });
});


describe("Project management authorization", () => {
  it("creates a project with an owner and default limits", async () => {
    const created = await browserRequest("/api/projects", "POST", { name: "Additional workspace" });
    expect(created.status).toBe(201);
    const body = await created.json() as { project: { id: string; limits: unknown } };
    expect(body.project.id).toMatch(/^prj_/);
    expect(body.project.limits).toEqual({ maxPayloadBytes: 1_048_576, maxConcurrency: 8, maxSessionSeconds: 300 });
    const members = await browserRequest(`/api/projects/${body.project.id}/members`);
    expect(await members.json()).toMatchObject({ members: [{ userId: fixture.userId, role: "owner" }] });
  });

  it("round-trips membership and prevents admins from modifying owners or other admins", async () => {
    const foreign = await identityEnv.DB.prepare("SELECT id,issuer,subject FROM users WHERE subject='foreign-subject'")
      .first<{ id: string; issuer: string; subject: string }>();
    expect(foreign).not.toBeNull();
    const memberBody = { issuer: foreign!.issuer, subject: foreign!.subject, role: "member" };
    const added = await browserRequest(`/api/projects/${fixture.projectId}/members`, "POST", memberBody);
    expect(added.status).toBe(201);
    expect(await added.json()).toMatchObject({ member: { userId: foreign!.id, role: "member" } });
    const listed = await browserRequest(`/api/projects/${fixture.projectId}/members`);
    const members = await listed.json() as { members: Array<{ userId: string }> };
    expect(members.members.map((item) => item.userId)).toContain(foreign!.id);
    const promote = await browserRequest(`/api/projects/${fixture.projectId}/members`, "POST", { ...memberBody, role: "admin" });
    expect(promote.status).toBe(201);

    // Simulate a project with two administrators; neither can demote the other.
    await identityEnv.DB.prepare("UPDATE project_members SET role='admin' WHERE project_id=? AND user_id=?")
      .bind(fixture.projectId, fixture.userId).run();
    const demote = await browserRequest(`/api/projects/${fixture.projectId}/members`, "POST", memberBody);
    expect(demote.status).toBe(403);
    const removeAdmin = await browserRequest(`/api/projects/${fixture.projectId}/members/${foreign!.id}`, "DELETE");
    expect(removeAdmin.status).toBe(403);
    const limitChange = await browserRequest(`/api/projects/${fixture.projectId}/limits`, "PUT", {
      maxPayloadBytes: 4096, maxConcurrency: 3, maxSessionSeconds: 120,
    });
    expect(limitChange.status).toBe(200);
    await identityEnv.DB.prepare("UPDATE project_members SET role='owner' WHERE project_id=? AND user_id=?")
      .bind(fixture.projectId, fixture.userId).run();
    const removeOwner = await browserRequest(`/api/projects/${fixture.projectId}/members/${fixture.userId}`, "DELETE");
    expect(removeOwner.status).toBe(403);
    const removed = await browserRequest(`/api/projects/${fixture.projectId}/members/${foreign!.id}`, "DELETE");
    expect(removed.status).toBe(200);
    expect(await identityEnv.DB.prepare("SELECT role FROM project_members WHERE project_id=? AND user_id=?")
      .bind(fixture.projectId, foreign!.id).first()).toBeNull();
  });

  it("rejects authenticated management writes without CSRF or from a foreign origin", async () => {
    const cookie = `__Host-identity_session=${fixture.browserToken}; __Host-identity_csrf=${fixture.csrfToken}`;
    for (const headers of [
      { cookie, origin: identityEnv.PUBLIC_ORIGIN },
      { cookie, origin: "https://attacker.example", "x-csrf-token": fixture.csrfToken },
    ]) {
      const response = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/api/projects`, {
        method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ name: "Blocked" }),
      }));
      expect(response.status).toBe(403);
    }
  });
});

async function seedIdentityDatabase(): Promise<IdentityFixture> {
  const now = Math.floor(Date.now() / 1000);
  const userIssuer = "https://accounts.integration.test";
  const subject = randomId("sub");
  const userId = randomId("usr");
  const projectId = randomId("prj");
  const confidentialClientRowId = randomId("client");
  const publicClientRowId = randomId("client");
  const foreignUserId = randomId("usr");
  const foreignProjectId = randomId("prj");
  const foreignPublicClientRowId = randomId("client");
  const confidentialClientId = randomId("cli");
  const publicClientId = randomId("cli");
  const foreignPublicClientId = randomId("cli");
  const refreshSessionId = randomId("ses");
  const browserSessionId = randomId("web");
  const refreshToken = `rfr-${randomProviderSecret()}`;
  const browserToken = randomProviderSecret();
  const csrfToken = randomProviderSecret();
  const confidentialClientSecret = randomProviderSecret();
  const secretHash = await sha256Base64Url(confidentialClientSecret);
  const refreshHash = await sha256Base64Url(refreshToken);
  const browserHash = await sha256Base64Url(browserToken);
  const csrfHash = await sha256Base64Url(csrfToken);

  await identityEnv.DB.prepare(
    "INSERT INTO user_allowlist (issuer, subject, email, is_admin, approved_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
  ).bind(userIssuer, subject, "integration-user@integration.test", now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO users (id, issuer, subject, email, display_name, active, created_at, updated_at) VALUES (?, ?, ?, ?, 'Integration User', 1, ?, ?)",
  ).bind(userId, userIssuer, subject, "integration-user@integration.test", now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO projects (id, owner_user_id, name, created_at) VALUES (?, ?, 'Integration Project', ?)",
  ).bind(projectId, userId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
  ).bind(projectId, userId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO clients (id, client_identifier, project_id, created_by, name, kind, secret_hash, active, created_at) VALUES (?, ?, ?, ?, 'Confidential integration client', 'confidential', ?, 1, ?)",
  ).bind(confidentialClientRowId, confidentialClientId, projectId, userId, secretHash, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO clients (id, client_identifier, project_id, created_by, name, kind, secret_hash, active, created_at) VALUES (?, ?, ?, ?, 'Public integration client', 'public', NULL, 1, ?)",
  ).bind(publicClientRowId, publicClientId, projectId, userId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO user_allowlist (issuer, subject, email, is_admin, approved_at, created_at) VALUES (?, ?, ?, 0, ?, ?)",
  ).bind(userIssuer, "foreign-subject", "foreign@integration.test", now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO users (id, issuer, subject, email, display_name, active, created_at, updated_at) VALUES (?, ?, 'foreign-subject', 'foreign@integration.test', 'Foreign User', 1, ?, ?)",
  ).bind(foreignUserId, userIssuer, now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO projects (id, owner_user_id, name, created_at) VALUES (?, ?, 'Foreign Project', ?)",
  ).bind(foreignProjectId, foreignUserId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
  ).bind(foreignProjectId, foreignUserId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO clients (id, client_identifier, project_id, created_by, name, kind, secret_hash, active, created_at) VALUES (?, ?, ?, ?, 'Foreign public client', 'public', NULL, 1, ?)",
  ).bind(foreignPublicClientRowId, foreignPublicClientId, foreignProjectId, foreignUserId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO sessions (id, user_id, project_id, kind, browser_token_hash, csrf_token_hash, device_name, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, 'web', ?, ?, 'integration browser', ?, ?, ?)",
  ).bind(browserSessionId, userId, projectId, browserHash, csrfHash, now, now + 3_600, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO sessions (id, user_id, project_id, client_id, kind, refresh_token_hash, device_name, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, 'refresh', ?, 'integration adapter', ?, ?, ?)",
  ).bind(refreshSessionId, userId, projectId, publicClientRowId, refreshHash, now, now + 86_400, now).run();

  return {
    userId,
    projectId,
    confidentialClientId,
    confidentialClientSecret,
    confidentialClientRowId,
    publicClientId,
    foreignPublicClientId,
    refreshSessionId,
    refreshToken,
    browserToken,
    csrfToken,
  };
}

async function postForm(form: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
  return SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(form).toString(),
  }));
}

function refresh(token: string, clientId = fixture.publicClientId): Promise<Response> {
  return postForm({ grant_type: "refresh_token", client_id: clientId, refresh_token: token });
}

function browserRequest(path: string, method = "GET", body?: unknown): Promise<Response> {
  return SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}${path}`, {
    method,
    headers: {
      cookie: `__Host-identity_session=${encodeURIComponent(fixture.browserToken)}; __Host-identity_csrf=${encodeURIComponent(fixture.csrfToken)}`,
      origin: identityEnv.PUBLIC_ORIGIN,
      "x-csrf-token": fixture.csrfToken,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
