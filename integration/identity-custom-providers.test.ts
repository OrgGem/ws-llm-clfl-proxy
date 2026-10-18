import { env, reset, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IdentityInternal } from "../apps/identity/src/identity-service.js";
import { migrateIdentityDatabase, randomId, randomProviderSecret } from "./db-fixtures.js";

interface IdentityCustomProviderEnv {
  DB: D1Database;
  PUBLIC_ORIGIN: string;
  MACHINE_ISSUER: string;
}

interface BrowserActor {
  userId: string;
  projectId: string;
  browserToken: string;
  csrfToken: string;
}

interface ProviderResponse {
  provider: {
    id: string;
    displayName: string;
    baseUrl: string;
    protocol: "openai" | "anthropic";
    custom: boolean;
    enabled: boolean;
  };
}

const identityEnv = env as unknown as IdentityCustomProviderEnv;
const providerId = "private-gateway";
const publicBaseUrl = "https://api.example.org/v1/";
const modelAlias = "custom-chat";
let admin: BrowserActor;
let member: BrowserActor;
let foreign: BrowserActor;
let dnsRequests: URL[];
let privateDnsHost: string | null;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(identityEnv.DB);
  dnsRequests = [];
  privateDnsHost = null;
  installDnsStub();
  admin = await seedBrowserActor("provider-admin", true);
  member = await seedBrowserActor("provider-member", false);
  foreign = await seedBrowserActor("provider-foreign", false);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Identity custom provider registry integration", () => {
  it("allows only a CSRF-authenticated global administrator to create a normalized public HTTPS endpoint", async () => {
    const body = {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: "HTTPS://API.EXAMPLE.ORG:443/v1/",
      protocol: "openai",
    };

    const missingCsrf = await browserRequest(admin, "/api/providers", "POST", body, false);
    expect(missingCsrf.status).toBe(403);

    const nonAdmin = await browserRequest(member, "/api/providers", "POST", body);
    expect(nonAdmin.status).toBe(403);

    const created = await browserRequest(admin, "/api/providers", "POST", body);
    expect(created.status, await created.clone().text()).toBe(201);
    const result = await created.json() as ProviderResponse;
    expect(result.provider).toEqual({
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
      custom: true,
      enabled: true,
    });
    expect(new Set(dnsRequests.map((url) => url.searchParams.get("type")))).toEqual(new Set(["A", "AAAA"]));
    expect(dnsRequests.every((url) => url.origin === "https://cloudflare-dns.com" && url.pathname === "/dns-query" && url.searchParams.get("name") === "api.example.org")).toBe(true);

    const stored = await identityEnv.DB.prepare("SELECT protocol,base_url,custom,enabled FROM providers WHERE provider=?")
      .bind(providerId).first<{ protocol: string; base_url: string; custom: number; enabled: number }>();
    expect(stored).toEqual({ protocol: "openai", base_url: publicBaseUrl, custom: 1, enabled: 1 });

    const providerList = await browserRequest(admin, `/api/providers?projectId=${admin.projectId}`);
    expect(providerList.status).toBe(200);
    const list = await providerList.json() as { providers: Array<Record<string, unknown>> };
    expect(list.providers).toContainEqual(expect.objectContaining({
      provider: providerId,
      protocol: "openai",
      baseUrl: publicBaseUrl,
      custom: true,
    }));
  });

  it("fails closed when a custom hostname resolves to any private address", async () => {
    privateDnsHost = "private.integration.example.org";
    const response = await browserRequest(admin, "/api/providers", "POST", {
      id: "private-dns",
      displayName: "Private DNS",
      baseUrl: "https://private.integration.example.org/v1/",
      protocol: "openai",
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "endpoint_not_allowed" });
    expect(dnsRequests.map((url) => url.searchParams.get("type")).sort()).toEqual(["A", "AAAA"]);
    const stored = await identityEnv.DB.prepare("SELECT provider FROM providers WHERE provider='private-dns'").first();
    expect(stored).toBeNull();
  });

  it("keeps a registered provider endpoint immutable when its ID is reused", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status, await created.clone().text()).toBe(201);

    const conflict = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Changed Gateway",
      baseUrl: "https://changed.example.org/v2/",
      protocol: "openai",
    });
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({ error: "provider_exists" });
    const stored = await identityEnv.DB.prepare("SELECT display_name,base_url FROM providers WHERE provider=?")
      .bind(providerId).first<{ display_name: string; base_url: string }>();
    expect(stored).toEqual({ display_name: "Private Gateway", base_url: publicBaseUrl });

    const disabled = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", { enabled: false });
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toMatchObject({ provider: { id: providerId, enabled: false, baseUrl: publicBaseUrl } });
    const enabledAgain = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", { enabled: true });
    expect(enabledAgain.status).toBe(200);
    expect(await enabledAgain.json()).toMatchObject({ provider: { id: providerId, enabled: true, baseUrl: publicBaseUrl } });
  });

  it("does not enable a provider when the administrator session is revoked while DNS validation is pending", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status, await created.clone().text()).toBe(201);
    const disabled = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", { enabled: false });
    expect(disabled.status).toBe(200);

    dnsRequests = [];
    let unblockDns!: () => void;
    let dnsBlocked!: () => void;
    const dnsGate = new Promise<void>((resolve) => { unblockDns = resolve; });
    const bothDnsQueriesStarted = new Promise<void>((resolve) => { dnsBlocked = resolve; });
    let pendingDns = 0;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      dnsRequests.push(url);
      pendingDns += 1;
      if (pendingDns === 2) dnsBlocked();
      await dnsGate;
      const type = url.searchParams.get("type");
      const answer = type === "A" ? [{ name: "api.example.org", type: 1, TTL: 300, data: "8.8.8.8" }] : undefined;
      return new Response(JSON.stringify({ Status: 0, ...(answer ? { Answer: answer } : {}) }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    });

    const enabling = browserRequest(admin, `/api/providers/${providerId}`, "PUT", { enabled: true });
    await bothDnsQueriesStarted;
    await identityEnv.DB.prepare("UPDATE sessions SET revoked_at=? WHERE browser_token_hash=?")
      .bind(Math.floor(Date.now() / 1000), await sha256Base64Url(admin.browserToken))
      .run();
    unblockDns();

    const response = await enabling;
    expect(response.status).toBe(403);
    expect(dnsRequests.map((url) => url.searchParams.get("type")).sort()).toEqual(["A", "AAAA"]);
    const stored = await identityEnv.DB.prepare("SELECT enabled FROM providers WHERE provider=?")
      .bind(providerId).first<{ enabled: number }>();
    expect(stored).toEqual({ enabled: 0 });
  });

  it("authorizes only granted models and owner credentials, returning the registry endpoint rather than a client-supplied URL", async () => {
    const registered = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(registered.status, await registered.clone().text()).toBe(201);

    const invalidAlias = await browserRequest(admin, "/api/providers/models", "POST", {
      provider: providerId,
      alias: "org/alias",
      upstreamModel: "org/model",
      displayName: "Invalid Alias",
    });
    expect(invalidAlias.status).toBe(400);

    const model = await browserRequest(admin, "/api/providers/models", "POST", {
      provider: providerId,
      alias: modelAlias,
      upstreamModel: "org/model",
      displayName: "Custom Chat",
    });
    expect(model.status).toBe(201);

    const permission = await browserRequest(member, "/api/permissions", "POST", {
      projectId: member.projectId,
      provider: providerId,
      model: modelAlias,
      allowed: true,
    });
    expect(permission.status).toBe(200);

    const clientResponse = await browserRequest(member, "/api/clients", "POST", {
      projectId: member.projectId,
      name: "Custom provider adapter",
      kind: "confidential",
      models: [{ provider: providerId, model: modelAlias }],
    });
    expect(clientResponse.status).toBe(201);
    const client = await clientResponse.json() as {
      client: { clientIdentifier: string };
      clientSecret: string;
    };

    const ownCredentialResponse = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
    });
    expect(ownCredentialResponse.status).toBe(201);
    const ownCredential = await ownCredentialResponse.json() as { credential: { id: string } };

    const foreignCredentialResponse = await browserRequest(foreign, "/api/credentials", "POST", {
      projectId: foreign.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
    });
    expect(foreignCredentialResponse.status).toBe(201);
    const foreignCredential = await foreignCredentialResponse.json() as { credential: { id: string } };

    const tokenResponse = await SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}/oauth/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${btoa(`${client.client.clientIdentifier}:${client.clientSecret}`)}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_type: "client_credentials" }).toString(),
    }));
    expect(tokenResponse.status).toBe(200);
    const token = (await tokenResponse.json() as { access_token: string }).access_token;

    const identityInternal = new IdentityInternal({} as ExecutionContext, env as unknown as Env);
    const allowed = await identityInternal.authorizeTokenRequest({
      accessToken: token,
      credentialId: ownCredential.credential.id,
      provider: providerId,
      model: modelAlias,
      baseUrl: "https://attacker.example/",
    } as Parameters<IdentityInternal["authorizeTokenRequest"]>[0] & { baseUrl: string });
    expect(allowed.allowed).toBe(true);
    expect(allowed.authorizedModel).toEqual({ alias: modelAlias, upstreamModel: "org/model" });
    expect(allowed.authorizedProvider).toMatchObject({ id: providerId, protocol: "openai", baseUrl: publicBaseUrl, custom: true });
    expect(allowed.authorizedProvider?.baseUrl).not.toContain("attacker.example");

    const crossUser = await identityInternal.authorizeTokenRequest({
      accessToken: token,
      credentialId: foreignCredential.credential.id,
      provider: providerId,
      model: modelAlias,
    });
    expect(crossUser).toMatchObject({ allowed: false, reasonCode: "credential_owner_mismatch" });

    await identityEnv.DB.prepare("DELETE FROM project_permissions WHERE project_id=? AND provider=? AND model=?")
      .bind(member.projectId, providerId, modelAlias).run();
    const deniedModel = await identityInternal.authorizeTokenRequest({
      accessToken: token,
      credentialId: ownCredential.credential.id,
      provider: providerId,
      model: modelAlias,
    });
    expect(deniedModel).toMatchObject({ allowed: false, reasonCode: "provider_or_model_not_allowed" });
  });
});

function installDnsStub(): void {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== "https://cloudflare-dns.com" || url.pathname !== "/dns-query") {
      return new Response("unexpected fetch", { status: 502 });
    }
    dnsRequests.push(url);
    const name = url.searchParams.get("name");
    const type = url.searchParams.get("type");
    if (type === "A") {
      const data = name === privateDnsHost ? "10.1.2.3" : "8.8.8.8";
      return new Response(JSON.stringify({ Status: 0, Answer: [{ name, type: 1, TTL: 300, data }] }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    if (type === "AAAA") {
      return new Response(JSON.stringify({ Status: 0 }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    return new Response(JSON.stringify({ Status: 4 }), {
      status: 200,
      headers: { "content-type": "application/dns-json" },
    });
  });
}

async function seedBrowserActor(prefix: string, isAdmin: boolean): Promise<BrowserActor> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = "https://accounts.integration.test";
  const subject = randomId("sub");
  const userId = randomId("usr");
  const projectId = randomId("prj");
  const sessionId = randomId("web");
  const browserToken = randomProviderSecret();
  const csrfToken = randomProviderSecret();

  await identityEnv.DB.prepare(
    "INSERT INTO user_allowlist (issuer,subject,email,is_admin,approved_at,created_at) VALUES (?,?,?,?,?,?)",
  ).bind(issuer, subject, `${prefix}@integration.test`, isAdmin ? 1 : 0, now, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO users (id,issuer,subject,email,display_name,active,created_at,updated_at) VALUES (?,?,?,?,?,1,?,?)",
  ).bind(userId, issuer, subject, `${prefix}@integration.test`, prefix, now, now).run();
  await identityEnv.DB.prepare("INSERT INTO projects (id,owner_user_id,name,created_at) VALUES (?,?,?,?)")
    .bind(projectId, userId, `${prefix} project`, now).run();
  await identityEnv.DB.prepare("INSERT INTO project_members (project_id,user_id,role,created_at) VALUES (?,?,'owner',?)")
    .bind(projectId, userId, now).run();
  await identityEnv.DB.prepare(
    "INSERT INTO sessions (id,user_id,project_id,kind,browser_token_hash,csrf_token_hash,device_name,created_at,expires_at,last_seen_at) VALUES (?,?,?,'web',?,?,?, ?,?,?)",
  ).bind(
    sessionId,
    userId,
    projectId,
    await sha256Base64Url(browserToken),
    await sha256Base64Url(csrfToken),
    `${prefix} browser`,
    now,
    now + 3_600,
    now,
  ).run();
  return { userId, projectId, browserToken, csrfToken };
}

function browserRequest(
  actor: BrowserActor,
  path: string,
  method = "GET",
  body?: unknown,
  includeCsrf = true,
): Promise<Response> {
  const headers = new Headers({
    cookie: `__Host-identity_session=${encodeURIComponent(actor.browserToken)}; __Host-identity_csrf=${encodeURIComponent(actor.csrfToken)}`,
  });
  if (method !== "GET" && method !== "HEAD") {
    headers.set("origin", identityEnv.PUBLIC_ORIGIN);
    headers.set("sec-fetch-site", "same-origin");
    if (includeCsrf) headers.set("x-csrf-token", actor.csrfToken);
  }
  if (body !== undefined) {
    headers.set("content-type", "application/json");
  }
  return SELF.fetch(new Request(`${identityEnv.PUBLIC_ORIGIN}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
