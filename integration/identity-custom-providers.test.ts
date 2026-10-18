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
  vi.restoreAllMocks();
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

  it("updates custom routes with CAS, keeps same-origin credentials, and revokes all credentials on origin change", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status, await created.clone().text()).toBe(201);

    const builtinUpdate = await browserRequest(admin, "/api/providers/openai", "PUT", {
      baseUrl: "https://proxy.example.org/v1/",
      expectedBaseUrl: "https://api.openai.com/v1/",
    });
    expect(builtinUpdate.status).toBe(403);

    const omittedExpected = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://api.example.org/openai/v1/",
    });
    expect(omittedExpected.status).toBe(400);
    expect(await omittedExpected.json()).toMatchObject({ error: "invalid_request" });

    const missingCsrf = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://api.example.org/openai/v1/",
      expectedBaseUrl: publicBaseUrl,
    }, false);
    expect(missingCsrf.status).toBe(403);

    const nonAdmin = await browserRequest(member, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://api.example.org/openai/v1/",
      expectedBaseUrl: publicBaseUrl,
    });
    expect(nonAdmin.status).toBe(403);

    const stale = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://api.example.org/openai/v1/",
      expectedBaseUrl: "https://stale.example.org/v1/",
    });
    expect(stale.status).toBe(409);
    expect(await stale.json()).toMatchObject({ error: "provider_conflict" });

    const missingCredentialVersion = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
    });
    expect(missingCredentialVersion.status).toBe(409);
    expect(await missingCredentialVersion.json()).toMatchObject({ error: "provider_conflict" });
    const staleCredentialVersion = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
      expectedBaseUrl: "https://stale.example.org/v1/",
    });
    expect(staleCredentialVersion.status).toBe(409);
    expect(await staleCredentialVersion.json()).toMatchObject({ error: "provider_conflict" });
    const beforeEnrollment = await identityEnv.DB.prepare("SELECT COUNT(*) AS count FROM credentials WHERE provider=?")
      .bind(providerId).first<{ count: number }>();
    expect(beforeEnrollment?.count).toBe(0);

    const credentialResponse = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
      expectedBaseUrl: publicBaseUrl,
    });
    expect(credentialResponse.status, await credentialResponse.clone().text()).toBe(201);
    const credential = await credentialResponse.json() as { credential: { id: string } };

    const sameOriginUrl = "https://api.example.org/openai/v1/";
    const sameOrigin = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://API.EXAMPLE.ORG:443/openai/v1",
      expectedBaseUrl: publicBaseUrl,
    });
    expect(sameOrigin.status, await sameOrigin.clone().text()).toBe(200);
    expect(await sameOrigin.json()).toMatchObject({
      provider: { id: providerId, baseUrl: sameOriginUrl, enabled: true },
      revokedCredentialCount: 0,
    });
    let credentialRow = await identityEnv.DB.prepare("SELECT revoked_at FROM credentials WHERE id=?")
      .bind(credential.credential.id).first<{ revoked_at: number | null }>();
    expect(credentialRow).toEqual({ revoked_at: null });

    const dnsCountBeforeNoop = dnsRequests.length;
    const noOp = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: sameOriginUrl,
      expectedBaseUrl: sameOriginUrl,
    });
    expect(noOp.status).toBe(200);
    expect(await noOp.json()).toMatchObject({ provider: { baseUrl: sameOriginUrl }, revokedCredentialCount: 0 });
    expect(dnsRequests).toHaveLength(dnsCountBeforeNoop);
    credentialRow = await identityEnv.DB.prepare("SELECT revoked_at FROM credentials WHERE id=?")
      .bind(credential.credential.id).first<{ revoked_at: number | null }>();
    expect(credentialRow).toEqual({ revoked_at: null });

    privateDnsHost = "private-update.integration.example.org";
    const privateTarget = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: `https://${privateDnsHost}/v2/`,
      expectedBaseUrl: sameOriginUrl,
    });
    expect(privateTarget.status).toBe(400);
    expect(await privateTarget.json()).toMatchObject({ error: "endpoint_not_allowed" });
    privateDnsHost = null;

    const newBaseUrl = "https://next.example.net/v2/";
    const crossOrigin = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: newBaseUrl,
      expectedBaseUrl: sameOriginUrl,
    });
    expect(crossOrigin.status, await crossOrigin.clone().text()).toBe(200);
    expect(await crossOrigin.json()).toMatchObject({
      provider: { id: providerId, baseUrl: newBaseUrl, enabled: true },
      revokedCredentialCount: 1,
    });
    credentialRow = await identityEnv.DB.prepare("SELECT revoked_at FROM credentials WHERE id=?")
      .bind(credential.credential.id).first<{ revoked_at: number | null }>();
    expect(credentialRow?.revoked_at).toEqual(expect.any(Number));
    const audit = await identityEnv.DB.prepare(
      "SELECT action,details_json FROM audit_events WHERE action='provider.base_url_updated' AND target_id=? ORDER BY rowid DESC LIMIT 1",
    ).bind(providerId).first<{ action: string; details_json: string }>();
    expect(audit?.action).toBe("provider.base_url_updated");
    expect(JSON.parse(audit!.details_json)).toEqual({
      oldBaseUrl: sameOriginUrl,
      newBaseUrl,
      originChanged: true,
      revokedCredentialCount: 1,
    });
  });

  it("rejects an enrollment when the observed route changes before the conditional insert", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status).toBe(201);

    await identityEnv.DB.prepare(
      `CREATE TRIGGER retarget_before_credential_insert AFTER INSERT ON rate_limits
       BEGIN UPDATE providers SET base_url='https://next.example.net/v1/' WHERE provider='private-gateway'; END`,
    ).run();
    const enrollment = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
      expectedBaseUrl: publicBaseUrl,
    });
    await identityEnv.DB.prepare("DROP TRIGGER retarget_before_credential_insert").run();
    expect(enrollment.status).toBe(409);
    expect(await enrollment.json()).toMatchObject({ error: "provider_conflict" });
    const updatedProvider = await identityEnv.DB.prepare("SELECT base_url AS baseUrl FROM providers WHERE provider=?")
      .bind(providerId).first<{ baseUrl: string }>();
    expect(updatedProvider?.baseUrl).toBe("https://next.example.net/v1/");
    const credentials = await identityEnv.DB.prepare("SELECT id,revoked_at FROM credentials WHERE provider=?")
      .bind(providerId).all<{ id: string; revoked_at: number | null }>();
    expect(credentials.results).toEqual([]);
  });

  it("rolls back route changes and credential revocation if the audit insert fails", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status).toBe(201);
    const credentialResponse = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
      expectedBaseUrl: publicBaseUrl,
    });
    expect(credentialResponse.status).toBe(201);
    const credential = await credentialResponse.json() as { credential: { id: string } };
    await identityEnv.DB.prepare(
      `CREATE TRIGGER fail_provider_base_audit BEFORE INSERT ON audit_events
       WHEN NEW.action='provider.base_url_updated'
       BEGIN SELECT RAISE(ABORT,'integration audit failure'); END`,
    ).run();

    let response: Response;
    try {
      response = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
        baseUrl: "https://next.example.net/v1/",
        expectedBaseUrl: publicBaseUrl,
      });
    } finally {
      await identityEnv.DB.prepare("DROP TRIGGER fail_provider_base_audit").run();
    }

    expect(response!.status).toBe(500);
    const provider = await identityEnv.DB.prepare("SELECT base_url AS baseUrl FROM providers WHERE provider=?")
      .bind(providerId).first<{ baseUrl: string }>();
    const storedCredential = await identityEnv.DB.prepare("SELECT revoked_at FROM credentials WHERE id=?")
      .bind(credential.credential.id).first<{ revoked_at: number | null }>();
    expect(provider).toEqual({ baseUrl: publicBaseUrl });
    expect(storedCredential).toEqual({ revoked_at: null });
  });

  it("does not send an old credential to a newly retargeted endpoint during connection test DNS validation", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status).toBe(201);
    const credentialResponse = await browserRequest(member, "/api/credentials", "POST", {
      projectId: member.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
      expectedBaseUrl: publicBaseUrl,
    });
    expect(credentialResponse.status).toBe(201);
    const credential = await credentialResponse.json() as { credential: { id: string }; envelope: unknown };

    let routeChangedDuringDns = false;
    let providerCalls = 0;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.origin === "https://cloudflare-dns.com" && url.pathname === "/dns-query") {
        const name = url.searchParams.get("name");
        const type = url.searchParams.get("type");
        dnsRequests.push(url);
        if (name === "api.example.org" && !routeChangedDuringDns) {
          routeChangedDuringDns = true;
          const changedAt = Math.floor(Date.now() / 1000);
          await identityEnv.DB.batch([
            identityEnv.DB.prepare("UPDATE providers SET base_url='https://next.example.net/v1/' WHERE provider=? AND base_url=?")
              .bind(providerId, publicBaseUrl),
            identityEnv.DB.prepare("UPDATE credentials SET revoked_at=? WHERE provider=? AND revoked_at IS NULL")
              .bind(changedAt, providerId),
          ]);
        }
        const answer = type === "A" ? [{ name, type: 1, TTL: 300, data: "8.8.8.8" }] : undefined;
        return new Response(JSON.stringify({ Status: 0, ...(answer ? { Answer: answer } : {}) }), {
          status: 200,
          headers: { "content-type": "application/dns-json" },
        });
      }
      providerCalls += 1;
      return new Response("unexpected provider call", { status: 200 });
    });

    const response = await browserRequest(member, `/api/credentials/${credential.credential.id}/test`, "POST", {
      envelope: credential.envelope,
    });
    expect(routeChangedDuringDns).toBe(true);
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "forbidden" });
    expect(providerCalls).toBe(0);
  });

  it("does not update a custom route when the admin session is revoked during DNS validation", async () => {
    const created = await browserRequest(admin, "/api/providers", "POST", {
      id: providerId,
      displayName: "Private Gateway",
      baseUrl: publicBaseUrl,
      protocol: "openai",
    });
    expect(created.status).toBe(201);

    dnsRequests = [];
    let unblockDns!: () => void;
    let dnsStarted!: () => void;
    const dnsGate = new Promise<void>((resolve) => { unblockDns = resolve; });
    const bothDnsQueriesStarted = new Promise<void>((resolve) => { dnsStarted = resolve; });
    let pendingDns = 0;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      dnsRequests.push(url);
      pendingDns += 1;
      if (pendingDns === 2) dnsStarted();
      await dnsGate;
      const type = url.searchParams.get("type");
      const answer = type === "A" ? [{ name: "api.example.org", type: 1, TTL: 300, data: "8.8.8.8" }] : undefined;
      return new Response(JSON.stringify({ Status: 0, ...(answer ? { Answer: answer } : {}) }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    });

    const updating = browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://api.example.org/openai/v1/",
      expectedBaseUrl: publicBaseUrl,
    });
    await bothDnsQueriesStarted;
    await identityEnv.DB.prepare("UPDATE sessions SET revoked_at=? WHERE browser_token_hash=?")
      .bind(Math.floor(Date.now() / 1000), await sha256Base64Url(admin.browserToken)).run();
    unblockDns();

    const response = await updating;
    expect(response.status).toBe(403);
    expect(dnsRequests.map((url) => url.searchParams.get("type")).sort()).toEqual(["A", "AAAA"]);
    const stored = await identityEnv.DB.prepare("SELECT base_url AS baseUrl FROM providers WHERE provider=?")
      .bind(providerId).first<{ baseUrl: string }>();
    expect(stored).toEqual({ baseUrl: publicBaseUrl });
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
      expectedBaseUrl: publicBaseUrl,
    });
    expect(ownCredentialResponse.status).toBe(201);
    const ownCredential = await ownCredentialResponse.json() as { credential: { id: string } };

    const foreignCredentialResponse = await browserRequest(foreign, "/api/credentials", "POST", {
      projectId: foreign.projectId,
      provider: providerId,
      apiKey: randomProviderSecret(),
      expectedBaseUrl: publicBaseUrl,
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

    await env.DB.prepare("INSERT INTO project_permissions (project_id,provider,model,created_by,created_at) VALUES (?,?,?,?,?)")
      .bind(member.projectId, providerId, modelAlias, member.userId, Math.floor(Date.now() / 1000)).run();
    const sameOriginUrl = "https://api.example.org/openai/v1/";
    const sameOrigin = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: sameOriginUrl,
      expectedBaseUrl: publicBaseUrl,
    });
    expect(sameOrigin.status).toBe(200);
    const retained = await identityInternal.authorizeTokenRequest({
      accessToken: token,
      credentialId: ownCredential.credential.id,
      provider: providerId,
      model: modelAlias,
    });
    expect(retained.allowed).toBe(true);
    expect(retained.authorizedProvider?.baseUrl).toBe(sameOriginUrl);

    const crossOrigin = await browserRequest(admin, `/api/providers/${providerId}`, "PUT", {
      baseUrl: "https://next.example.net/v2/",
      expectedBaseUrl: sameOriginUrl,
    });
    expect(crossOrigin.status).toBe(200);
    expect(await crossOrigin.json()).toMatchObject({ revokedCredentialCount: 2 });
    const globallyRevoked = await identityEnv.DB.prepare(
      "SELECT COUNT(*) AS count FROM credentials WHERE provider=? AND revoked_at IS NOT NULL",
    ).bind(providerId).first<{ count: number }>();
    expect(globallyRevoked?.count).toBe(2);
    const oldEnvelopeRejected = await identityInternal.authorizeTokenRequest({
      accessToken: token,
      credentialId: ownCredential.credential.id,
      provider: providerId,
      model: modelAlias,
    });
    expect(oldEnvelopeRejected).toMatchObject({ allowed: false, reasonCode: "credential_revoked" });
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
