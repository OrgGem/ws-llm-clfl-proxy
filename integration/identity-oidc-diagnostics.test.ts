import { env, reset, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { migrateIdentityDatabase, randomProviderSecret } from "./db-fixtures.js";

interface OidcDiagnosticEnv {
  DB: D1Database;
  PUBLIC_ORIGIN: string;
  OIDC_PROVIDERS: string;
}

interface TestProvider {
  id: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

const identityEnv = env as unknown as OidcDiagnosticEnv;

beforeEach(async () => {
  await reset();
  await migrateIdentityDatabase(identityEnv.DB);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("OIDC callback diagnostics", () => {
  it("rejects a callback without its browser state cookie before contacting discovery", async () => {
    const provider = (JSON.parse(identityEnv.OIDC_PROVIDERS) as TestProvider[]).find(({ id }) => id === "provider-a");
    expect(provider).toBeDefined();
    const state = randomProviderSecret();
    const now = Math.floor(Date.now() / 1000);
    await identityEnv.DB.prepare(
      "INSERT INTO oidc_transactions (state_hash,provider_key,code_verifier,nonce,redirect_uri,return_to,expires_at) VALUES (?,?,?,?,?,?,?)",
    ).bind(await sha256Base64Url(state), provider!.id, randomProviderSecret(), randomProviderSecret(), provider!.redirectUri, "/", now + 600).run();

    const observed: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      observed.push(input instanceof Request ? input.url : String(input));
      return new Response(null, { status: 503 });
    });
    const callbackUrl = new URL(provider!.redirectUri);
    callbackUrl.searchParams.set("code", "synthetic-code");
    callbackUrl.searchParams.set("state", state);
    const response = await SELF.fetch(new Request(callbackUrl));

    expect(response.status).toBe(400);
    expect(response.headers.get("x-oidc-error")).toBeNull();
    expect(observed).toEqual([]);
    const row = await identityEnv.DB.prepare("SELECT state_hash FROM oidc_transactions WHERE state_hash=?")
      .bind(await sha256Base64Url(state)).first();
    expect(row).not.toBeNull();
  });

  it("returns only a safe OAuth classification, never response details or callback credentials", async () => {
    const provider = (JSON.parse(identityEnv.OIDC_PROVIDERS) as TestProvider[]).find(({ id }) => id === "provider-a");
    expect(provider).toBeDefined();
    const state = randomProviderSecret();
    const codeVerifier = randomProviderSecret();
    const nonce = randomProviderSecret();
    const authorizationCode = "synthetic-auth-code-never-return-this";
    const secretMarker = "synthetic-client-secret-never-return-this";
    const descriptionMarker = "synthetic-error-description-never-return-this";
    const now = Math.floor(Date.now() / 1000);
    await identityEnv.DB.prepare(
      "INSERT INTO oidc_transactions (state_hash,provider_key,code_verifier,nonce,redirect_uri,return_to,expires_at) VALUES (?,?,?,?,?,?,?)",
    ).bind(
      await sha256Base64Url(state),
      provider!.id,
      codeVerifier,
      nonce,
      provider!.redirectUri,
      "/",
      now + 600,
    ).run();

    const observed: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      observed.push(`${request.method} ${url.origin}${url.pathname}`);
      if (url.href === `${provider!.issuer}/.well-known/openid-configuration`) {
        return json({
          issuer: provider!.issuer,
          authorization_endpoint: `${provider!.issuer}/authorize`,
          token_endpoint: "https://oidc-a.integration.test/token",
          jwks_uri: "https://oidc-a.integration.test/jwks",
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
          code_challenge_methods_supported: ["S256"],
        });
      }
      if (url.href === "https://oidc-a.integration.test/token") {
        expect(request.method).toBe("POST");
        expect(request.headers.get("authorization")).toMatch(/^Basic /);
        const form = await request.formData();
        expect(form.get("code")).toBe(authorizationCode);
        expect(form.get("client_id")).toBeNull();
        expect(form.get("client_secret")).toBeNull();
        return new Response(JSON.stringify({
          error: "invalid_client",
          error_description: `${descriptionMarker} ${secretMarker} ${authorizationCode}`,
        }), { status: 401, headers: { "content-type": "application/json" } });
      }
      return new Response("unexpected synthetic request", { status: 404 });
    });

    const callbackUrl = new URL(provider!.redirectUri);
    callbackUrl.searchParams.set("code", authorizationCode);
    callbackUrl.searchParams.set("state", state);
    const response = await SELF.fetch(new Request(callbackUrl, {
      headers: { cookie: `__Host-oidc_${state}=${state}` },
    }));

    expect(response.status).toBe(401);
    expect(response.headers.get("x-oidc-error")).toBe("token_response:invalid_client");
    const exposed = `${await response.text()}\n${[...response.headers.entries()].map(([name, value]) => `${name}: ${value}`).join("\n")}`;
    expect(exposed).toContain("Sign-in could not be verified. Please start again.");
    expect(exposed).not.toContain(authorizationCode);
    expect(exposed).not.toContain(secretMarker);
    expect(exposed).not.toContain(descriptionMarker);
    expect(exposed).not.toContain(callbackUrl.href);
    expect(observed).toContain("POST https://oidc-a.integration.test/token");
  });
});

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
