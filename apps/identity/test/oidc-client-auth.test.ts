import { afterEach, describe, expect, it, vi } from "vitest";
import { OidcCallbackFailure, parseOidcProviders, processOidcCallback, type OidcTransaction } from "../src/oidc.js";

const redirectUri = "https://identity.example.test/auth/oidc/callback";

afterEach(() => vi.unstubAllGlobals());

describe("OIDC token endpoint client authentication", () => {
  it.each([
    ["unsupported method", ["private_key_jwt"]],
    ["malformed non-array metadata", "client_secret_post"],
  ])("fails closed for %s", async (_name, advertisedMethods) => {
    const issuer = `https://auth-method-${Math.random().toString(36).slice(2)}.example.test`;
    const provider = parseOidcProviders(JSON.stringify([{
      id: "test-provider",
      issuer,
      clientId: "unit-test-client",
      clientSecret: "unit-test-secret",
      redirectUri,
    }]))[0]!;
    const state = "unit-test-state-that-is-long-enough";
    const transaction: OidcTransaction = {
      stateHash: "not-used",
      state,
      provider,
      codeVerifier: "unit-test-verifier",
      nonce: "unit-test-nonce",
      redirectUri,
      returnTo: "/",
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    };
    const requests: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      requests.push(url.href);
      if (url.pathname === "/.well-known/openid-configuration") {
        return json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: advertisedMethods,
        });
      }
      return new Response("unexpected request", { status: 404 });
    });
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", "synthetic-code");
    callback.searchParams.set("state", state);

    const failure = await processOidcCallback(provider, callback, transaction, state).then(
      () => undefined,
      (error: unknown) => error,
    );

    expect(failure).toBeInstanceOf(OidcCallbackFailure);
    expect((failure as OidcCallbackFailure).reason).toBe("OAUTH_UNSUPPORTED_OPERATION");
    expect(requests).toHaveLength(1);
    expect(requests[0]).toContain("/.well-known/openid-configuration");
  });
});

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}
