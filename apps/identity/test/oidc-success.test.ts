import { createHash } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OidcCallbackFailure, parseOidcProviders, processOidcCallback, type OidcTransaction } from "../src/oidc.js";

const issuer = "https://accounts.google.com";
const clientId = "offline-google-client.apps.googleusercontent.com";
const clientSecret = "offline-google-client-secret";
const redirectUri = "https://identity.example.test/auth/oidc/callback";

describe("Google-shaped OIDC callback", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("exchanges the code and verifies a signed ID token through discovery and JWKS", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    const keyId = "offline-google-signing-key";
    const now = Math.floor(Date.now() / 1000);
    const accessToken = "offline-access-token";
    const nonce = "offline-callback-nonce";
    const subject = "google-subject-123";
    const email = "allowed-admin@example.test";
    const atHash = createHash("sha256").update(accessToken).digest().subarray(0, 16).toString("base64url");
    const idToken = await new SignJWT({
      sub: subject,
      aud: clientId,
      iat: now,
      exp: now + 300,
      nonce,
      at_hash: atHash,
      email,
      email_verified: true,
      name: "Offline Google User",
    })
      .setProtectedHeader({ alg: "RS256", kid: keyId, typ: "JWT" })
      .setIssuer(issuer)
      .sign(privateKey);
    const badNonce = "offline-nonce-that-must-not-be-disclosed";
    const badNonceToken = await new SignJWT({
      sub: subject,
      aud: clientId,
      iat: now,
      exp: now + 300,
      nonce: badNonce,
      at_hash: atHash,
      email,
      email_verified: true,
      name: "Offline Google User",
    })
      .setProtectedHeader({ alg: "RS256", kid: keyId, typ: "JWT" })
      .setIssuer(issuer)
      .sign(privateKey);
    let currentIdToken = idToken;

    const requests: Array<{ url: string; method: string; contentType: string | null }> = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      requests.push({ url: url.href, method: request.method, contentType: request.headers.get("content-type") });

      if (url.href === `${issuer}/.well-known/openid-configuration`) {
        return json({
          issuer,
          authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
          token_endpoint: "https://oauth2.googleapis.com/token",
          jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
          userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
          code_challenge_methods_supported: ["S256"],
          scopes_supported: ["openid", "email", "profile"],
        });
      }
      if (url.href === "https://oauth2.googleapis.com/token") {
        expect(request.method).toBe("POST");
        expect(request.headers.get("authorization")).toBeNull();
        expect(request.headers.get("content-type")).toContain("application/x-www-form-urlencoded");
        const form = new URLSearchParams(await request.text());
        expect(form.get("grant_type")).toBe("authorization_code");
        expect(["offline-authorization-code", "offline-code-that-must-not-be-disclosed"]).toContain(form.get("code"));
        expect(form.get("redirect_uri")).toBe(redirectUri);
        expect(form.get("code_verifier")).toBe("offline-pkce-verifier");
        expect(form.get("client_id")).toBe(clientId);
        expect(form.get("client_secret")).toBe(clientSecret);
        return json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, id_token: currentIdToken });
      }
      if (url.href === "https://www.googleapis.com/oauth2/v3/certs") {
        return json({ keys: [{ ...publicJwk, kid: keyId, alg: "RS256", use: "sig" }] });
      }
      return new Response("unexpected offline OIDC request", { status: 404 });
    });

    const provider = parseOidcProviders(JSON.stringify([{
      id: "google",
      label: "Google",
      issuer,
      clientId,
      clientSecret,
      redirectUri,
    }]))[0]!;
    const state = "offline-google-state-value-123456";
    const transaction: OidcTransaction = {
      stateHash: "offline-state-hash",
      state,
      provider,
      codeVerifier: "offline-pkce-verifier",
      nonce,
      redirectUri,
      returnTo: "/",
      expiresAt: now + 600,
    };
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", "offline-authorization-code");
    callback.searchParams.set("state", state);

    await expect(processOidcCallback(provider, callback, transaction, state)).resolves.toEqual({
      issuer,
      subject,
      email,
      displayName: "Offline Google User",
    });
    expect(requests.map(({ url, method }) => [new URL(url).hostname, method])).toEqual([
      ["accounts.google.com", "GET"],
      ["oauth2.googleapis.com", "POST"],
      ["www.googleapis.com", "GET"],
    ]);

    currentIdToken = badNonceToken;
    const badNonceCallback = new URL(callback);
    badNonceCallback.searchParams.set("code", "offline-code-that-must-not-be-disclosed");
    const failure = await processOidcCallback(provider, badNonceCallback, transaction, state).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(OidcCallbackFailure);
    expect(failure).toMatchObject({
      stage: "claims",
      reason: "OAUTH_JWT_CLAIM_COMPARISON_FAILED",
      claim: "nonce",
    });
    expect((failure as Error).message).not.toContain(badNonce);
    expect((failure as Error).message).not.toContain("offline-code-that-must-not-be-disclosed");
    expect((failure as Error).message).not.toContain(clientSecret);
  });
});

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}
