import { describe, expect, it } from "vitest";
import { parseOidcProviders, processOidcCallback, type OidcTransaction } from "../src/oidc.js";

describe("OIDC callback binding", () => {
  it("keeps query-free registered callback URIs and pinned issuer paths intact", () => {
    const providers = parseOidcProviders(JSON.stringify([{
      id: "org",
      label: "Organization",
      issuer: "https://login.example.test/tenant/",
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://identity.example.test/auth/oidc/callback",
    }]));
    expect(providers).toHaveLength(1);
    expect(providers[0]?.issuer.href).toBe("https://login.example.test/tenant/");
    expect(providers[0]?.redirectUri).toBe("https://identity.example.test/auth/oidc/callback");
  });

  it("rejects a valid callback query state when the browser transaction cookie is absent or mismatched", async () => {
    const provider = parseOidcProviders(JSON.stringify([{
      id: "org",
      issuer: "https://login.example.test/tenant/",
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://identity.example.test/auth/oidc/callback",
    }]))[0]!;
    const transaction: OidcTransaction = {
      stateHash: "not-used-before-cookie-check",
      state: "browser-bound-state",
      provider,
      codeVerifier: "verifier",
      nonce: "nonce",
      redirectUri: provider.redirectUri,
      returnTo: "/",
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    };
    const validQueryState = new URL("https://identity.example.test/auth/oidc/callback?code=authorization-code&state=browser-bound-state");
    await expect(processOidcCallback(provider, validQueryState, transaction, undefined)).rejects.toThrow(/state validation/i);
    await expect(processOidcCallback(provider, validQueryState, transaction, "attacker-state")).rejects.toThrow(/state validation/i);
  });
});
