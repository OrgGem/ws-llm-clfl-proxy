import { describe, expect, it } from "vitest";
import {
  decryptCredentialEnvelope,
  issueGatewayAccessToken,
  verifyGatewayAccessToken,
} from "@ws-proxy/shared";
import { decideOidcAllowlist } from "../src/db.js";
import { assertBrowserWrite, type WebActor } from "../src/http.js";
import { createCredentialEnvelope, encodeBase64Url, readJson } from "../src/security.js";

describe("Identity security contracts", () => {
  it("encrypts provider keys into owner-bound envelopes and rejects tampering", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const encodedKey = encodeBase64Url(key);
    const keyConfig = JSON.stringify({ current: "env-v1", keys: { "env-v1": encodedKey } });
    const envelope = await createCredentialEnvelope("sk-provider-value", {
      credentialId: "cred-123",
      userId: "user-123",
      projectId: "project-123",
      provider: "openai",
      exp: 2_000_000_000,
    }, keyConfig);

    expect(JSON.stringify(envelope)).not.toContain("sk-provider-value");
    const decrypted = await decryptCredentialEnvelope(envelope, key, { now: 1_900_000_000 });
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe("sk-provider-value");
    expect(decrypted.metadata).toMatchObject({ credentialId: "cred-123", userId: "user-123", projectId: "project-123", provider: "openai" });

    await expect(decryptCredentialEnvelope({ ...envelope, projectId: "other-project" }, key, { now: 1_900_000_000 })).rejects.toThrow();
    const replacement = envelope.ciphertext.endsWith("A") ? "B" : "A";
    await expect(decryptCredentialEnvelope({ ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -1)}${replacement}` }, key, { now: 1_900_000_000 })).rejects.toThrow();
    await expect(decryptCredentialEnvelope(envelope, key, { now: 2_000_000_000 })).rejects.toThrow(/expired/i);
    decrypted.plaintext.fill(0);
    key.fill(0);
  });

  it("accepts only machine-token signatures with the configured issuer, audience, and expiry", async () => {
    const now = 1_900_000_000;
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const claims = { userId: "user-123", sessionId: "session-123", projectId: "project-123", clientId: "client-123", tokenId: "token-123" };
    const token = await issueGatewayAccessToken(claims, pair.privateKey, { issuer: "https://identity.example.test", kid: "sign-v1", now: now - 10 });
    const resolveKey = async (kid: string) => kid === "sign-v1" ? pair.publicKey : null;

    await expect(verifyGatewayAccessToken(token, resolveKey, { issuer: "https://identity.example.test", now })).resolves.toMatchObject({
      sub: "user-123",
      sid: "session-123",
      project_id: "project-123",
      client_id: "client-123",
    });
    await expect(verifyGatewayAccessToken(token, resolveKey, { issuer: "https://wrong.example.test", now })).rejects.toThrow();

    const wrongAudience = await issueGatewayAccessToken(claims, pair.privateKey, {
      issuer: "https://identity.example.test",
      audience: "another-service",
      kid: "sign-v1",
      now: now - 10,
    });
    await expect(verifyGatewayAccessToken(wrongAudience, resolveKey, { issuer: "https://identity.example.test", now })).rejects.toThrow();

    const expired = await issueGatewayAccessToken(claims, pair.privateKey, { issuer: "https://identity.example.test", kid: "sign-v1", now: now - 400 });
    await expect(verifyGatewayAccessToken(expired, resolveKey, { issuer: "https://identity.example.test", now })).rejects.toThrow();
  });

  it("keys OIDC allowlisting by issuer and subject even when email is shared", async () => {
    const allowlist = new Map<string, { is_admin: number; revoked_at: number | null; email: string }>();
    const pending = new Map<string, { email: string; displayName: string }>();
    const keyOf = (issuer: unknown, subject: unknown) => `${String(issuer)}\u0000${String(subject)}`;
    const db = {
      prepare(sql: string) {
        let params: unknown[] = [];
        const statement = {
          bind(...values: unknown[]) { params = values; return statement; },
          async first() {
            if (sql.startsWith("SELECT is_admin, revoked_at FROM user_allowlist")) return allowlist.get(keyOf(params[0], params[1])) ?? null;
            if (sql.includes("INSERT INTO user_allowlist")) {
              const pairKey = keyOf(params[0], params[1]);
              // The permanent bootstrap guard counts every prior admin row, including revoked admins.
              const adminEverExisted = [...allowlist.values()].some((row) => row.is_admin === 1);
              if (adminEverExisted || allowlist.has(pairKey)) return null;
              allowlist.set(pairKey, { is_admin: 1, revoked_at: null, email: String(params[2]) });
              return { is_admin: 1 };
            }
            throw new Error(`Unexpected query: ${sql}`);
          },
          async run() {
            if (sql.startsWith("UPDATE user_allowlist SET email")) {
              const row = allowlist.get(keyOf(params[1], params[2]));
              if (row) row.email = String(params[0]);
              return { success: true, meta: { changes: row ? 1 : 0 } };
            }
            if (sql.includes("INSERT INTO pending_identities")) {
              pending.set(keyOf(params[0], params[1]), { email: String(params[2]), displayName: String(params[3]) });
              return { success: true, meta: { changes: 1 } };
            }
            throw new Error(`Unexpected query: ${sql}`);
          },
        };
        return statement;
      },
    } as unknown as D1Database;

    const first = await decideOidcAllowlist(db, {
      issuer: "https://login.example.test",
      subject: "subject-one",
      email: "same@example.test",
      displayName: "First user",
    }, "same@example.test", 1_900_000_000);
    const bootstrapAdmin = allowlist.get(keyOf("https://login.example.test", "subject-one"));
    if (bootstrapAdmin) bootstrapAdmin.revoked_at = 1_900_000_005;
    const second = await decideOidcAllowlist(db, {
      issuer: "https://login.example.test",
      subject: "subject-two",
      email: "same@example.test",
      displayName: "Different user",
    }, "same@example.test", 1_900_000_010);

    expect(first).toMatchObject({ allowed: true, isAdmin: true, pending: false });
    expect(bootstrapAdmin?.revoked_at).toBe(1_900_000_005);
    expect(second).toMatchObject({ allowed: false, isAdmin: false, pending: true });
    expect(allowlist.has(keyOf("https://login.example.test", "subject-two"))).toBe(false);
    expect(pending.get(keyOf("https://login.example.test", "subject-two"))?.email).toBe("same@example.test");
  });

  it("requires same-origin requests and the session CSRF token for browser writes", async () => {
    const env = { PUBLIC_ORIGIN: "https://identity.example.test" } as unknown as Env;
    const actor = { csrfToken: "csrf-token-from-session" } as WebActor;
    const allowed = new Request("https://identity.example.test/api/clients", {
      method: "POST",
      headers: { origin: "https://identity.example.test", "sec-fetch-site": "same-origin", "x-csrf-token": "csrf-token-from-session" },
    });
    expect(await assertBrowserWrite(allowed, env, actor)).toBe(true);

    const wrongOrigin = new Request("https://identity.example.test/api/clients", {
      method: "POST",
      headers: { origin: "https://attacker.example", "x-csrf-token": "csrf-token-from-session" },
    });
    expect(await assertBrowserWrite(wrongOrigin, env, actor)).toBe(false);
    const wrongCsrf = new Request("https://identity.example.test/api/clients", {
      method: "POST",
      headers: { origin: "https://identity.example.test", "x-csrf-token": "wrong-token" },
    });
    expect(await assertBrowserWrite(wrongCsrf, env, actor)).toBe(false);
  });

  it("rejects malformed and non-object API JSON bodies", async () => {
    await expect(readJson(new Request("https://identity.example.test/api/clients", { method: "POST", body: "{" }))).rejects.toMatchObject({ code: "invalid_json" });
    await expect(readJson(new Request("https://identity.example.test/api/clients", { method: "POST", body: "[]" }))).rejects.toMatchObject({ code: "invalid_json" });
    await expect(readJson(new Request("https://identity.example.test/api/clients", { method: "POST", body: JSON.stringify({ apiKey: "x".repeat(16_385) }) }), 16_384)).rejects.toMatchObject({ code: "request_too_large" });
  });
});
