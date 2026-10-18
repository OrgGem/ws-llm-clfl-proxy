import { describe, expect, it, vi } from "vitest";
import { parseClientBootstrap } from "../../adapter/src/auth.js";
import { ApiError, createApiClient } from "../public/api.js";
import { safeBootstrapMetadata } from "../public/bootstrap.js";
import { isTimestampExpired } from "../public/dates.js";

describe("Identity browser API client", () => {
  it("sends provider keys only in same-origin POST bodies with the session CSRF header", async () => {
    const secret = "provider-secret-never-put-in-a-url";
    let requestUrl: URL | undefined;
    let requestInit: RequestInit | undefined;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requestUrl = new URL(input instanceof Request ? input.url : String(input));
      requestInit = init;
      return new Response(JSON.stringify({ envelope: { v: 1 } }), { status: 201, headers: { "content-type": "application/json" } });
    });
    const api = createApiClient({
      origin: "https://identity.example.test",
      fetchImpl,
      getCsrfToken: () => "csrf-in-memory-only",
    });

    await api.post("/api/credentials", { projectId: "project-1", provider: "openai", apiKey: secret });

    expect(requestUrl?.origin).toBe("https://identity.example.test");
    expect(requestUrl?.pathname).toBe("/api/credentials");
    expect(requestUrl?.search).toBe("");
    expect(requestUrl?.toString()).not.toContain(secret);
    expect(requestInit?.method).toBe("POST");
    expect(new Headers(requestInit?.headers).get("X-CSRF-Token")).toBe("csrf-in-memory-only");
    expect(new Headers(requestInit?.headers).get("Content-Type")).toBe("application/json");
    expect(requestInit?.body).toContain(secret);
    expect(requestInit?.credentials).toBe("same-origin");
    expect(requestInit?.cache).toBe("no-store");
    expect(requestInit?.redirect).toBe("error");
    expect(requestInit?.referrerPolicy).toBe("same-origin");
  });

  it("does not send a CSRF token on reads and avoids cache or cross-origin redirects", async () => {
    let requestInit: RequestInit | undefined;
    const api = createApiClient({
      origin: "https://identity.example.test",
      getCsrfToken: () => "secret-csrf",
      fetchImpl: async (_input, init) => {
        requestInit = init;
        return new Response(JSON.stringify({ authenticated: false }), { status: 200, headers: { "content-type": "application/json" } });
      },
    });

    await api.get("/api/session");

    expect(requestInit?.method).toBe("GET");
    expect(new Headers(requestInit?.headers).has("X-CSRF-Token")).toBe(false);
    expect(requestInit?.credentials).toBe("same-origin");
    expect(requestInit?.cache).toBe("no-store");
    expect(requestInit?.redirect).toBe("error");
  });

  it("rejects URLs outside the same-origin API path before calling fetch", async () => {
    const fetchImpl = vi.fn();
    const api = createApiClient({ origin: "https://identity.example.test", fetchImpl, getCsrfToken: () => "csrf" });

    expect(() => api.get("https://attacker.example/api/session")).toThrow(/same origin/i);
    expect(() => api.get("//attacker.example/api/session")).toThrow(/same origin/i);
    expect(() => api.get("/auth/oidc/start")).toThrow(/under \/api\//i);
    await expect(api.post("/api/credentials?apiKey=secret", { provider: "openai" })).rejects.toThrow(/must not put data in the URL/i);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("fails closed on mutations when the session has no CSRF token", async () => {
    const fetchImpl = vi.fn();
    const api = createApiClient({ origin: "https://identity.example.test", fetchImpl });

    await expect(api.post("/api/clients", { name: "adapter" })).rejects.toMatchObject({
      name: "ApiError",
      status: 403,
    } satisfies Partial<ApiError>);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("omits CSRF only for the exact setup login POST", async () => {
    const password = "temporary-bootstrap-password";
    let requestUrl: URL | undefined;
    let requestInit: RequestInit | undefined;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requestUrl = new URL(input instanceof Request ? input.url : String(input));
      requestInit = init;
      return new Response(JSON.stringify({ csrfToken: "setup-csrf" }), { status: 200, headers: { "content-type": "application/json" } });
    });
    const api = createApiClient({ origin: "https://identity.example.test", fetchImpl });

    await api.postSetupLogin({ password });

    expect(requestUrl?.pathname).toBe("/api/setup/login");
    expect(requestUrl?.search).toBe("");
    expect(requestInit?.method).toBe("POST");
    expect(new Headers(requestInit?.headers).has("X-CSRF-Token")).toBe(false);
    expect(requestInit?.body).toBe(JSON.stringify({ password }));
    await expect(api.post("/api/setup/oidc", { providers: [] })).rejects.toMatchObject({ status: 403 });
    await expect(api.request("/api/setup/login", { method: "PUT", body: { password } })).rejects.toMatchObject({ status: 403 });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does not echo error response bodies that could contain submitted secrets", async () => {
    const secret = "provider-secret-never-echo";
    const api = createApiClient({
      origin: "https://identity.example.test",
      getCsrfToken: () => "csrf",
      fetchImpl: async () => new Response(JSON.stringify({ error: secret }), { status: 500 }),
    });

    await expect(api.post("/api/credentials", { apiKey: secret })).rejects.toThrow("The request could not be completed. Try again.");
  });

  it("projects setup downloads to the adapter's strict schema and strips secrets", () => {
    const response = {
      version: 1,
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/v1/socket",
      projectId: "project-1",
      client: { id: "client-1", clientId: "cli-1", name: "Local", kind: "confidential", clientSecret: "client-secret" },
      models: [{ provider: "openai", id: "fast-chat", upstreamModel: "internal-model" }],
      credentials: [{ id: "cred-1", provider: "openai", keyVersion: "env-v1", apiKey: "provider-secret", envelope: { ciphertext: "sensitive-envelope" } }],
      limits: { maxPayloadBytes: 65536, maxConcurrency: 2, maxSessionSeconds: 60 },
      accessToken: "machine-token",
    };

    const safe = safeBootstrapMetadata(response);

    expect(safe).toEqual({
      version: 1,
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/v1/socket",
      client: { clientId: "cli-1", kind: "confidential" },
      projectId: "project-1",
      models: [{ id: "fast-chat", provider: "openai" }],
      limits: { maxPayloadBytes: 65536, maxConcurrency: 2, maxSessionSeconds: 60 },
    });
    expect(parseClientBootstrap(safe)).toEqual(safe);
    const serialized = JSON.stringify(safe);
    for (const secret of ["client-secret", "provider-secret", "sensitive-envelope", "machine-token", "internal-model"]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("treats D1 session expiry timestamps as Unix seconds", () => {
    const now = Date.UTC(2026, 9, 17, 12, 0, 0);
    const nowSeconds = now / 1000;

    expect(isTimestampExpired(nowSeconds + 60, now)).toBe(false);
    expect(isTimestampExpired(nowSeconds - 1, now)).toBe(true);
    expect(isTimestampExpired(now + 60_000, now)).toBe(false);
    expect(isTimestampExpired(nowSeconds, now)).toBe(true);
  });
});
