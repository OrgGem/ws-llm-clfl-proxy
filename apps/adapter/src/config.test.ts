import { chmod, mkdtemp, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigStore, createInitialConfig, validateConfig } from "./config.js";

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("local configuration security", () => {
  it("creates a private config with generated local API bearer credentials", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "adapter-config-"));
    dirs.push(directory);
    const store = new ConfigStore(path.join(directory, "state", "adapter.json"));
    const config = createInitialConfig({
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/session",
      auth: { type: "public", clientId: "client_1", refreshToken: "opaque-refresh-token" },
    });
    await store.save(config);
    const saved = await store.load();
    expect(saved.localBearerToken).toHaveLength(43);
    expect((await stat(store.filePath)).mode & 0o777).toBe(0o600);
    expect((await stat(path.dirname(store.filePath))).mode & 0o777).toBe(0o700);
  });

  it("rejects non-loopback cleartext machine endpoints and mismatched envelopes", () => {
    expect(() => createInitialConfig({
      identityUrl: "http://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/session",
      auth: { type: "confidential", clientId: "id", clientSecret: "secret" },
    })).toThrow("must use HTTPS");
    expect(() => validateConfig({
      version: 1,
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/session",
      auth: { type: "public", clientId: "id", refreshToken: "refresh" },
      localBearerToken: "x".repeat(32),
      models: [{ id: "model", provider: "openai", credentialId: "missing" }],
      envelopes: [],
    })).toThrow("unknown credential ID");
  });

  it("rejects query strings on the Gateway URL", () => {
    expect(() => createInitialConfig({
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/session?token=secret",
      auth: { type: "confidential", clientId: "id", clientSecret: "secret" },
    })).toThrow("cannot contain credentials, query, or fragment");
  });

  it("accepts bracketed IPv6 loopback URLs for local development", () => {
    const config = createInitialConfig({
      identityUrl: "http://[::1]:3000",
      gatewayUrl: "ws://[::1]:8787/v1/socket",
      auth: { type: "public", clientId: "client_1", refreshToken: "opaque-refresh-token" },
    });
    expect(config.identityUrl).toBe("http://[::1]:3000");
    expect(config.gatewayUrl).toBe("ws://[::1]:8787/v1/socket");
  });

  it("does not change permissions on a pre-existing custom parent directory", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "adapter-custom-parent-"));
    dirs.push(directory);
    if (process.platform !== "win32") await chmod(directory, 0o755);
    const store = new ConfigStore(path.join(directory, "adapter.json"));
    const config = createInitialConfig({
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/v1/socket",
      auth: { type: "public", clientId: "client_1", refreshToken: "opaque-refresh-token" },
    });

    await store.save(config);

    if (process.platform !== "win32") expect((await stat(directory)).mode & 0o777).toBe(0o755);
    expect((await stat(store.filePath)).mode & 0o777).toBe(0o600);
  });
});
