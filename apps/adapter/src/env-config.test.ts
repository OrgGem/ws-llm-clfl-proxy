import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEnvironmentConfigStore, EnvironmentConfigStore, loadPrivateEnvFile, readProtectedEnvelope } from "./env-config.js";

const directories: string[] = [];
const originalEnv = new Map<string, string | undefined>();

afterEach(async () => {
  for (const [key, value] of originalEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  originalEnv.clear();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("environment runtime configuration", () => {
  it("loads one protected envelope into a memory-only confidential config", async () => {
    const directory = await privateDirectory();
    const envelopePath = await writeEnvelope(directory);
    const env = runtimeEnv(envelopePath);
    const store = await createEnvironmentConfigStore(env);

    expect(store).toBeInstanceOf(EnvironmentConfigStore);
    expect(await store.load()).toMatchObject({
      identityUrl: "https://identity.example.test",
      gatewayUrl: "wss://gateway.example.test/v1/socket",
      auth: { type: "confidential", clientId: "client_runtime", clientSecret: "secret_runtime" },
      localBearerToken: "L".repeat(43),
      models: [{ id: "agent-alias", provider: "openai", protocol: "openai", credentialId: "credential_runtime" }],
      envelopes: [{ credentialId: "credential_runtime", provider: "openai" }],
    });

    await store.update((current) => ({ ...current, localBearerToken: "N".repeat(43) }));
    expect((await store.load()).localBearerToken).toBe("N".repeat(43));
    expect(store.filePath).toBe("<environment>");
    await expect(readFile(path.join(directory, "adapter.json"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects incomplete env settings and files that are not owner-only", async () => {
    const directory = await privateDirectory();
    const envelopePath = await writeEnvelope(directory);
    await expect(createEnvironmentConfigStore({ WS_PROXY_CONFIG_SOURCE: "env", WS_PROXY_ENVELOPE_FILE: envelopePath }))
      .rejects.toThrow("Environment mode requires WS_PROXY_IDENTITY_URL");

    const envFile = path.join(directory, "runtime.env");
    await writeFile(envFile, "WS_PROXY_CONFIG_SOURCE=env\n", { mode: 0o600 });
    if (process.platform !== "win32") {
      await chmod(envFile, 0o644);
      await expect(loadPrivateEnvFile(envFile)).rejects.toThrow("0600 permissions");
    }
  });

  it("reads dotenv as data, preserves inherited OS values, and rejects unrelated process settings", async () => {
    const directory = await privateDirectory();
    const envFile = path.join(directory, "runtime.env");
    await writeFile(envFile, [
      "WS_PROXY_CONFIG_SOURCE=env",
      "WS_PROXY_CLIENT_ID=file-client",
      'WS_PROXY_CLIENT_SECRET="literal $(this is not executed)"',
      "NODE_OPTIONS=--require=unexpected.js",
    ].join("\n"), { mode: 0o600 });
    saveEnv("WS_PROXY_CONFIG_SOURCE");
    saveEnv("WS_PROXY_CLIENT_ID");
    saveEnv("WS_PROXY_CLIENT_SECRET");
    saveEnv("NODE_OPTIONS");
    process.env.WS_PROXY_CLIENT_ID = "inherited-client";
    delete process.env.WS_PROXY_CONFIG_SOURCE;
    delete process.env.WS_PROXY_CLIENT_SECRET;
    delete process.env.NODE_OPTIONS;

    await expect(loadPrivateEnvFile(envFile)).rejects.toThrow("unsupported setting");
    expect(process.env.NODE_OPTIONS).toBeUndefined();
    expect(process.env.WS_PROXY_CLIENT_ID).toBe("inherited-client");

    const allowedEnv = path.join(directory, "allowed.env");
    await writeFile(allowedEnv, [
      "WS_PROXY_CONFIG_SOURCE=env",
      "WS_PROXY_CLIENT_ID=file-client",
      'WS_PROXY_CLIENT_SECRET="literal $(this is not executed)"',
    ].join("\n"), { mode: 0o600 });
    await loadPrivateEnvFile(allowedEnv);
    expect(process.env.WS_PROXY_CONFIG_SOURCE).toBe("env");
    expect(process.env.WS_PROXY_CLIENT_ID).toBe("inherited-client");
    expect(process.env.WS_PROXY_CLIENT_SECRET).toBe("literal $(this is not executed)");
  });

  it("rejects symlinked envelope files instead of following them", async () => {
    if (process.platform === "win32") return;
    const directory = await privateDirectory();
    const target = await writeEnvelope(directory);
    const link = path.join(directory, "envelope-link.json");
    const { symlink } = await import("node:fs/promises");
    await symlink(target, link);
    await expect(readProtectedEnvelope(link)).rejects.toThrow("unreadable or invalid");
  });
});

async function privateDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "adapter-env-config-"));
  directories.push(directory);
  return directory;
}

async function writeEnvelope(directory: string): Promise<string> {
  const filePath = path.join(directory, "envelope.json");
  const envelope = {
    v: 1,
    alg: "A256GCM",
    kid: "key_test",
    credentialId: "credential_runtime",
    userId: "user_runtime",
    projectId: "project_runtime",
    provider: "openai",
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: "AAAAAAAAAAAAAAAA",
    ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
  };
  await writeFile(filePath, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
  return filePath;
}

function runtimeEnv(envelopePath: string): NodeJS.ProcessEnv {
  return {
    WS_PROXY_CONFIG_SOURCE: "env",
    WS_PROXY_IDENTITY_URL: "https://identity.example.test",
    WS_PROXY_GATEWAY_URL: "wss://gateway.example.test/v1/socket",
    WS_PROXY_CLIENT_ID: "client_runtime",
    WS_PROXY_CLIENT_SECRET: "secret_runtime",
    WS_PROXY_LOCAL_BEARER_TOKEN: "L".repeat(43),
    WS_PROXY_ENVELOPE_FILE: envelopePath,
    WS_PROXY_MODEL_ALIAS: "agent-alias",
    WS_PROXY_PROVIDER: "openai",
    WS_PROXY_PROTOCOL: "openai",
  };
}

function saveEnv(key: string): void {
  if (!originalEnv.has(key)) originalEnv.set(key, process.env[key]);
}
