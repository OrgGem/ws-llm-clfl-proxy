import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import { parseEnv } from "node:util";
import { parseCredentialEnvelope } from "@ws-proxy/shared";
import { ConfigError, ConfigStore, validateConfig } from "./config.js";
import type { AdapterConfig, ProviderProtocol } from "./types.js";

const MAX_ENV_FILE_BYTES = 64 * 1024;
const MAX_ENVELOPE_FILE_BYTES = 32 * 1024;

const ENV_KEYS = [
  "WS_PROXY_IDENTITY_URL",
  "WS_PROXY_GATEWAY_URL",
  "WS_PROXY_CLIENT_ID",
  "WS_PROXY_CLIENT_SECRET",
  "WS_PROXY_LOCAL_BEARER_TOKEN",
  "WS_PROXY_ENVELOPE_FILE",
  "WS_PROXY_MODEL_ALIAS",
  "WS_PROXY_PROVIDER",
  "WS_PROXY_PROTOCOL",
] as const;

export class EnvironmentConfigStore extends ConfigStore {
  private current: AdapterConfig;

  constructor(config: AdapterConfig) {
    // This path is never opened: environment mode overrides all file operations.
    super("<environment>");
    this.current = validateConfig(config);
  }

  override async load(): Promise<AdapterConfig> {
    return structuredClone(this.current);
  }

  override async save(config: AdapterConfig): Promise<void> {
    this.current = validateConfig(config);
  }
}

export async function createEnvironmentConfigStore(env: NodeJS.ProcessEnv = process.env): Promise<EnvironmentConfigStore> {
  const source = env.WS_PROXY_CONFIG_SOURCE;
  if (source !== "env") throw new ConfigError("Environment config source must be explicitly set to env");
  const required = (name: typeof ENV_KEYS[number]): string => {
    const value = env[name];
    if (typeof value !== "string" || value.length === 0 || value.length > 8192) {
      throw new ConfigError(`Environment mode requires ${name}`);
    }
    return value;
  };

  const identityUrl = required("WS_PROXY_IDENTITY_URL");
  const gatewayUrl = required("WS_PROXY_GATEWAY_URL");
  const clientId = required("WS_PROXY_CLIENT_ID");
  const clientSecret = required("WS_PROXY_CLIENT_SECRET");
  const localBearerToken = required("WS_PROXY_LOCAL_BEARER_TOKEN");
  const envelopePath = required("WS_PROXY_ENVELOPE_FILE");
  const modelAlias = required("WS_PROXY_MODEL_ALIAS");
  const provider = required("WS_PROXY_PROVIDER");
  const protocol = required("WS_PROXY_PROTOCOL");
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(provider)) throw new ConfigError("WS_PROXY_PROVIDER must be a valid provider ID");
  if (protocol !== "openai" && protocol !== "anthropic") throw new ConfigError("WS_PROXY_PROTOCOL must be openai or anthropic");
  const envelope = await readProtectedEnvelope(envelopePath);

  let config: AdapterConfig;
  try {
    config = validateConfig({
      version: 1,
      identityUrl,
      gatewayUrl,
      auth: {
        type: "confidential",
        clientId,
        clientSecret,
      },
      localBearerToken,
      port: 43128,
      models: [{ id: modelAlias, provider, protocol: protocol as ProviderProtocol, credentialId: envelope.credentialId }],
      envelopes: [envelope],
      oauthModels: [],
    });
  } catch (error) {
    if (error instanceof ConfigError && error.message.startsWith("WS_PROXY_")) throw error;
    throw new ConfigError("Environment runtime settings are invalid");
  }
  return new EnvironmentConfigStore(config);
}

export async function loadPrivateEnvFile(filePath: string): Promise<void> {
  const contents = await readProtectedTextFile(filePath, MAX_ENV_FILE_BYTES, "Environment file");
  let parsed: NodeJS.Dict<string>;
  try {
    // Node's dotenv parser consumes data only; file contents are never run as
    // shell code. Limit keys to this adapter's documented runtime settings.
    parsed = parseEnv(contents);
  } catch {
    throw new ConfigError("Environment file is unreadable or invalid");
  }
  const allowed = new Set(["WS_PROXY_CONFIG_SOURCE", ...ENV_KEYS]);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) {
    throw new ConfigError("Environment file contains an unsupported setting");
  }
  // Keep inherited environment values authoritative, matching Node's
  // loadEnvFile precedence without reopening the validated path.
  for (const [key, value] of Object.entries(parsed)) {
    if (process.env[key] === undefined && value !== undefined) process.env[key] = value;
  }
}

export async function readProtectedEnvelope(filePath: string): Promise<ReturnType<typeof parseCredentialEnvelope>> {
  const contents = await readProtectedTextFile(filePath, MAX_ENVELOPE_FILE_BYTES, "Envelope file");
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents) as unknown;
  } catch {
    throw new ConfigError("Envelope file is unreadable or invalid JSON");
  }
  try {
    return parseCredentialEnvelope(parsed);
  } catch {
    throw new ConfigError("Envelope file does not match the shared credential schema");
  }
}

export function hasEnvironmentRuntimeSettings(env: NodeJS.ProcessEnv = process.env): boolean {
  return ENV_KEYS.some((key) => env[key] !== undefined && key !== "WS_PROXY_CLIENT_SECRET");
}

async function readProtectedTextFile(filePath: string, maximumBytes: number, label: string): Promise<string> {
  let handle: FileHandle | undefined;
  try {
    handle = await openProtectedRegularFile(filePath, maximumBytes, label);
    const fileStat = await handle.stat();
    const chunks: Buffer[] = [];
    let total = 0;
    const buffer = Buffer.alloc(Math.min(8192, maximumBytes + 1));
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.byteLength, maximumBytes + 1 - total), null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximumBytes) throw new ConfigError(`${label} exceeds its size limit`);
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    if (fileStat.size > maximumBytes) throw new ConfigError(`${label} exceeds its size limit`);
    return Buffer.concat(chunks, total).toString("utf8");
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw new ConfigError(`${label} is unreadable or invalid`);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function openProtectedRegularFile(filePath: string, maximumBytes: number, label: string): Promise<FileHandle> {
  let handle: FileHandle | undefined;
  try {
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    handle = await open(path.resolve(filePath), fsConstants.O_RDONLY | noFollow);
    const fileStat = await handle.stat();
    if (!fileStat.isFile() || fileStat.size > maximumBytes) throw new ConfigError(`${label} must be a regular file within its size limit`);
    assertOwnerOnly(fileStat.mode);
    assertOwnedByCurrentUser(fileStat.uid);
    return handle;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof ConfigError) throw error;
    throw new ConfigError(`${label} is unreadable or invalid`);
  }
}

function assertOwnerOnly(mode: number): void {
  if (process.platform !== "win32" && (mode & 0o777) !== 0o600) {
    throw new ConfigError("Environment and envelope files must have owner-only 0600 permissions");
  }
}

function assertOwnedByCurrentUser(uid: number): void {
  if (process.platform !== "win32" && typeof process.getuid === "function" && uid !== process.getuid()) {
    throw new ConfigError("Environment and envelope files must be owned by the current user");
  }
}
