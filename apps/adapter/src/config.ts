import { randomBytes } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { parseCredentialEnvelope } from "@ws-proxy/shared";
import type { AdapterConfig, CredentialEnvelope, MachineAuth, ModelConfig, ProviderProtocol } from "./types.js";

const DEFAULT_PORT = 43128;
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function defaultConfigPath(): string {
  return process.env.WS_PROXY_ADAPTER_CONFIG ?? path.join(homedir(), ".config", "ws-llm-clfl-proxy", "adapter.json");
}

export function createInitialConfig(input: {
  identityUrl: string;
  gatewayUrl: string;
  auth: MachineAuth;
  port?: number;
}): AdapterConfig {
  return validateConfig({
    version: 1,
    identityUrl: input.identityUrl,
    gatewayUrl: input.gatewayUrl,
    auth: input.auth,
    localBearerToken: randomBytes(32).toString("base64url"),
    port: input.port ?? DEFAULT_PORT,
    models: [],
    envelopes: [],
  });
}

export function validateConfig(value: unknown): AdapterConfig {
  if (!isRecord(value) || value.version !== 1) throw new ConfigError("Adapter config must use version 1");
  const identityUrl = validateIdentityUrl(value.identityUrl);
  const gatewayUrl = validateGatewayUrl(value.gatewayUrl);
  const localBearerToken = nonEmptyString(value.localBearerToken, "localBearerToken");
  if (Buffer.byteLength(localBearerToken) < 32) throw new ConfigError("localBearerToken must be at least 32 bytes");
  const port = value.port === undefined ? DEFAULT_PORT : value.port;
  if (!Number.isInteger(port) || Number(port) < 1 || Number(port) > 65535) throw new ConfigError("port must be an integer between 1 and 65535");
  const auth = validateAuth(value.auth);
  const rawEnvelopes = Array.isArray(value.envelopes) ? value.envelopes : [];
  if (rawEnvelopes.length > 256) throw new ConfigError("At most 256 credential envelopes are supported");
  const envelopes = rawEnvelopes.map(validateEnvelope);
  const envelopeIds = new Set<string>();
  for (const envelope of envelopes) {
    if (envelopeIds.has(envelope.credentialId)) throw new ConfigError("Credential IDs must be unique in the adapter config");
    envelopeIds.add(envelope.credentialId);
  }
  const rawModels = Array.isArray(value.models) ? value.models : [];
  if (rawModels.length > 256) throw new ConfigError("At most 256 local model aliases are supported");
  const models = rawModels.map(validateModel);
  const modelIds = new Set<string>();
  for (const model of models) {
    if (modelIds.has(model.id)) throw new ConfigError("Model IDs must be unique in the adapter config");
    modelIds.add(model.id);
    const envelope = envelopes.find((item) => item.credentialId === model.credentialId);
    if (!envelope) throw new ConfigError(`Model ${model.id} references an unknown credential ID`);
    if (envelope.provider !== model.provider) throw new ConfigError(`Model ${model.id} provider does not match its envelope`);
  }
  return { version: 1, identityUrl, gatewayUrl, auth, localBearerToken, port: Number(port), models, envelopes };
}

function validateAuth(value: unknown): MachineAuth {
  if (!isRecord(value)) throw new ConfigError("auth must be an object");
  if (value.type === "confidential") {
    return {
      type: "confidential",
      clientId: nonEmptyString(value.clientId, "auth.clientId"),
      clientSecret: nonEmptyString(value.clientSecret, "auth.clientSecret"),
    };
  }
  if (value.type === "public") {
    return {
      type: "public",
      clientId: nonEmptyString(value.clientId, "auth.clientId"),
      refreshToken: nonEmptyString(value.refreshToken, "auth.refreshToken"),
    };
  }
  throw new ConfigError("auth.type must be confidential or public");
}

function validateEnvelope(value: unknown): CredentialEnvelope {
  try {
    return parseCredentialEnvelope(value);
  } catch {
    throw new ConfigError("Credential envelope does not match the shared v1 schema");
  }
}

function validateModel(value: unknown): ModelConfig {
  if (!isRecord(value)) throw new ConfigError("model entries must be objects");
  const id = nonEmptyString(value.id, "model.id");
  if (id.length > 128 || /[\u0000-\u0020]/.test(id)) throw new ConfigError("model.id must be at most 128 characters without whitespace");
  const provider = value.provider;
  if (typeof provider !== "string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(provider)) {
    throw new ConfigError("model.provider must be a valid provider ID");
  }
  const protocol = value.protocol === undefined && (provider === "openai" || provider === "anthropic")
    ? provider
    : value.protocol;
  if (protocol !== "openai" && protocol !== "anthropic") {
    throw new ConfigError("Custom model providers require protocol openai or anthropic");
  }
  if ((provider === "openai" || provider === "anthropic") && provider !== protocol) {
    throw new ConfigError("Built-in provider protocol must match its provider ID");
  }
  return { id, provider, protocol: protocol as ProviderProtocol, credentialId: nonEmptyString(value.credentialId, "model.credentialId") };
}

function validateIdentityUrl(value: unknown): string {
  const url = parseUrl(value, "identityUrl");
  const localHttp = url.protocol === "http:" && isLoopbackHostname(url.hostname);
  if (url.protocol !== "https:" && !localHttp) throw new ConfigError("identityUrl must use HTTPS (or HTTP on loopback for local development)");
  if (url.username || url.password || url.search || url.hash) throw new ConfigError("identityUrl cannot contain credentials, query, or fragment");
  return url.toString().replace(/\/$/, "");
}

function validateGatewayUrl(value: unknown): string {
  const url = parseUrl(value, "gatewayUrl");
  const localWs = url.protocol === "ws:" && isLoopbackHostname(url.hostname);
  if (url.protocol !== "wss:" && !localWs) throw new ConfigError("gatewayUrl must use WSS (or WS on loopback for local development)");
  if (url.username || url.password || url.search || url.hash) throw new ConfigError("gatewayUrl cannot contain credentials, query, or fragment");
  return url.toString();
}

function parseUrl(value: unknown, name: string): URL {
  if (typeof value !== "string" || value.length > 2048) throw new ConfigError(`${name} must be a URL`);
  try {
    return new URL(value);
  } catch {
    throw new ConfigError(`${name} must be a valid URL`);
  }
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]" || hostname === "localhost";
}

function nonEmptyString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 8192) throw new ConfigError(`${name} must be a non-empty string`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class ConfigStore {
  private updateTail: Promise<void> = Promise.resolve();

  constructor(readonly filePath = defaultConfigPath()) {}

  async load(): Promise<AdapterConfig> {
    let fileStat;
    try {
      fileStat = await stat(this.filePath);
    } catch {
      throw new ConfigError(`Adapter config not found at ${this.filePath}; run the pair or machine setup command first`);
    }
    if (process.platform !== "win32" && (fileStat.mode & 0o077) !== 0) {
      throw new ConfigError("Adapter config permissions are too broad; restrict the file to owner read/write (0600)");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(this.filePath, "utf8"));
    } catch {
      throw new ConfigError("Adapter config is unreadable or invalid JSON");
    }
    return validateConfig(parsed);
  }

  async save(config: AdapterConfig): Promise<void> {
    const validated = validateConfig(config);
    const directory = path.dirname(this.filePath);
    const createdDirectory = await mkdir(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32" && createdDirectory && path.resolve(createdDirectory) === path.resolve(directory)) {
      await chmod(directory, 0o700);
    }
    const tempPath = `${this.filePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      const handle = await open(tempPath, "wx", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(validated, null, 2)}\n`, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      if (process.platform !== "win32") await chmod(tempPath, 0o600);
      await rename(tempPath, this.filePath);
      if (process.platform !== "win32") await chmod(this.filePath, 0o600);
    } catch (error) {
      await rm(tempPath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  async update(mutator: (current: AdapterConfig) => AdapterConfig): Promise<AdapterConfig> {
    const operation = this.updateTail.then(async () => {
      const current = await this.load();
      const next = validateConfig(mutator(current));
      await this.save(next);
      return next;
    });
    this.updateTail = operation.then(() => undefined, () => undefined);
    return operation;
  }
}
