import { randomBytes } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { MAX_IN_FLIGHT, MAX_REQUEST_PAYLOAD_BYTES, MAX_SESSION_SECONDS, MIN_REQUEST_PAYLOAD_BYTES, MIN_SESSION_SECONDS } from "@ws-proxy/shared";
import { ConfigStore, createInitialConfig } from "./config.js";
import { fetchWithEnvironmentProxy } from "./proxy.js";
import type { AdapterConfig, ProviderProtocol } from "./types.js";

export type IdentityFetch = (input: string | URL, init?: RequestInit) => Promise<Response>;

interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token?: string;
}

export class IdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityError";
  }
}

export interface ClientBootstrap {
  version: 1;
  identityUrl: string;
  gatewayUrl: string;
  client: { clientId: string; kind: "public" | "confidential" };
  projectId: string;
  models: Array<{ id: string; provider: string; protocol: ProviderProtocol }>;
  limits: { maxPayloadBytes: number; maxConcurrency: number; maxSessionSeconds: number };
}

export async function readClientBootstrapFile(filePath: string): Promise<ClientBootstrap> {
  let fileStat;
  let contents: string;
  try {
    fileStat = await stat(filePath);
    if (!fileStat.isFile() || fileStat.size > 262_144) throw new Error("invalid file");
    contents = await readFile(filePath, "utf8");
  } catch {
    throw new IdentityError("Bootstrap file is unreadable or exceeds the 256 KiB limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents) as unknown;
  } catch {
    throw new IdentityError("Bootstrap file is not valid JSON");
  }
  return parseClientBootstrap(parsed);
}

export function parseClientBootstrap(value: unknown): ClientBootstrap {
  if (!isExactRecord(value, ["version", "identityUrl", "gatewayUrl", "client", "projectId", "models", "limits"]) || value.version !== 1) {
    throw new IdentityError("Bootstrap must match the secret-free version 1 schema");
  }
  if (!isExactRecord(value.client, ["clientId", "kind"]) || !isIdentifier(value.client.clientId)) {
    throw new IdentityError("Bootstrap client must include a valid clientId and kind");
  }
  if (value.client.kind !== "public" && value.client.kind !== "confidential") {
    throw new IdentityError("Bootstrap client kind must be public or confidential");
  }
  if (!isIdentifier(value.projectId)) throw new IdentityError("Bootstrap projectId is invalid");
  if (!Array.isArray(value.models) || value.models.length > 256) throw new IdentityError("Bootstrap models must be a bounded array");
  const models = value.models.map((model) => {
    const legacyShape = isExactRecord(model, ["id", "provider"]);
    const explicitProtocolShape = isExactRecord(model, ["id", "provider", "protocol"]);
    if ((!legacyShape && !explicitProtocolShape) || !isModelAlias(model.id)) {
      throw new IdentityError("Bootstrap model must contain a valid id and provider");
    }
    if (!isProviderId(model.provider)) {
      throw new IdentityError("Bootstrap model provider must be a valid provider ID");
    }
    const protocol = model.protocol === undefined && (model.provider === "openai" || model.provider === "anthropic")
      ? model.provider
      : model.protocol;
    if (protocol !== "openai" && protocol !== "anthropic") {
      throw new IdentityError("Custom bootstrap model providers require an explicit supported protocol");
    }
    if ((model.provider === "openai" || model.provider === "anthropic") && protocol !== model.provider) {
      throw new IdentityError("Built-in bootstrap provider protocol must match its provider ID");
    }
    return { id: model.id, provider: model.provider, protocol: protocol as ProviderProtocol };
  });
  if (new Set(models.map((model) => model.id)).size !== models.length) throw new IdentityError("Bootstrap model IDs must be unique");
  if (!isExactRecord(value.limits, ["maxPayloadBytes", "maxConcurrency", "maxSessionSeconds"])) {
    throw new IdentityError("Bootstrap limits do not match the supported schema");
  }
  if (!isIntegerInRange(value.limits.maxPayloadBytes, MIN_REQUEST_PAYLOAD_BYTES, MAX_REQUEST_PAYLOAD_BYTES)
    || !isIntegerInRange(value.limits.maxConcurrency, 1, MAX_IN_FLIGHT)
    || !isIntegerInRange(value.limits.maxSessionSeconds, MIN_SESSION_SECONDS, MAX_SESSION_SECONDS)) {
    throw new IdentityError("Bootstrap limits are outside the supported bounds");
  }
  let config: AdapterConfig;
  try {
    config = createInitialConfig({
      identityUrl: requiredString(value.identityUrl),
      gatewayUrl: requiredString(value.gatewayUrl),
      auth: { type: "confidential", clientId: "bootstrap-client", clientSecret: "bootstrap-validation-only" },
    });
  } catch {
    throw new IdentityError("Bootstrap contains invalid Identity or Gateway URLs");
  }
  return {
    version: 1,
    identityUrl: config.identityUrl,
    gatewayUrl: config.gatewayUrl,
    client: { clientId: value.client.clientId, kind: value.client.kind },
    projectId: value.projectId,
    models,
    limits: {
      maxPayloadBytes: value.limits.maxPayloadBytes,
      maxConcurrency: value.limits.maxConcurrency,
      maxSessionSeconds: value.limits.maxSessionSeconds,
    },
  };
}

export class TokenProvider {
  private accessToken: string | undefined;
  private expiresAt = 0;
  private refreshPromise: Promise<string> | undefined;

  constructor(
    private readonly configStore: ConfigStore,
    private readonly fetchImpl: IdentityFetch = fetchWithEnvironmentProxy,
  ) {}

  async getAccessToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.expiresAt - 30_000) return this.accessToken;
    if (!this.refreshPromise) {
      this.refreshPromise = this.refresh().finally(() => { this.refreshPromise = undefined; });
    }
    return this.refreshPromise;
  }

  private async refresh(): Promise<string> {
    const config = await this.configStore.load();
    const body = new URLSearchParams();
    const headers = new Headers({ "content-type": "application/x-www-form-urlencoded" });
    if (config.auth.type === "confidential") {
      body.set("grant_type", "client_credentials");
      headers.set("authorization", `Basic ${Buffer.from(`${encodeURIComponent(config.auth.clientId)}:${encodeURIComponent(config.auth.clientSecret)}`).toString("base64")}`);
    } else {
      body.set("grant_type", "refresh_token");
      body.set("client_id", config.auth.clientId);
      body.set("refresh_token", config.auth.refreshToken);
    }
    const response = await this.fetchImpl(new URL("/oauth/token", config.identityUrl), {
      method: "POST",
      headers,
      body,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    }).catch(() => { throw new IdentityError("Identity token request failed"); });
    const payload = await readJson(response);
    if (!response.ok) throw new IdentityError("Identity rejected the machine credential; pair or provision the client again");
    if (!isRecord(payload) || typeof payload.access_token !== "string" || payload.token_type !== "Bearer" || !Number.isInteger(payload.expires_in)) {
      throw new IdentityError("Identity returned an invalid machine token response");
    }
    const expiresIn = Number(payload.expires_in);
    if (expiresIn < 30 || expiresIn > 3600) throw new IdentityError("Identity returned an invalid token lifetime");
    let refreshedConfig: AdapterConfig | undefined;
    if (config.auth.type === "public") {
      if (typeof payload.refresh_token !== "string" || payload.refresh_token.length < 32) {
        throw new IdentityError("Identity did not rotate the public client refresh token");
      }
      refreshedConfig = await this.configStore.update((current) => {
        if (current.auth.type !== "public" || current.auth.clientId !== config.auth.clientId) {
          throw new IdentityError("Adapter authentication configuration changed during refresh");
        }
        return { ...current, auth: { ...current.auth, refreshToken: payload.refresh_token as string } };
      });
    }
    this.accessToken = payload.access_token;
    this.expiresAt = Date.now() + expiresIn * 1000;
    void refreshedConfig;
    return this.accessToken;
  }
}

export async function pairPublicClient(options: {
  identityUrl: string;
  gatewayUrl: string;
  clientName: string;
  configStore: ConfigStore;
  onCode: (verificationUri: string, userCode: string) => void;
  fetchImpl?: IdentityFetch;
}): Promise<AdapterConfig> {
  const fetchImpl = options.fetchImpl ?? fetchWithEnvironmentProxy;
  const started = await identityJson(new URL("/pairing/start", options.identityUrl), {
    clientName: options.clientName,
  }, fetchImpl);
  if (!isRecord(started.payload) || !started.response.ok || started.response.status !== 201) {
    throw new IdentityError("Identity could not start client pairing");
  }
  const pairingId = stringField(started.payload.pairingId);
  const deviceCode = stringField(started.payload.deviceCode);
  const userCode = stringField(started.payload.userCode);
  const verificationUri = stringField(started.payload.verificationUri);
  const expiresIn = numberField(started.payload.expiresIn);
  const interval = numberField(started.payload.interval);
  if (!pairingId || !deviceCode || !userCode || !verificationUri || expiresIn < 1 || expiresIn > 600 || interval < 1 || interval > 30) {
    throw new IdentityError("Identity returned an invalid pairing response");
  }
  const verification = new URL(verificationUri);
  const identity = new URL(options.identityUrl);
  if ((verification.protocol !== "https:" && !(verification.protocol === "http:" && isLoopback(verification.hostname)))
    || verification.origin !== identity.origin
    || verification.pathname !== "/pair"
    || verification.search
    || verification.hash
    || verification.username
    || verification.password) {
    throw new IdentityError("Identity returned an unsafe pairing verification URL");
  }
  options.onCode(verification.toString(), userCode);

  const deadline = Date.now() + expiresIn * 1000;
  let clientId: string | undefined;
  let refreshToken: string | undefined;
  while (Date.now() < deadline) {
    await delay(Math.max(1, interval) * 1000);
    const result = await identityJson(new URL("/pairing/token", options.identityUrl), { pairingId, deviceCode }, fetchImpl);
    if (result.response.status === 403) throw new IdentityError("Client pairing was rejected");
    if (result.response.status === 410) throw new IdentityError("Client pairing expired or the token was already delivered");
    if (!result.response.ok || !isRecord(result.payload)) throw new IdentityError("Identity pairing status request failed");
    if (result.payload.status === "pending") continue;
    if (result.payload.status !== "approved") throw new IdentityError("Identity returned an invalid pairing status");
    clientId = stringField(result.payload.client_id);
    refreshToken = stringField(result.payload.refresh_token);
    if (!clientId || !refreshToken) throw new IdentityError("Identity returned an invalid public client credential");
    break;
  }
  if (!clientId || !refreshToken) throw new IdentityError("Client pairing timed out");

  const config = createInitialConfig({
    identityUrl: options.identityUrl,
    gatewayUrl: options.gatewayUrl,
    auth: { type: "public", clientId, refreshToken },
  });
  await options.configStore.save(config);
  return config;
}

export async function configureConfidentialClient(options: {
  identityUrl: string;
  gatewayUrl: string;
  clientId: string;
  clientSecret: string;
  configStore: ConfigStore;
}): Promise<AdapterConfig> {
  const config = createInitialConfig({
    identityUrl: options.identityUrl,
    gatewayUrl: options.gatewayUrl,
    auth: { type: "confidential", clientId: options.clientId, clientSecret: options.clientSecret },
  });
  await options.configStore.save(config);
  return config;
}

export function createDeviceLabel(): string {
  return `adapter-${randomBytes(3).toString("hex")}`;
}

async function identityJson(url: URL, body: Record<string, unknown>, fetchImpl: IdentityFetch): Promise<{ response: Response; payload: unknown }> {
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  }).catch(() => { throw new IdentityError("Identity request failed"); });
  return { response, payload: await readJson(response) };
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

function stringField(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberField(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isExactRecord(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const actualKeys = Object.keys(value);
  return actualKeys.length === keys.length && keys.every((key) => key in value);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
}

function isModelAlias(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && !/[\u0000-\u0020]/.test(value);
}

function isProviderId(value: unknown): value is string {
  return typeof value === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(value);
}

function isIntegerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) throw new Error("invalid string");
  return value;
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
