import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { CredentialEnvelope } from "@ws-proxy/shared";

const PAIR_CODE_TTL_MS = 120_000;
const CONTROL_SESSION_TTL_MS = 10 * 60_000;
const MAX_PENDING_PAIRINGS = 8;
const MAX_CONTROL_SESSIONS = 8;
const MAX_CODE_ATTEMPTS = 5;
const MAX_JSON_BYTES = 2_048;
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const PAIRING_TOKEN = /^ogt_[A-Za-z0-9_-]{43}$/;

const ROUTE_METHODS = new Map<string, string>([
  ["/local/oauth/health", "GET"],
  ["/local/oauth/pair/start", "POST"],
  ["/local/oauth/pair/approve", "POST"],
  ["/local/oauth/status", "GET"],
  ["/local/oauth/models", "GET"],
  ["/local/oauth/model", "POST"],
  ["/local/oauth/disconnect", "POST"],
]);

export interface OAuthPairingGrant {
  projectId: string;
  expiresAt: number;
  bindingId: string;
}

export type OAuthLoginStatus =
  | { status: "pending" }
  | { status: "connected"; profileId: string; email?: string; modelsAvailable: number }
  | { status: "failed"; code: "authorization_failed" | "callback_timeout" | "invalid_response" };

export interface OAuthDiscoveredModel {
  id: string;
  displayName?: string;
  contextWindow?: number;
  inputModalities: string[];
  reasoningEfforts: string[];
}

/** Narrow adapter-owned OAuth interface. It never returns provider tokens. */
export interface OAuthBridgeManager {
  redeemPairing(pairingToken: string, machineBearer: string): Promise<OAuthPairingGrant>;
  startLogin(options?: { profileId?: string }): Promise<{ operationId: string; authorizationUrl: string }>;
  status(operationId: string): OAuthLoginStatus | Promise<OAuthLoginStatus>;
  bindProfile(profileId: string, grant: OAuthPairingGrant, identityOrigin: string): Promise<void>;
  discoverModels(profileId: string): Promise<OAuthDiscoveredModel[]>;
  bindModelProfile(alias: string, profileId: string): Promise<void>;
  ensureModelEnvelope?(alias: string, machineBearer: string, api: "responses"): Promise<CredentialEnvelope | undefined>;
  disconnect(profileId: string): Promise<void>;
  listOAuthModelAliases?(profileId?: string): Promise<string[]>;
  listModelBindings?(): Promise<Array<{ alias: string; profileId: string }>>;
  close?(): Promise<void>;
}

export interface OAuthMachineTokenProvider {
  getAccessToken(): Promise<string>;
}

export interface OAuthBridgeOptions {
  identityUrl: string;
  manager?: OAuthBridgeManager;
  tokenProvider?: OAuthMachineTokenProvider;
  now?: () => number;
  /** The eight-digit code is printed only to the local adapter terminal. */
  writeApprovalCode?: (message: string) => void;
}

interface PendingPairing {
  pairingToken: string;
  codeHash: Buffer;
  expiresAt: number;
  attempts: number;
}

interface ControlSession {
  operationId: string;
  grant: OAuthPairingGrant | undefined;
  expiresAt: number;
  profileId?: string;
  binding?: Promise<void>;
  disconnected: boolean;
}

/**
 * The local-control bridge is deliberately isolated from /v1 CORS and bearer auth.
 * It accepts requests only from the exact configured Identity origin and loopback Host.
 */
export class OAuthBridge {
  private readonly identityOrigin: string;
  private readonly pending = new Map<string, PendingPairing>();
  private readonly controlSessions = new Map<string, ControlSession>();
  private readonly now: () => number;
  private readonly writeApprovalCode: (message: string) => void;

  constructor(private readonly options: OAuthBridgeOptions) {
    let identity: URL;
    try {
      identity = new URL(options.identityUrl);
    } catch {
      throw new TypeError("OAuth bridge requires a valid configured Identity URL");
    }
    if (identity.protocol !== "https:" && !(identity.protocol === "http:" && isLoopbackHostname(identity.hostname))) {
      throw new TypeError("OAuth bridge Identity URL must use HTTPS or loopback HTTP");
    }
    if (identity.username || identity.password || identity.search || identity.hash) {
      throw new TypeError("OAuth bridge Identity URL cannot contain credentials, query, or fragment");
    }
    this.identityOrigin = identity.origin;
    this.now = options.now ?? Date.now;
    this.writeApprovalCode = options.writeApprovalCode ?? ((message) => { process.stdout.write(`${message}\n`); });
  }

  async listOAuthModelAliases(): Promise<string[]> {
    if (!this.options.manager?.listOAuthModelAliases) return [];
    const aliases = await this.options.manager.listOAuthModelAliases();
    if (!Array.isArray(aliases) || aliases.length > 256) throw new Error("OAuth model catalog is invalid");
    return [...new Set(aliases.filter((alias) => typeof alias === "string" && alias.length > 0 && alias.length <= 128 && !/[\u0000-\u0020]/.test(alias)))];
  }

  async getOAuthModelAliasesForProfile(profileId: string): Promise<string[]> {
    const manager = this.options.manager;
    if (!manager?.listOAuthModelAliases) return [];
    const aliases = await manager.listOAuthModelAliases(profileId);
    if (!Array.isArray(aliases) || aliases.length > 256) throw new Error("OAuth model catalog is invalid");
    return [...new Set(aliases.filter((alias) => typeof alias === "string" && alias.length > 0 && alias.length <= 128 && !/[\u0000-\u0020]/.test(alias)))];
  }

  async hasOAuthModelAlias(alias: string): Promise<boolean> {
    const manager = this.options.manager;
    if (manager?.listModelBindings) {
      const bindings = await manager.listModelBindings();
      return Array.isArray(bindings) && bindings.some((binding) => isRecord(binding) && binding.alias === alias);
    }
    if (!manager?.listOAuthModelAliases) return false;
    const aliases = await manager.listOAuthModelAliases();
    return Array.isArray(aliases) && aliases.includes(alias);
  }

  hasEnvelopeResolver(): boolean {
    return typeof this.options.manager?.ensureModelEnvelope === "function";
  }

  async ensureModelEnvelope(alias: string, machineBearer: string): Promise<CredentialEnvelope | undefined> {
    const resolver = this.options.manager?.ensureModelEnvelope;
    return resolver ? resolver(alias, machineBearer, "responses") : undefined;
  }

  async handle(request: IncomingMessage, response: ServerResponse, port: number): Promise<boolean> {
    const rawTarget = request.url ?? "/";
    const rawPath = rawTarget.split(/[?#]/, 1)[0] ?? "/";
    if (!rawPath.startsWith("/local/oauth/")) return false;

    this.cleanExpired();
    if (!isLoopbackRemote(request.socket.remoteAddress) || request.headers.host !== `127.0.0.1:${port}`) {
      sendJson(response, 403, "forbidden", "Request host or address is not allowed");
      return true;
    }
    if (typeof request.headers.origin !== "string" || request.headers.origin !== this.identityOrigin) {
      sendJson(response, 403, "forbidden", "Request origin is not allowed");
      return true;
    }

    const expectedMethod = ROUTE_METHODS.get(rawPath);
    setCorsHeaders(response, this.identityOrigin);
    response.setHeader("cross-origin-resource-policy", "cross-origin");
    if (request.method === "OPTIONS") {
      this.handlePreflight(request, response, rawPath, expectedMethod);
      return true;
    }
    if (rawTarget !== rawPath) {
      sendJson(response, 400, "invalid_request", "Query strings and fragments are not accepted");
      return true;
    }
    if (!expectedMethod || request.method !== expectedMethod) {
      sendJson(response, 404, "not_found", "OAuth bridge route not found");
      return true;
    }
    if (rawPath === "/local/oauth/health") {
      sendJson(response, 200, undefined, undefined, {
        reachable: true,
        oauthAvailable: Boolean(this.options.manager && this.options.tokenProvider),
      });
      return true;
    }
    if (!this.options.manager || !this.options.tokenProvider) {
      sendJson(response, 503, "oauth_unavailable", "Local OAuth is not configured on this adapter");
      return true;
    }

    if (rawPath === "/local/oauth/pair/start") {
      await this.startPairing(request, response);
      return true;
    }
    if (rawPath === "/local/oauth/pair/approve") {
      await this.approvePairing(request, response);
      return true;
    }
    const session = this.findControlSession(request.headers.authorization);
    if (!session || session.disconnected) {
      sendJson(response, 401, "unauthorized", "A valid local OAuth control session is required");
      return true;
    }
    if (rawPath === "/local/oauth/status") {
      await this.getStatus(response, session);
      return true;
    }
    if (rawPath === "/local/oauth/models") {
      await this.getModels(response, session);
      return true;
    }
    if (rawPath === "/local/oauth/model") {
      await this.bindModel(request, response, session);
      return true;
    }
    if (rawPath === "/local/oauth/disconnect") {
      await this.disconnect(response, session);
      return true;
    }
    sendJson(response, 404, "not_found", "OAuth bridge route not found");
    return true;
  }

  private handlePreflight(request: IncomingMessage, response: ServerResponse, path: string, expectedMethod?: string): void {
    const requestedMethod = request.headers["access-control-request-method"];
    const requestedHeaders = request.headers["access-control-request-headers"];
    const privateNetwork = request.headers["access-control-request-private-network"];
    if (request.url !== path || !expectedMethod || requestedMethod !== expectedMethod ||
        (privateNetwork !== undefined && privateNetwork !== "true") ||
        !requestedHeadersAllowed(requestedHeaders)) {
      sendJson(response, 403, "forbidden", "Preflight request is not allowed");
      return;
    }
    response.setHeader("access-control-allow-methods", expectedMethod);
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-max-age", "300");
    response.setHeader("vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network");
    if (privateNetwork === "true") response.setHeader("access-control-allow-private-network", "true");
    response.statusCode = 204;
    response.end();
  }

  private async startPairing(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const body = await readJson(request, response);
    if (!body) return;
    if (!hasExactKeys(body, ["pairingToken"]) || typeof body.pairingToken !== "string" || !PAIRING_TOKEN.test(body.pairingToken)) {
      sendJson(response, 400, "invalid_request", "A valid one-time Identity pairing token is required");
      return;
    }
    if (this.pending.size >= MAX_PENDING_PAIRINGS) {
      sendJson(response, 429, "rate_limited", "Too many pending local pairing requests");
      return;
    }
    const pairingId = randomUUID();
    const code = randomInt(0, 100_000_000).toString().padStart(8, "0");
    const expiresAt = this.now() + PAIR_CODE_TTL_MS;
    this.pending.set(pairingId, {
      pairingToken: body.pairingToken,
      codeHash: approvalCodeHash(pairingId, code),
      expiresAt,
      attempts: 0,
    });
    this.writeApprovalCode(`Local ChatGPT pairing code: ${code} (valid for 2 minutes)`);
    sendJson(response, 202, undefined, undefined, { pairingId, expiresAt: Math.floor(expiresAt / 1000) });
  }

  private async approvePairing(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const body = await readJson(request, response);
    if (!body) return;
    if (!hasExactKeys(body, ["pairingId", "approvalCode"]) || typeof body.pairingId !== "string" ||
        !isUuid(body.pairingId) || typeof body.approvalCode !== "string" || !/^\d{8}$/.test(body.approvalCode)) {
      sendJson(response, 400, "invalid_request", "Pairing ID and eight-digit local approval code are required");
      return;
    }
    const pending = this.pending.get(body.pairingId);
    if (!pending || pending.expiresAt <= this.now()) {
      this.pending.delete(body.pairingId);
      sendJson(response, 410, "pairing_expired", "The local pairing request expired; start again from Identity");
      return;
    }
    if (this.controlSessions.size >= MAX_CONTROL_SESSIONS) {
      sendJson(response, 429, "rate_limited", "Too many active local OAuth sessions");
      return;
    }
    pending.attempts += 1;
    const suppliedHash = approvalCodeHash(body.pairingId, body.approvalCode);
    if (!timingSafeEqual(pending.codeHash, suppliedHash)) {
      if (pending.attempts >= MAX_CODE_ATTEMPTS) this.pending.delete(body.pairingId);
      sendJson(response, pending.attempts >= MAX_CODE_ATTEMPTS ? 410 : 401, "approval_rejected", "The local approval code is incorrect or expired");
      return;
    }

    // Consume before awaiting network operations so concurrent/replayed approvals cannot win twice.
    this.pending.delete(body.pairingId);
    try {
      const machineBearer = await this.options.tokenProvider!.getAccessToken();
      const grant = await this.options.manager!.redeemPairing(pending.pairingToken, machineBearer);
      pending.pairingToken = "";
      if (!isRecord(grant) || !SAFE_ID.test(grant.projectId) || !Number.isSafeInteger(grant.expiresAt)) {
        sendJson(response, 502, "identity_unavailable", "Identity returned an invalid pairing grant");
        return;
      }
      const login = await this.options.manager!.startLogin();
      if (!isRecord(login) || typeof login.operationId !== "string" || !SAFE_ID.test(login.operationId) ||
          !isSafeAuthorizationUrl(login.authorizationUrl)) {
        sendJson(response, 502, "oauth_unavailable", "The local OAuth login could not be started");
        return;
      }
      const token = randomBytes(32).toString("base64url");
      const tokenHash = hashControlToken(token);
      const expiresAt = this.now() + CONTROL_SESSION_TTL_MS;
      this.controlSessions.set(tokenHash, {
        operationId: login.operationId,
        grant,
        expiresAt,
        disconnected: false,
      });
      sendJson(response, 200, undefined, undefined, {
        controlToken: token,
        expiresAt: Math.floor(expiresAt / 1000),
        authorizationUrl: login.authorizationUrl,
      });
    } catch {
      pending.pairingToken = "";
      sendJson(response, 502, "oauth_unavailable", "Identity pairing or local OAuth login could not be completed");
    }
  }

  private findControlSession(authorization: string | string[] | undefined): ControlSession | undefined {
    if (typeof authorization !== "string" || authorization.length > 512) return undefined;
    const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(authorization);
    if (!match?.[1]) return undefined;
    const session = this.controlSessions.get(hashControlToken(match[1]));
    if (!session || session.expiresAt <= this.now()) return undefined;
    return session;
  }

  private async getStatus(response: ServerResponse, session: ControlSession): Promise<void> {
    try {
      const status = await this.options.manager!.status(session.operationId);
      if (!isLoginStatus(status)) {
        sendJson(response, 502, "oauth_unavailable", "Local OAuth status is unavailable");
        return;
      }
      if (status.status === "connected" && !session.profileId) {
        if (!session.grant) {
          sendJson(response, 502, "oauth_unavailable", "The local OAuth project binding is unavailable");
          return;
        }
        session.binding ??= this.options.manager!.bindProfile(status.profileId, session.grant, this.identityOrigin);
        await session.binding;
        session.profileId = status.profileId;
        session.grant = undefined;
      }
      sendJson(response, 200, undefined, undefined, sanitizeLoginStatus(status));
    } catch {
      sendJson(response, 502, "oauth_unavailable", "Local OAuth status is unavailable");
    }
  }

  private async getModels(response: ServerResponse, session: ControlSession): Promise<void> {
    if (!session.profileId) {
      sendJson(response, 409, "login_pending", "Complete ChatGPT sign-in before discovering models");
      return;
    }
    try {
      const models = await this.options.manager!.discoverModels(session.profileId);
      if (!Array.isArray(models) || models.length > 500 || !models.every(isDiscoveredModel)) {
        sendJson(response, 502, "oauth_unavailable", "Model discovery returned invalid metadata");
        return;
      }
      sendJson(response, 200, undefined, undefined, {
        models: models.map(sanitizeModel),
        boundAliases: await this.getOAuthModelAliasesForProfile(session.profileId),
      });
    } catch {
      sendJson(response, 502, "oauth_unavailable", "ChatGPT model discovery is unavailable");
    }
  }

  private async bindModel(request: IncomingMessage, response: ServerResponse, session: ControlSession): Promise<void> {
    if (!session.profileId) {
      sendJson(response, 409, "login_pending", "Finish local ChatGPT sign-in before mapping a model alias");
      return;
    }
    const body = await readJson(request, response);
    if (!body) return;
    if (!hasExactKeys(body, ["alias"]) || typeof body.alias !== "string" || !isModelAlias(body.alias)) {
      sendJson(response, 400, "invalid_request", "A valid existing model alias is required");
      return;
    }
    try {
      await this.options.manager!.bindModelProfile(body.alias, session.profileId);
      sendJson(response, 200, undefined, undefined, { alias: body.alias, bound: true });
    } catch {
      sendJson(response, 400, "model_binding_rejected", "The local adapter could not bind this model alias");
    }
  }

  private async disconnect(response: ServerResponse, session: ControlSession): Promise<void> {
    if (!session.profileId) {
      sendJson(response, 409, "login_pending", "Finish local ChatGPT sign-in before disconnecting the profile");
      return;
    }
    session.disconnected = true;
    this.controlSessions.delete([...this.controlSessions].find(([, value]) => value === session)?.[0] ?? "");
    try {
      await this.options.manager!.disconnect(session.profileId);
      sendJson(response, 200, undefined, undefined, { disconnected: true });
    } catch {
      sendJson(response, 502, "oauth_unavailable", "Local OAuth disconnect could not be completed");
    }
  }

  private cleanExpired(): void {
    const now = this.now();
    for (const [id, pending] of this.pending) if (pending.expiresAt <= now) this.pending.delete(id);
    for (const [tokenHash, session] of this.controlSessions) if (session.expiresAt <= now) this.controlSessions.delete(tokenHash);
  }
}

function setCorsHeaders(response: ServerResponse, origin: string): void {
  response.setHeader("access-control-allow-origin", origin);
  response.setHeader("vary", "Origin");
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
}

function requestedHeadersAllowed(value: string | string[] | undefined): boolean {
  if (value === undefined) return true;
  if (typeof value !== "string" || value.length > 256) return false;
  const requested = value.split(",").map((header) => header.trim().toLowerCase()).filter(Boolean);
  return requested.length <= 2 && requested.every((header) => header === "authorization" || header === "content-type");
}

async function readJson(request: IncomingMessage, response: ServerResponse): Promise<Record<string, unknown> | undefined> {
  if (!request.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
    sendJson(response, 415, "invalid_request", "Content-Type must be application/json");
    return undefined;
  }
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > MAX_JSON_BYTES) {
      sendJson(response, 413, "invalid_request", "OAuth bridge request is too large");
      return undefined;
    }
    chunks.push(buffer);
  }
  let value: unknown;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    sendJson(response, 400, "invalid_request", "Request body must be valid JSON");
    return undefined;
  }
  if (!isRecord(value)) {
    sendJson(response, 400, "invalid_request", "Request body must be a JSON object");
    return undefined;
  }
  return value;
}

function sendJson(response: ServerResponse, status: number, code?: string, message?: string, data?: Record<string, unknown>): void {
  if (response.destroyed || response.writableEnded) return;
  response.statusCode = status;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.end(JSON.stringify(code ? { error: { code, message } } : data ?? {}));
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isModelAlias(value: string): boolean {
  return value.length > 0 && value.length <= 128 && !/[\u0000-\u0020]/.test(value);
}

function approvalCodeHash(pairingId: string, code: string): Buffer {
  return createHash("sha256").update(`${pairingId}\n${code}`).digest();
}

function hashControlToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function isSafeAuthorizationUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 4096) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "auth.openai.com" &&
      url.pathname === "/api/accounts/authorize" && !url.username && !url.password && !url.hash;
  } catch {
    return false;
  }
}

function isLoginStatus(value: unknown): value is OAuthLoginStatus {
  if (!isRecord(value)) return false;
  if (value.status === "pending") return true;
  if (value.status === "failed") return ["authorization_failed", "callback_timeout", "invalid_response"].includes(value.code);
  return value.status === "connected" && typeof value.profileId === "string" && SAFE_ID.test(value.profileId) &&
    (value.email === undefined || typeof value.email === "string" && value.email.length <= 254) &&
    Number.isInteger(value.modelsAvailable) && value.modelsAvailable >= 0 && value.modelsAvailable <= 500;
}

function sanitizeLoginStatus(status: OAuthLoginStatus): Record<string, unknown> {
  if (status.status === "pending") return { status: "pending" };
  if (status.status === "failed") return { status: "failed", code: status.code };
  return {
    status: "connected",
    ...(status.email ? { email: status.email } : {}),
    modelsAvailable: status.modelsAvailable,
  };
}

function isDiscoveredModel(value: unknown): value is OAuthDiscoveredModel {
  return isRecord(value) && typeof value.id === "string" && value.id.length > 0 && value.id.length <= 256 &&
    !/[\u0000-\u001f]/.test(value.id) &&
    (value.displayName === undefined || typeof value.displayName === "string" && value.displayName.length <= 256) &&
    (value.contextWindow === undefined || Number.isSafeInteger(value.contextWindow) && value.contextWindow > 0 && value.contextWindow <= 10_000_000) &&
    Array.isArray(value.inputModalities) && value.inputModalities.length <= 16 && value.inputModalities.every((item: unknown) => typeof item === "string" && item.length <= 32) &&
    Array.isArray(value.reasoningEfforts) && value.reasoningEfforts.length <= 16 && value.reasoningEfforts.every((item: unknown) => typeof item === "string" && item.length <= 32);
}

function sanitizeModel(model: OAuthDiscoveredModel): Record<string, unknown> {
  return {
    id: model.id,
    ...(model.displayName ? { displayName: model.displayName } : {}),
    ...(model.contextWindow ? { contextWindow: model.contextWindow } : {}),
    inputModalities: [...model.inputModalities],
    reasoningEfforts: [...model.reasoningEfforts],
  };
}

function isLoopbackRemote(address: string | undefined): boolean {
  if (!address) return false;
  if (address === "127.0.0.1" || address === "::1") return true;
  if (address.startsWith("::ffff:")) return isLoopbackRemote(address.slice(7));
  return /^127(?:\.\d{1,3}){3}$/.test(address);
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]" || hostname === "::1";
}
