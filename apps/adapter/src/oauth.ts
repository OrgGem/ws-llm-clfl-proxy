import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { URLSearchParams } from "node:url";
import { createRemoteJWKSet, customFetch, decodeJwt, jwtVerify, type JWTPayload } from "jose";
import { parseCredentialEnvelope } from "@ws-proxy/shared";
import type { CredentialEnvelope } from "./types.js";
import type { ConfigStore } from "./config.js";
import { OAuthProfileStore, OAuthStoreError, type OAuthStorage, type StoredChatGptProfile } from "./oauth-store.js";
import { fetchWithEnvironmentProxy } from "./proxy.js";

const ISSUER = "https://auth.openai.com";
const AUTHORIZE_URL = new URL("/api/accounts/authorize", ISSUER);
const TOKEN_URL = new URL("/api/accounts/oauth/token", ISSUER);
const JWKS_URL = new URL("/.well-known/jwks.json", ISSUER);
const RESOURCE = "https://api.openai.com/v1";
const MODELS_URL = new URL("/v1/models", RESOURCE);
const REQUIRED_SCOPES = ["offline_access", "resource.invoke", "chatgpt.tokens.use.direct"] as const;
const REQUESTED_SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const OPERATION_TTL_MS = 10 * 60_000;
const MAX_LOGIN_OPERATIONS = 16;
const MAX_PAIRING_GRANTS = 32;
const SAFE_EMAIL = /^[^\s@]{1,128}@[^\s@]{1,190}$/;

export interface OAuthModelSummary {
  id: string;
  displayName?: string;
  contextWindow?: number;
  inputModalities: string[];
  reasoningEfforts: string[];
}

export interface OAuthProfileSummary {
  profileId: string;
  email?: string;
  connectedAt: number;
  accessExpiresAt?: number;
  connected: boolean;
  scopes: string[];
}

export type OAuthOperationStatus =
  | { status: "pending" }
  | { status: "connected"; profileId: string; email?: string; modelsAvailable: number }
  | { status: "failed"; code: "authorization_failed" | "callback_timeout" | "invalid_response" };

export interface OAuthPairingGrant {
  projectId: string;
  expiresAt: number;
  /** One-use local capability; retained only in memory by the bridge, never sent to the browser. */
  bindingId: string;
}

interface LoginOptions {
  profileId?: string;
}

interface OAuthTokenResponse {
  access_token?: unknown;
  refresh_token?: unknown;
  id_token?: unknown;
  expires_in?: unknown;
  scope?: unknown;
  error?: unknown;
}

interface AccessTokenEntry {
  token: string;
  expiresAt: number;
}

interface LoginOperation {
  id: string;
  createdAt: number;
  generation: number;
  status: OAuthOperationStatus;
  server: Server;
  redirectUri: string;
  state: string;
  nonce: string;
  verifier: string;
  clientId?: string;
  profileId?: string;
  timer: NodeJS.Timeout;
  completion: Promise<void>;
  resolveCallback: (result: CallbackResult) => void;
  callbackAccepted: boolean;
  committing: boolean;
}

type CallbackResult = { code: string; clientId?: string } | { error: true };
type FetchImpl = (input: string | URL, init?: RequestInit) => Promise<Response>;

/** Client-owned ChatGPT SIWC OAuth. Raw access tokens never leave this class or its HTTPS calls. */
export class ChatGptOAuthManager {
  private readonly profiles: OAuthProfileStore;
  private readonly accessTokens = new Map<string, AccessTokenEntry>();
  private readonly accessFlights = new Map<string, Promise<AccessTokenEntry>>();
  private readonly envelopeCache = new Map<string, CredentialEnvelope>();
  private readonly envelopeFlights = new Map<string, Promise<CredentialEnvelope>>();
  private readonly profileEpochs = new Map<string, number>();
  private readonly disconnecting = new Set<string>();
  private readonly operations = new Map<string, LoginOperation>();
  private readonly pairingGrants = new Map<string, { origin: string; projectId: string; expiresAt: number; createdAt: number }>();
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(
    private readonly configStore: ConfigStore,
    private readonly fetchImpl: FetchImpl = fetchWithEnvironmentProxy,
    private readonly now: () => number = Date.now,
  ) {
    this.profiles = new OAuthProfileStore(configStore.filePath);
    this.jwks = createRemoteJWKSet(JWKS_URL, {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
      [customFetch]: (url, options) => this.fetchImpl(url, options),
    });
  }

  async startLogin(options: LoginOptions = {}): Promise<{ operationId: string; authorizationUrl: string }> {
    this.pruneOperations();
    while (this.operations.size >= MAX_LOGIN_OPERATIONS) {
      const completed = [...this.operations.values()].find((operation) => operation.status.status !== "pending");
      if (!completed) break;
      this.operations.delete(completed.id);
    }
    if (this.operations.size >= MAX_LOGIN_OPERATIONS) {
      throw new OAuthConnectorError("too_many_logins", "Too many ChatGPT sign-in attempts are active.");
    }
    const storage = await this.profiles.update((current) => current);
    const savedProfile = options.profileId
      ? storage.profiles.find((profile) => profile.profileId === options.profileId)
      : undefined;
    if (options.profileId && !savedProfile) throw new OAuthConnectorError("profile_not_found", "OAuth profile was not found.");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const state = randomBytes(32).toString("base64url");
    const nonce = randomBytes(32).toString("base64url");
    const operationId = randomUUID();
    let resolveCallback!: (result: CallbackResult) => void;
    const callback = new Promise<CallbackResult>((resolve) => { resolveCallback = resolve; });
    const server = createServer((request, response) => this.handleCallback(request, response, operation));
    const operation = {
      id: operationId,
      createdAt: this.now(),
      generation: 0,
      status: { status: "pending" } as OAuthOperationStatus,
      server,
      redirectUri: "",
      state,
      nonce,
      verifier,
      ...(savedProfile ? { clientId: savedProfile.clientId, profileId: savedProfile.profileId } : {}),
      timer: setTimeout(() => undefined, 0),
      completion: Promise.resolve(),
      resolveCallback,
      callbackAccepted: false,
      committing: false,
    } satisfies LoginOperation;
    await listenLoopback(server);
    const address = server.address();
    if (!address || typeof address === "string") throw new OAuthConnectorError("callback_failed", "Could not start the local OAuth callback.");
    operation.redirectUri = `http://127.0.0.1:${address.port}/auth/callback`;
    operation.timer = setTimeout(() => {
      if (operation.status.status !== "pending" || operation.committing) return;
      operation.generation += 1;
      operation.status = { status: "failed", code: "callback_timeout" };
      operation.resolveCallback({ error: true });
      closeServer(operation.server);
    }, OPERATION_TTL_MS);
    operation.timer.unref();
    this.operations.set(operationId, operation);
    operation.completion = this.completeLogin(operation, callback);
    void operation.completion.catch(() => undefined);

    const params = new URLSearchParams({
      client_id: savedProfile?.clientId ?? "dynamic_agent_client",
      ...(savedProfile ? {} : { agent_name_hint: "WS LLM Adapter" }),
      ext_agent_host_id: storage.hostId,
      response_type: "code",
      redirect_uri: operation.redirectUri,
      scope: REQUESTED_SCOPES,
      resource: RESOURCE,
      state,
      nonce,
      code_challenge_method: "S256",
      code_challenge: challenge,
    });
    const authorizationUrl = `${AUTHORIZE_URL.toString()}?${params.toString()}`;
    return { operationId, authorizationUrl };
  }

  status(operationId: string): OAuthOperationStatus {
    this.pruneOperations();
    const operation = this.operations.get(operationId);
    if (!operation || this.now() - operation.createdAt > OPERATION_TTL_MS * 2) {
      return { status: "failed", code: "authorization_failed" };
    }
    return structuredClone(operation.status);
  }

  async cancelLogin(operationId: string): Promise<void> {
    const operation = this.operations.get(operationId);
    if (!operation || operation.status.status !== "pending") return;
    if (operation.committing) {
      await operation.completion;
      return;
    }
    operation.generation += 1;
    operation.status = { status: "failed", code: "authorization_failed" };
    operation.resolveCallback({ error: true });
    clearTimeout(operation.timer);
    closeServer(operation.server);
    await operation.completion.catch(() => undefined);
  }

  async listProfiles(): Promise<OAuthProfileSummary[]> {
    const storage = await this.profiles.snapshot();
    return storage.profiles.map((profile) => {
      const token = this.accessTokens.get(profile.profileId);
      return {
        profileId: profile.profileId,
        ...(profile.email ? { email: profile.email } : {}),
        connectedAt: profile.connectedAt,
        ...(token ? { accessExpiresAt: Math.floor(token.expiresAt / 1000) } : {}),
        connected: typeof profile.refreshToken === "string",
        scopes: [...profile.scopes],
      };
    });
  }

  async discoverModels(profileId: string): Promise<OAuthModelSummary[]> {
    const token = await this.getAccessToken(profileId);
    const response = await this.fetchImpl(MODELS_URL, {
      method: "GET",
      headers: { authorization: `Bearer ${token.token}`, accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    }).catch(() => { throw new OAuthConnectorError("model_discovery_failed", "ChatGPT model discovery failed."); });
    const payload = await readBoundedJson(response, 1_048_576);
    if (!response.ok) throw new OAuthConnectorError("model_discovery_failed", "ChatGPT model discovery failed.");
    const models = normalizeModels(payload);
    await this.profiles.update((storage) => ({
      ...storage,
      profiles: storage.profiles.map((profile) => profile.profileId === profileId ? { ...profile, modelCache: models } : profile),
    }));
    return models;
  }

  async readCachedModels(profileId: string): Promise<OAuthModelSummary[]> {
    const profile = (await this.profiles.snapshot()).profiles.find((item) => item.profileId === profileId);
    if (!profile) throw new OAuthConnectorError("profile_not_found", "OAuth profile was not found.");
    return structuredClone(profile.modelCache ?? []);
  }

  async redeemPairing(pairingToken: string, machineBearer: string): Promise<OAuthPairingGrant> {
    if (!/^ogt_[A-Za-z0-9_-]{43}$/.test(pairingToken) || machineBearer.length < 20) {
      throw new OAuthConnectorError("pairing_failed", "The local account pairing could not be completed.");
    }
    const config = await this.configStore.load();
    const response = await this.fetchImpl(new URL("/api/oauth/pairing/redeem", config.identityUrl), {
      method: "POST",
      headers: { authorization: `Bearer ${machineBearer}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ pairingToken }),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    }).catch(() => { throw new OAuthConnectorError("pairing_failed", "The local account pairing could not be completed."); });
    const payload = await readBoundedJson(response, 8_192);
    if (!response.ok || !isRecord(payload) || !isRecord(payload.grant) || payload.grant.connectorId !== "chatgpt" || payload.grant.provider !== "openai") {
      throw new OAuthConnectorError("pairing_failed", "The local account pairing could not be completed.");
    }
    const projectId = boundedString(payload.grant.projectId, /^[A-Za-z0-9._:-]{1,128}$/);
    const expiresAt = integer(payload.grant.expiresAt, Math.floor(this.now() / 1000) + 1, Number.MAX_SAFE_INTEGER);
    if (!projectId || !expiresAt) throw new OAuthConnectorError("pairing_failed", "The local account pairing could not be completed.");
    const bindingId = randomBytes(32).toString("base64url");
    const grant = Object.freeze({ projectId, expiresAt, bindingId });
    const configNow = await this.configStore.load();
    this.prunePairingGrants();
    if (this.pairingGrants.size >= MAX_PAIRING_GRANTS) throw new OAuthConnectorError("pairing_failed", "Too many local account pairings are active.");
    this.pairingGrants.set(bindingId, { origin: new URL(configNow.identityUrl).origin, projectId, expiresAt, createdAt: this.now() });
    return grant;
  }

  async bindProfile(profileId: string, grant: OAuthPairingGrant, identityOrigin?: string): Promise<void> {
    const redeemed = this.pairingGrants.get(grant.bindingId);
    const configuredOrigin = new URL((await this.configStore.load()).identityUrl).origin;
    if (!redeemed || this.now() - redeemed.createdAt > OPERATION_TTL_MS || redeemed.projectId !== grant.projectId || redeemed.expiresAt !== grant.expiresAt || redeemed.origin !== configuredOrigin || (identityOrigin && identityOrigin !== configuredOrigin)) {
      throw new OAuthConnectorError("pairing_failed", "The local account pairing is invalid or expired.");
    }
    await this.profiles.update((storage) => {
      if (!storage.profiles.some((profile) => profile.profileId === profileId)) {
        throw new OAuthConnectorError("profile_not_found", "OAuth profile was not found.");
      }
      return {
        ...storage,
        profiles: storage.profiles.map((profile) => profile.profileId === profileId
          ? { ...profile, projectId: grant.projectId, identityOrigin: configuredOrigin }
          : profile),
      };
    });
    this.profileEpochs.set(profileId, (this.profileEpochs.get(profileId) ?? 0) + 1);
    this.pairingGrants.delete(grant.bindingId);
    for (const binding of await this.listModelBindings()) {
      if (binding.profileId === profileId) {
        for (const key of this.envelopeCache.keys()) if (key.startsWith(`${binding.alias}:${profileId}:`)) this.envelopeCache.delete(key);
        for (const key of this.envelopeFlights.keys()) if (key.startsWith(`${binding.alias}:${profileId}:`)) this.envelopeFlights.delete(key);
      }
    }
  }

  async bindModelProfile(alias: string, profileId: string): Promise<void> {
    if (!isModelAlias(alias)) throw new OAuthConnectorError("invalid_model_alias", "Model alias is invalid.");
    const storage = await this.profiles.snapshot();
    if (!storage.profiles.some((profile) => profile.profileId === profileId && profile.refreshToken)) {
      throw new OAuthConnectorError("profile_not_found", "A connected ChatGPT profile is required.");
    }
    await this.configStore.update((current) => {
      if (current.models.some((model) => model.id === alias)) {
        return {
          ...current,
          models: current.models.filter((model) => model.id !== alias),
          oauthModels: [...(current.oauthModels ?? []).filter((item) => item.alias !== alias), { alias, profileId }],
        };
      }
      return { ...current, oauthModels: [...(current.oauthModels ?? []).filter((item) => item.alias !== alias), { alias, profileId }] };
    });
    for (const key of this.envelopeCache.keys()) if (key.startsWith(`${alias}:`)) this.envelopeCache.delete(key);
  }

  async removeModelBinding(alias: string): Promise<void> {
    await this.configStore.update((current) => ({ ...current, oauthModels: (current.oauthModels ?? []).filter((item) => item.alias !== alias) }));
    for (const key of this.envelopeCache.keys()) if (key.startsWith(`${alias}:`)) this.envelopeCache.delete(key);
  }

  async listModelBindings(): Promise<Array<{ alias: string; profileId: string }>> {
    const config = await this.configStore.load();
    return (config.oauthModels ?? []).map((binding) => ({ ...binding }));
  }

  async listOAuthModelAliases(profileId?: string): Promise<string[]> {
    const config = await this.configStore.load();
    if (!config.oauthModels?.length) return [];
    const storage = await this.profiles.snapshot();
    const profiles = new Map(storage.profiles.map((profile) => [profile.profileId, profile]));
    const identityOrigin = new URL(config.identityUrl).origin;
    return (config.oauthModels ?? [])
      .filter((binding) => {
        if (profileId !== undefined && binding.profileId !== profileId) return false;
        const profile = profiles.get(binding.profileId);
        return Boolean(profile?.refreshToken && profile.projectId && profile.identityOrigin === identityOrigin);
      })
      .map((binding) => binding.alias);
  }

  /** Returns undefined only for API-key aliases; mapped OAuth aliases never fall through. */
  async ensureModelEnvelope(alias: string, machineBearer: string, api: "responses" | "chat.completions" | "completions" = "responses"): Promise<CredentialEnvelope | undefined> {
    const config = await this.configStore.load();
    const binding = (config.oauthModels ?? []).find((item) => item.alias === alias);
    if (!binding) return undefined;
    if (api !== "responses") throw new OAuthConnectorError("responses_required", "ChatGPT subscription OAuth requires the native Responses API.");
    const profile = (await this.profiles.snapshot()).profiles.find((item) => item.profileId === binding.profileId);
    if (!profile?.refreshToken) throw new OAuthConnectorError("profile_disconnected", "The ChatGPT profile for this model must be reconnected.");
    if (!profile.projectId) throw new OAuthConnectorError("pairing_required", "Connect this adapter to the authorized cloud project before using ChatGPT OAuth.");
    if (profile.identityOrigin !== new URL(config.identityUrl).origin) {
      throw new OAuthConnectorError("pairing_required", "Pair this ChatGPT profile with the currently configured Identity service.");
    }
    const cacheKey = `${alias}:${binding.profileId}:${profile.projectId}:responses`;
    const cached = this.envelopeCache.get(cacheKey);
    if (cached && cached.projectId === profile.projectId && cached.exp > Math.floor(this.now() / 1000) + 30) return cached;
    if (cached) this.envelopeCache.delete(cacheKey);
    let pending = this.envelopeFlights.get(cacheKey);
    if (!pending) {
      const mint = this.mintEnvelope(alias, binding.profileId, profile.projectId, machineBearer);
      let tracked: Promise<CredentialEnvelope>;
      tracked = mint.finally(() => {
        if (this.envelopeFlights.get(cacheKey) === tracked) this.envelopeFlights.delete(cacheKey);
      });
      pending = tracked;
      this.envelopeFlights.set(cacheKey, tracked);
    }
    return pending;
  }

  async disconnect(profileId: string): Promise<void> {
    await this.disconnectWithStatus(profileId);
  }

  async disconnectWithStatus(profileId: string): Promise<{ localDisconnected: true; remoteRevoked: boolean }> {
    let remoteRevoked = false;
    if (this.disconnecting.has(profileId)) throw new OAuthConnectorError("disconnect_in_progress", "This ChatGPT profile is already being disconnected.");
    this.disconnecting.add(profileId);
    this.profileEpochs.set(profileId, (this.profileEpochs.get(profileId) ?? 0) + 1);
    try {
      await this.profiles.transaction(async (storage) => {
        const profile = storage.profiles.find((item) => item.profileId === profileId);
        if (!profile) throw new OAuthConnectorError("profile_not_found", "OAuth profile was not found.");
        if (profile.refreshToken) remoteRevoked = await this.revokeRefreshToken(profile.clientId, profile.refreshToken);
        return {
          value: undefined,
          next: {
            ...storage,
            profiles: storage.profiles.map((item) => {
              if (item.profileId !== profileId) return item;
              const { refreshToken: _refreshToken, projectId: _projectId, identityOrigin: _identityOrigin, ...disconnected } = item;
              return disconnected;
            }),
          },
        };
      });
      this.accessTokens.delete(profileId);
      const config = await this.configStore.load();
      for (const binding of config.oauthModels ?? []) if (binding.profileId === profileId) {
        for (const key of this.envelopeCache.keys()) if (key.startsWith(`${binding.alias}:${profileId}:`)) this.envelopeCache.delete(key);
        for (const key of this.envelopeFlights.keys()) if (key.startsWith(`${binding.alias}:${profileId}:`)) this.envelopeFlights.delete(key);
      }
      return { localDisconnected: true, remoteRevoked };
    } finally {
      this.disconnecting.delete(profileId);
    }
  }

  async close(): Promise<void> {
    for (const operation of this.operations.values()) {
      if (operation.status.status === "pending" && !operation.committing) {
        operation.generation += 1;
        operation.status = { status: "failed", code: "authorization_failed" };
        operation.resolveCallback({ error: true });
      }
      clearTimeout(operation.timer);
      closeServer(operation.server);
    }
    await Promise.all([...this.operations.values()].map((operation) => operation.completion.catch(() => undefined)));
    this.accessTokens.clear();
    this.envelopeCache.clear();
  }

  private async completeLogin(operation: LoginOperation, callback: Promise<CallbackResult>): Promise<void> {
    const generation = operation.generation;
    try {
      const result = await callback;
      if ("error" in result || !isLoginPending(operation, generation)) return;
      if (operation.clientId && result.clientId && operation.clientId !== result.clientId) {
        operation.status = { status: "failed", code: "invalid_response" };
        return;
      }
      const clientId = operation.clientId ?? result.clientId;
      if (!clientId || !isClientId(clientId)) throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in returned an invalid client response.");
      const tokenPayload = await this.exchangeCode(result.code, clientId, operation);
      if (!isLoginPending(operation, generation)) return;
      const access = requireToken(tokenPayload.access_token, "access_token");
      const refresh = requireToken(tokenPayload.refresh_token, "refresh_token");
      const idToken = requireToken(tokenPayload.id_token, "id_token");
      const scopes = parseScopes(tokenPayload.scope);
      requireScopes(scopes);
      const claims = await this.verifyIdToken(idToken, clientId, operation.nonce);
      if (operation.profileId && claims.sub !== (await this.profile(operation.profileId)).subject) {
        throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in returned a different account for this profile.");
      }
      const token = await this.validateAccessToken(access, clientId, claims.sub, scopes, tokenPayload.expires_in);
      const profileId = operation.profileId ?? randomBytes(24).toString("base64url");
      const email = claims.email_verified === true && typeof claims.email === "string" && SAFE_EMAIL.test(claims.email)
        ? claims.email
        : undefined;
      const connectedAt = Math.floor(this.now() / 1000);
      const profile: StoredChatGptProfile = {
        profileId,
        clientId,
        subject: claims.sub,
        ...(email ? { email } : {}),
        connectedAt,
        scopes,
        refreshToken: refresh,
      };
      if (!isLoginPending(operation, generation)) return;
      // This is the linearization point: cancellation can win before the write starts,
      // but once committing is true it waits for this operation to finish.
      operation.committing = true;
      await this.profiles.update((storage) => {
        if (!isLoginPending(operation, generation)) {
          throw new OAuthConnectorError("login_cancelled", "ChatGPT sign-in was cancelled.");
        }
        const existing = storage.profiles.find((item) => item.profileId === profileId);
        if (existing && (existing.clientId !== clientId || existing.subject !== claims.sub)) {
          throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in did not match the saved profile.");
        }
        return {
          ...storage,
          profiles: [...storage.profiles.filter((item) => item.profileId !== profileId), {
            ...existing,
            ...profile,
            ...(existing?.projectId ? { projectId: existing.projectId } : {}),
            ...(existing?.identityOrigin ? { identityOrigin: existing.identityOrigin } : {}),
            ...(existing?.modelCache ? { modelCache: existing.modelCache } : {}),
          }],
        };
      });
      if (!isLoginPending(operation, generation)) return;
      this.profileEpochs.set(profileId, (this.profileEpochs.get(profileId) ?? 0) + 1);
      this.accessTokens.set(profileId, token);
      this.envelopeCache.clear();
      this.envelopeFlights.clear();
      operation.status = { status: "connected", profileId, ...(email ? { email } : {}), modelsAvailable: 0 };
    } catch (error) {
      if (isLoginPending(operation, generation)) {
        operation.generation += 1;
        operation.status = {
          status: "failed",
          code: error instanceof OAuthConnectorError && error.code === "invalid_response" ? "invalid_response" : "authorization_failed",
        };
      }
    } finally {
      operation.committing = false;
      clearTimeout(operation.timer);
      operation.state = "";
      operation.nonce = "";
      operation.verifier = "";
      closeServer(operation.server);
    }
  }

  private async exchangeCode(code: string, clientId: string, operation: LoginOperation): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      code_verifier: operation.verifier,
      redirect_uri: operation.redirectUri,
      resource: RESOURCE,
    });
    return this.tokenRequest(body);
  }

  private async tokenRequest(body: URLSearchParams): Promise<OAuthTokenResponse> {
    const response = await this.fetchImpl(TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    }).catch(() => { throw new OAuthConnectorError("token_request_failed", "ChatGPT sign-in could not be completed."); });
    const payload = await readBoundedJson(response, 65_536);
    if (!response.ok && isRecord(payload) && payload.error === "invalid_grant") {
      throw new OAuthConnectorError("invalid_grant", "ChatGPT session needs to be reconnected.");
    }
    if (!response.ok || !isRecord(payload)) throw new OAuthConnectorError("token_request_failed", "ChatGPT sign-in could not be completed.");
    return payload as OAuthTokenResponse;
  }

  private async verifyIdToken(token: string, clientId: string, nonce?: string, expectedSubject?: string): Promise<JWTPayload & { sub: string }> {
    try {
      const result = await jwtVerify(token, this.jwks, {
        issuer: ISSUER,
        audience: clientId,
        algorithms: ["RS256"],
        requiredClaims: ["iss", "aud", "exp", "iat", "sub"],
        clockTolerance: 5,
        maxTokenAge: "24h",
      });
      const claims = result.payload;
      if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 512) throw new Error("sub");
      if (nonce !== undefined && !constantTimeEqual(claims.nonce, nonce)) throw new Error("nonce");
      if (expectedSubject && claims.sub !== expectedSubject) throw new Error("subject");
      if (claims.email !== undefined && (typeof claims.email !== "string" || claims.email.length > 320)) throw new Error("email");
      return claims as JWTPayload & { sub: string };
    } catch {
      throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in returned an invalid ID token.");
    }
  }

  private async validateAccessToken(token: string, clientId: string, expectedSubject: string, grantedScopes: string[], expiresIn: unknown): Promise<AccessTokenEntry> {
    try {
      const result = await jwtVerify(token, this.jwks, {
        issuer: ISSUER,
        audience: RESOURCE,
        algorithms: ["RS256"],
        requiredClaims: ["iss", "aud", "exp", "iat", "sub", "client_id", "scope"],
        clockTolerance: 5,
        maxTokenAge: "24h",
      });
      const claims = result.payload;
      if (claims.sub !== expectedSubject || claims.client_id !== clientId || typeof claims.scope !== "string") throw new Error("claims");
      const tokenScopes = parseScopes(claims.scope);
      requireScopes(tokenScopes);
      requireScopes(grantedScopes);
      const exp = integer(claims.exp, Math.floor(this.now() / 1000) + 1, Math.floor(this.now() / 1000) + 24 * 60 * 60);
      const lifetime = integer(expiresIn, 1, 3600);
      if (!exp || !lifetime) throw new Error("expiry");
      return { token, expiresAt: Math.min(exp * 1000, this.now() + lifetime * 1000) };
    } catch {
      throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in returned an invalid access token.");
    }
  }

  private async getAccessToken(profileId: string): Promise<AccessTokenEntry> {
    if (this.disconnecting.has(profileId)) throw new OAuthConnectorError("profile_disconnected", "Reconnect the ChatGPT profile to continue.");
    const profile = await this.profile(profileId);
    if (!profile.refreshToken) {
      this.accessTokens.delete(profileId);
      throw new OAuthConnectorError("profile_disconnected", "Reconnect the ChatGPT profile to continue.");
    }
    const cached = this.accessTokens.get(profileId);
    if (cached && cached.expiresAt > this.now() + 30_000) return cached;
    let pending = this.accessFlights.get(profileId);
    if (!pending) {
      pending = this.refreshProfile(profileId).finally(() => this.accessFlights.delete(profileId));
      this.accessFlights.set(profileId, pending);
    }
    const token = await pending;
    if (this.disconnecting.has(profileId)) throw new OAuthConnectorError("profile_disconnected", "Reconnect the ChatGPT profile to continue.");
    return token;
  }

  private async refreshProfile(profileId: string): Promise<AccessTokenEntry> {
    const epoch = this.profileEpochs.get(profileId) ?? 0;
    let result: AccessTokenEntry | undefined;
    try {
      await this.profiles.transaction(async (storage) => {
        const profile = storage.profiles.find((item) => item.profileId === profileId);
        if (!profile || !profile.refreshToken) throw new OAuthConnectorError("profile_disconnected", "Reconnect the ChatGPT profile to continue.");
        const current = this.accessTokens.get(profileId);
        if (current && current.expiresAt > this.now() + 30_000) {
          result = current;
          return { value: undefined };
        }
        const body = new URLSearchParams({
          grant_type: "refresh_token",
          client_id: profile.clientId,
          refresh_token: profile.refreshToken,
          resource: RESOURCE,
        });
        let payload: OAuthTokenResponse;
        try {
          payload = await this.tokenRequest(body);
        } catch (error) {
          if (error instanceof OAuthConnectorError && error.code === "token_request_failed") {
            throw new OAuthConnectorError("refresh_failed", "ChatGPT access could not be refreshed.");
          }
          throw error;
        }
        const access = requireToken(payload.access_token, "access_token");
        const nextRefresh = requireToken(payload.refresh_token, "refresh_token");
        if (nextRefresh === profile.refreshToken) throw new OAuthConnectorError("refresh_failed", "ChatGPT did not rotate the refresh token.");
        const scopes = payload.scope === undefined ? profile.scopes : parseScopes(payload.scope);
        requireScopes(scopes);
        if (typeof payload.id_token === "string") await this.verifyIdToken(payload.id_token, profile.clientId, undefined, profile.subject);
        result = await this.validateAccessToken(access, profile.clientId, profile.subject, scopes, payload.expires_in);
        const nextProfile = { ...profile, refreshToken: nextRefresh, scopes };
        return {
          value: undefined,
          next: { ...storage, profiles: storage.profiles.map((item) => item.profileId === profileId ? nextProfile : item) },
        };
      });
    } catch (error) {
      if (isInvalidGrant(error)) {
        await this.profiles.update((storage) => ({
          ...storage,
          profiles: storage.profiles.map((profile) => {
            if (profile.profileId !== profileId) return profile;
            const { refreshToken: _refreshToken, ...disconnected } = profile;
            return disconnected;
          }),
        }));
        this.accessTokens.delete(profileId);
        throw new OAuthConnectorError("reauth_required", "The ChatGPT session expired; sign in again.");
      }
      throw safeOAuthError(error, "refresh_failed", "ChatGPT access could not be refreshed.");
    }
    if (!result) throw new OAuthConnectorError("refresh_failed", "ChatGPT access could not be refreshed.");
    if (this.disconnecting.has(profileId) || (this.profileEpochs.get(profileId) ?? 0) !== epoch) throw new OAuthConnectorError("profile_disconnected", "Reconnect the ChatGPT profile to continue.");
    this.profileEpochs.set(profileId, epoch + 1);
    this.envelopeCache.clear();
    this.envelopeFlights.clear();
    this.accessTokens.set(profileId, result);
    return result;
  }

  private async mintEnvelope(alias: string, profileId: string, expectedProjectId: string, machineBearer: string): Promise<CredentialEnvelope> {
    const token = await this.getAccessToken(profileId);
    const epoch = this.profileEpochs.get(profileId) ?? 0;
    const expiresAt = Math.floor(token.expiresAt / 1000);
    const config = await this.configStore.load();
    const profile = await this.profile(profileId);
    if (!profile.refreshToken || profile.projectId !== expectedProjectId || profile.identityOrigin !== new URL(config.identityUrl).origin) {
      throw new OAuthConnectorError("pairing_required", "Pair this ChatGPT profile with the currently configured Identity service.");
    }
    const response = await this.fetchImpl(new URL("/api/oauth/token-envelope", config.identityUrl), {
      method: "POST",
      headers: { authorization: `Bearer ${machineBearer}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ connectorId: "chatgpt", model: alias, accessToken: token.token, expiresAt }),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    }).catch(() => { throw new OAuthConnectorError("envelope_failed", "Identity could not create the short-lived ChatGPT credential."); });
    const payload = await readBoundedJson(response, 32_768);
    if (!response.ok) {
      const code = isRecord(payload) && payload.error === "remote_inference_not_verified" ? "eligibility_pending" : "envelope_failed";
      const message = code === "eligibility_pending"
        ? "Remote ChatGPT OAuth inference has not been enabled for this deployment."
        : "Identity could not create the short-lived ChatGPT credential.";
      throw new OAuthConnectorError(code, message);
    }
    if (!isRecord(payload) || payload.provider !== "openai" || typeof payload.credentialId !== "string" || !Number.isSafeInteger(payload.expiresAt)) {
      throw new OAuthConnectorError("envelope_failed", "Identity returned an invalid short-lived ChatGPT credential.");
    }
    let envelope: CredentialEnvelope;
    try { envelope = parseCredentialEnvelope(payload.envelope); }
    catch { throw new OAuthConnectorError("envelope_failed", "Identity returned an invalid short-lived ChatGPT credential."); }
    if (envelope.provider !== "openai" || envelope.credentialId !== payload.credentialId || envelope.exp !== payload.expiresAt || envelope.exp > expiresAt || envelope.projectId !== expectedProjectId) {
      throw new OAuthConnectorError("envelope_failed", "Identity returned an invalid short-lived ChatGPT credential.");
    }
    const currentProfile = await this.profile(profileId);
    const currentConfig = await this.configStore.load();
    const currentBinding = (currentConfig.oauthModels ?? []).find((item) => item.alias === alias);
    if ((this.profileEpochs.get(profileId) ?? 0) !== epoch || !currentProfile.refreshToken || currentProfile.projectId !== expectedProjectId || currentProfile.identityOrigin !== new URL(currentConfig.identityUrl).origin || currentBinding?.profileId !== profileId) {
      throw new OAuthConnectorError("profile_disconnected", "The ChatGPT profile changed while the short-lived credential was being created.");
    }
    this.envelopeCache.set(`${alias}:${profileId}:${expectedProjectId}:responses`, envelope);
    return envelope;
  }

  private async revokeRefreshToken(clientId: string, refreshToken: string): Promise<boolean> {
    let endpoint: URL;
    try {
      const discoveryResponse = await this.fetchImpl(new URL("/.well-known/openid-configuration", ISSUER), {
        headers: { accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(10_000),
      });
      const discovery = await readBoundedJson(discoveryResponse, 32_768);
      if (!discoveryResponse.ok || !isRecord(discovery) || typeof discovery.revocation_endpoint !== "string") return false;
      endpoint = new URL(discovery.revocation_endpoint);
      if (endpoint.protocol !== "https:" || endpoint.origin !== ISSUER || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) return false;
    } catch { return false; }
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const response = await this.fetchImpl(endpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
          body: new URLSearchParams({ token: refreshToken, token_type_hint: "refresh_token", client_id: clientId }),
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        if (response.ok) return true;
      } catch { /* A bounded retry follows. */ }
    }
    return false;
  }

  private async profile(profileId: string): Promise<StoredChatGptProfile> {
    const profile = (await this.profiles.snapshot()).profiles.find((item) => item.profileId === profileId);
    if (!profile) throw new OAuthConnectorError("profile_not_found", "OAuth profile was not found.");
    return profile;
  }

  private pruneOperations(): void {
    const cutoff = this.now() - OPERATION_TTL_MS * 2;
    for (const [id, operation] of this.operations) {
      if (operation.createdAt < cutoff && operation.status.status !== "pending") this.operations.delete(id);
    }
  }

  private prunePairingGrants(): void {
    const cutoff = this.now() - OPERATION_TTL_MS;
    for (const [id, grant] of this.pairingGrants) if (grant.createdAt < cutoff) this.pairingGrants.delete(id);
  }

  private async handleCallback(request: IncomingMessage, response: ServerResponse, operation: LoginOperation): Promise<void> {
    const address = operation.server.address();
    const expectedHost = address && typeof address !== "string" ? `127.0.0.1:${address.port}` : "";
    if (request.method !== "GET" || request.url === undefined || request.url.length > 8_192 || request.headers.host !== expectedHost || !isLoopbackAddress(request.socket.remoteAddress)) {
      sendCallbackPage(response, 400, "This OAuth callback is invalid.");
      return;
    }
    let url: URL;
    try { url = new URL(request.url, "http://127.0.0.1"); }
    catch { sendCallbackPage(response, 400, "This OAuth callback is invalid."); return; }
    if (url.pathname !== "/auth/callback" || url.searchParams.getAll("state").length !== 1) {
      sendCallbackPage(response, 400, "This OAuth callback is invalid.");
      return;
    }
    if (!constantTimeEqual(url.searchParams.get("state"), operation.state)) {
      sendCallbackPage(response, 400, "The OAuth state did not match. Return to the adapter and try again.");
      return;
    }
    if (operation.callbackAccepted) {
      sendCallbackPage(response, 409, "This OAuth callback was already received.");
      return;
    }
    const error = url.searchParams.get("error");
    if (error) {
      operation.callbackAccepted = true;
      operation.resolveCallback({ error: true });
      operation.generation += 1;
      operation.status = { status: "failed", code: "authorization_failed" };
      sendCallbackPage(response, 400, "ChatGPT authorization was not completed.");
      return;
    }
    const code = url.searchParams.get("code");
    const clientValues = url.searchParams.getAll("client_id");
    if (!code || code.length > 4096 || !/^[\x21-\x7e]+$/.test(code) || clientValues.length > 1 || (clientValues[0] && !isClientId(clientValues[0]))) {
      sendCallbackPage(response, 400, "ChatGPT returned an invalid sign-in response.");
      return;
    }
    operation.callbackAccepted = true;
    operation.resolveCallback({ code, ...(clientValues[0] ? { clientId: clientValues[0] } : {}) });
    sendCallbackPage(response, 200, "ChatGPT sign-in response received. Return to the adapter to check the connection status.");
  }

}

export class OAuthConnectorError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "OAuthConnectorError";
  }
}

function normalizeModels(value: unknown): OAuthModelSummary[] {
  if (!isRecord(value) || !Array.isArray(value.models) || value.models.length > 2_000) {
    throw new OAuthConnectorError("model_discovery_failed", "ChatGPT returned an invalid model list.");
  }
  const result: OAuthModelSummary[] = [];
  const seen = new Set<string>();
  for (const item of value.models) {
    if (!isRecord(item) || item.visibility !== "list" || item.supported_in_api !== true) continue;
    const id = boundedString(item.slug ?? item.id, /^[^\u0000-\u0020]{1,256}$/);
    if (!id || seen.has(id)) continue;
    const model: OAuthModelSummary = {
      id,
      inputModalities: normalizeStringArray(item.input_modalities, new Set(["text", "image", "audio", "video"]), 16),
      reasoningEfforts: normalizeReasoning(item.supported_reasoning_levels),
    };
    const displayName = boundedString(item.display_name, /^.{1,256}$/s);
    const contextWindow = integer(item.context_window, 1, 10_000_000);
    if (displayName) model.displayName = displayName;
    if (contextWindow) model.contextWindow = contextWindow;
    seen.add(id);
    result.push(model);
    if (result.length >= 500) break;
  }
  return result.sort((a, b) => a.id.localeCompare(b.id));
}

function normalizeStringArray(value: unknown, allowed: Set<string>, maximum: number): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string => typeof item === "string" && allowed.has(item)))].slice(0, maximum);
}

function normalizeReasoning(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.flatMap((item) => isRecord(item) && typeof item.effort === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(item.effort) ? [item.effort] : []))].slice(0, 32);
}

function parseScopes(value: unknown): string[] {
  if (typeof value !== "string" || value.length > 4096) throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in did not grant the required scopes.");
  return [...new Set(value.split(/\s+/).filter(Boolean))];
}

function requireScopes(scopes: string[]): void {
  if (!REQUIRED_SCOPES.every((scope) => scopes.includes(scope))) {
    throw new OAuthConnectorError("invalid_response", "ChatGPT sign-in did not grant the required scopes.");
  }
}

function requireToken(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length < 20 || value.length > 16_384 || /[\r\n\u0000]/.test(value)) {
    throw new OAuthConnectorError("invalid_response", `ChatGPT returned an invalid ${name}.`);
  }
  return value;
}

async function readBoundedJson(response: Response, limit: number): Promise<unknown> {
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length) && length > limit) throw new OAuthConnectorError("invalid_response", "OAuth server returned an oversized response.");
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new OAuthConnectorError("invalid_response", "OAuth server returned an oversized response.");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(concat(chunks, size))) as unknown; }
  catch { return undefined; }
}

function concat(chunks: Uint8Array[], size: number): Uint8Array {
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

function isModelAlias(value: string): boolean {
  return value.length > 0 && value.length <= 128 && !/[\u0000-\u0020]/.test(value);
}

function isClientId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,512}$/.test(value);
}

function boundedString(value: unknown, pattern: RegExp): string | undefined {
  return typeof value === "string" && pattern.test(value) ? value : undefined;
}

function integer(value: unknown, minimum: number, maximum: number): number | undefined {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum ? Number(value) : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isLoopbackAddress(value: string | undefined): boolean {
  if (!value) return false;
  const address = value.startsWith("::ffff:") ? value.slice(7) : value;
  return address === "127.0.0.1" || address === "::1";
}

function constantTimeEqual(actual: unknown, expected: string): boolean {
  if (typeof actual !== "string" || actual.length > 512) return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function isLoginPending(operation: LoginOperation, generation: number): boolean {
  return operation.status.status === "pending" && operation.generation === generation;
}

function sendCallbackPage(response: ServerResponse, status: number, message: string): void {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
    "x-content-type-options": "nosniff",
  });
  response.end(`<!doctype html><meta charset="utf-8"><title>ChatGPT connection</title><p>${escapeHtml(message)}</p>`);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char);
}

function listenLoopback(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => { server.off("listening", onListening); reject(error); };
    const onListening = () => { server.off("error", onError); resolve(); };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0, "127.0.0.1");
  });
}

function closeServer(server: Server): void {
  if (server.listening) server.close();
}

function safeOAuthError(error: unknown, code: string, message: string): OAuthConnectorError {
  if (error instanceof OAuthConnectorError) return error;
  if (error instanceof OAuthStoreError) return new OAuthConnectorError("storage_failed", error.message);
  return new OAuthConnectorError(code, message);
}

function isInvalidGrant(error: unknown): boolean {
  return error instanceof OAuthConnectorError && error.code === "invalid_grant";
}

