import * as oauth from "oauth4webapi";
import { constantTimeEqual, sha256Base64Url } from "./security.js";

export interface OidcProvider {
  id: string;
  label: string;
  issuer: URL;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface OidcIdentity {
  issuer: string;
  subject: string;
  email: string;
  displayName: string;
}

export interface OidcTransaction {
  stateHash: string;
  state: string;
  provider: OidcProvider;
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  returnTo: string;
  expiresAt: number;
}

export type OidcCallbackStage = "discovery" | "auth_response" | "token_request" | "token_response" | "signature" | "claims";
export type OidcSafeClaim = "iss" | "aud" | "nonce" | "exp" | "iat";
type OidcOAuthErrorName = "invalid_client" | "invalid_grant" | "invalid_request" | "unauthorized_client" | "access_denied" | "temporarily_unavailable" | "server_error";

const oauthErrorNames = new Set<OidcOAuthErrorName>([
  "invalid_client", "invalid_grant", "invalid_request", "unauthorized_client", "access_denied", "temporarily_unavailable", "server_error",
]);

const oauthLibraryCodeList = [
  oauth.RESPONSE_BODY_ERROR,
  oauth.UNSUPPORTED_OPERATION,
  oauth.AUTHORIZATION_RESPONSE_ERROR,
  oauth.JWT_USERINFO_EXPECTED,
  oauth.PARSE_ERROR,
  oauth.INVALID_RESPONSE,
  oauth.INVALID_REQUEST,
  oauth.RESPONSE_IS_NOT_JSON,
  oauth.RESPONSE_IS_NOT_CONFORM,
  oauth.HTTP_REQUEST_FORBIDDEN,
  oauth.REQUEST_PROTOCOL_FORBIDDEN,
  oauth.JWT_TIMESTAMP_CHECK,
  oauth.JWT_CLAIM_COMPARISON,
  oauth.JSON_ATTRIBUTE_COMPARISON,
  oauth.KEY_SELECTION,
  oauth.MISSING_SERVER_METADATA,
  oauth.INVALID_SERVER_METADATA,
] as const;
type OidcCallbackReason = OidcOAuthErrorName | typeof oauthLibraryCodeList[number];
const oauthLibraryCodes = new Set<string>(oauthLibraryCodeList);

const callbackStages = new Set<OidcCallbackStage>(["discovery", "auth_response", "token_request", "token_response", "signature", "claims"]);
const callbackReasons = new Set<string>([...oauthErrorNames, ...oauthLibraryCodeList]);

/** Fixed, value-free classification safe to expose to operators. */
export class OidcCallbackFailure extends Error {
  readonly stage: OidcCallbackStage;
  readonly reason: OidcCallbackReason;
  readonly claim?: OidcSafeClaim;

  constructor(stage: OidcCallbackStage, reason: OidcCallbackReason, claim?: OidcSafeClaim) {
    const safeStage = callbackStages.has(stage) ? stage : "claims";
    const safeReason = callbackReasons.has(reason) ? reason : oauth.INVALID_RESPONSE;
    const safeClaim = isSafeClaim(claim) ? claim : undefined;
    super(`${safeStage}:${safeReason}${safeClaim ? `:${safeClaim}` : ""}`);
    this.name = "OidcCallbackFailure";
    this.stage = safeStage;
    this.reason = safeReason;
    this.claim = safeClaim;
  }
}

function isSafeClaim(value: unknown): value is OidcSafeClaim {
  return value === "iss" || value === "aud" || value === "nonce" || value === "exp" || value === "iat";
}

function safeOAuthErrorName(value: unknown): OidcOAuthErrorName | undefined {
  return typeof value === "string" && oauthErrorNames.has(value as OidcOAuthErrorName) ? value as OidcOAuthErrorName : undefined;
}

function classifyOAuthFailure(error: unknown, stage: OidcCallbackStage): OidcCallbackFailure {
  let reason: OidcCallbackReason = oauth.INVALID_RESPONSE;
  let claim: OidcSafeClaim | undefined;

  if (error instanceof oauth.ResponseBodyError || error instanceof oauth.AuthorizationResponseError) {
    reason = safeOAuthErrorName(error.error) ?? oauth.RESPONSE_BODY_ERROR;
  } else if (error instanceof oauth.OperationProcessingError || error instanceof oauth.UnsupportedOperationError) {
    if (typeof error.code === "string" && oauthLibraryCodes.has(error.code)) reason = error.code as OidcCallbackReason;
    if (error instanceof oauth.OperationProcessingError && error.code === oauth.JWT_CLAIM_COMPARISON) {
      const cause = error.cause;
      if (cause && typeof cause === "object" && isSafeClaim((cause as { claim?: unknown }).claim)) {
        claim = (cause as { claim: OidcSafeClaim }).claim;
      }
    }
  }

  const classifiedStage = stage === "token_response" && reason === oauth.JWT_CLAIM_COMPARISON ? "claims" : stage;
  return new OidcCallbackFailure(classifiedStage, reason, claim);
}

async function atStage<T>(stage: OidcCallbackStage, operation: () => T | Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof OidcCallbackFailure) throw error;
    throw classifyOAuthFailure(error, stage);
  }
}

function failOidc(stage: OidcCallbackStage, reason: OidcCallbackReason, claim?: OidcSafeClaim): never {
  throw new OidcCallbackFailure(stage, reason, claim);
}

function clientSecretAuthentication(as: oauth.AuthorizationServer, provider: OidcProvider): oauth.ClientAuth {
  const advertised = as.token_endpoint_auth_methods_supported as unknown;
  if (advertised !== undefined && !Array.isArray(advertised)) {
    throw new oauth.UnsupportedOperationError("No supported client authentication method");
  }
  const supported = advertised as string[] | undefined;
  if (supported?.includes("client_secret_post")) return oauth.ClientSecretPost(provider.clientSecret);
  if (!supported || supported.includes("client_secret_basic")) return oauth.ClientSecretBasic(provider.clientSecret);
  throw new oauth.UnsupportedOperationError("No supported client authentication method");
}

interface RawOidcProvider {
  id: string;
  label?: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

const providerIdPattern = /^[a-z][a-z0-9_-]{0,31}$/;
const discoveryCache = new Map<string, Promise<oauth.AuthorizationServer>>();

export function parseOidcProviders(raw: string | undefined): OidcProvider[] {
  if (!raw || raw.length > 32_768) return [];
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(value) || value.length > 8) return [];
  const seen = new Set<string>();
  const providers: OidcProvider[] = [];
  for (const candidate of value) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
    const item = candidate as Partial<RawOidcProvider>;
    if (
      typeof item.id !== "string" ||
      !providerIdPattern.test(item.id) ||
      seen.has(item.id) ||
      typeof item.issuer !== "string" ||
      typeof item.clientId !== "string" ||
      item.clientId.length < 1 ||
      item.clientId.length > 512 ||
      typeof item.clientSecret !== "string" ||
      item.clientSecret.length < 1 ||
      item.clientSecret.length > 2048 ||
      typeof item.redirectUri !== "string"
    ) continue;
    let issuer: URL;
    let redirectUri: URL;
    try {
      issuer = new URL(item.issuer);
      redirectUri = new URL(item.redirectUri);
    } catch {
      continue;
    }
    if (!isSafeOrigin(issuer) || issuer.search || issuer.hash || issuer.username || issuer.password) continue;
    if (!isSafeOrigin(redirectUri) || redirectUri.search || redirectUri.hash || redirectUri.username || redirectUri.password) continue;
    seen.add(item.id);
    providers.push({
      id: item.id,
      label: typeof item.label === "string" && item.label.length <= 80 ? item.label : item.id,
      issuer,
      clientId: item.clientId,
      clientSecret: item.clientSecret,
      redirectUri: redirectUri.href,
    });
  }
  return providers;
}

function isSafeOrigin(url: URL): boolean {
  return url.protocol === "https:" || (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]"));
}

function authorizationServer(provider: OidcProvider): Promise<oauth.AuthorizationServer> {
  const key = provider.issuer.href;
  let pending = discoveryCache.get(key);
  if (!pending) {
    pending = oauth
      .discoveryRequest(provider.issuer, { algorithm: "oidc" })
      .then((response) => oauth.processDiscoveryResponse(provider.issuer, response))
      .then((as) => {
        for (const name of ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"] as const) {
          const endpoint = as[name];
          if (endpoint !== undefined && !isPublicHttpsEndpoint(endpoint)) {
            throw new Error(`OIDC provider ${name} must use a public HTTPS URL`);
          }
        }
        return as;
      });
    discoveryCache.set(key, pending);
    pending.catch(() => discoveryCache.delete(key));
  }
  return pending;
}

export function isPublicHttpsEndpoint(raw: string): boolean {
  try {
    const url = new URL(raw);
    const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    return url.protocol === "https:" && !url.username && !url.password && !url.hash &&
      hostname.includes(".") && !hostname.includes(":") && !/^\d+(?:\.\d+){3}$/.test(hostname) &&
      hostname !== "localhost" && !hostname.endsWith(".localhost") && !hostname.endsWith(".local") && !hostname.endsWith(".internal");
  } catch {
    return false;
  }
}

export async function createOidcAuthorizationRequest(provider: OidcProvider): Promise<{
  state: string;
  stateHash: string;
  nonce: string;
  codeVerifier: string;
  authorizationUrl: string;
}> {
  const as = await authorizationServer(provider);
  if (!as.authorization_endpoint) throw new Error("OIDC provider has no authorization endpoint");
  const endpoint = new URL(as.authorization_endpoint);
  if (!isPublicHttpsEndpoint(endpoint.href)) throw new Error("OIDC provider authorization endpoint is not public HTTPS");
  const client: oauth.Client = { client_id: provider.clientId };
  const state = oauth.generateRandomState();
  const nonce = oauth.generateRandomNonce();
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
  const authorizationUrl = new URL(endpoint);
  authorizationUrl.searchParams.set("client_id", client.client_id);
  authorizationUrl.searchParams.set("redirect_uri", provider.redirectUri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", "openid email profile");
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("nonce", nonce);
  return { state, stateHash: await sha256Base64Url(state), nonce, codeVerifier, authorizationUrl: authorizationUrl.href };
}

export async function processOidcCallback(
  provider: OidcProvider,
  callbackUrl: URL,
  transaction: OidcTransaction,
  browserState: string | undefined,
): Promise<OidcIdentity> {
  await atStage("auth_response", () => {
    if (!browserState || !constantTimeEqual(browserState, transaction.state)) {
      failOidc("auth_response", oauth.INVALID_REQUEST);
    }
    if (transaction.expiresAt <= Math.floor(Date.now() / 1000)) failOidc("auth_response", oauth.INVALID_REQUEST);
    if (transaction.provider.id !== provider.id || transaction.redirectUri !== provider.redirectUri) {
      failOidc("auth_response", oauth.INVALID_REQUEST);
    }
    if (`${callbackUrl.origin}${callbackUrl.pathname}` !== provider.redirectUri) {
      failOidc("auth_response", oauth.INVALID_REQUEST);
    }
  });
  const as = await atStage("discovery", () => authorizationServer(provider));
  const client: oauth.Client = { client_id: provider.clientId };
  const params = await atStage("auth_response", () => oauth.validateAuthResponse(as, client, callbackUrl, transaction.state));
  const response = await atStage("token_request", () => oauth.authorizationCodeGrantRequest(
    as,
    client,
    clientSecretAuthentication(as, provider),
    params,
    provider.redirectUri,
    transaction.codeVerifier,
  ));
  const result = await atStage("token_response", () => oauth.processAuthorizationCodeResponse(as, client, response, {
    expectedNonce: transaction.nonce,
    requireIdToken: true,
  }));
  await atStage("signature", () => oauth.validateApplicationLevelSignature(as, response));
  return atStage("claims", () => {
    const claims = oauth.getValidatedIdTokenClaims(result);
    if (!claims || claims.iss !== as.issuer) failOidc("claims", oauth.JWT_CLAIM_COMPARISON, "iss");
    if (typeof claims.sub !== "string" || claims.sub.length < 1 || claims.sub.length > 512) {
      failOidc("claims", oauth.INVALID_RESPONSE);
    }
    if (claims.email_verified !== true || typeof claims.email !== "string") failOidc("claims", oauth.INVALID_RESPONSE);
    const email = claims.email.trim().toLowerCase();
    if (email.length < 3 || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      failOidc("claims", oauth.INVALID_RESPONSE);
    }
    const name = typeof claims.name === "string" ? claims.name.trim() : "";
    return {
      issuer: as.issuer,
      subject: claims.sub,
      email,
      displayName: name.slice(0, 160) || email,
    };
  });
}

export function safeReturnTo(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return "/";
  try {
    const url = new URL(value, "https://identity.invalid");
    if (url.origin !== "https://identity.invalid") return "/";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "/";
  }
}
