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
  if (!browserState || !constantTimeEqual(browserState, transaction.state)) {
    throw new Error("OIDC state validation failed");
  }
  if (transaction.expiresAt <= Math.floor(Date.now() / 1000)) throw new Error("OIDC transaction expired");
  if (transaction.provider.id !== provider.id || transaction.redirectUri !== provider.redirectUri) {
    throw new Error("OIDC transaction does not match configured provider");
  }
  if (`${callbackUrl.origin}${callbackUrl.pathname}` !== provider.redirectUri) {
    throw new Error("OIDC callback URI does not match the registered redirect URI");
  }

  const as = await authorizationServer(provider);
  const client: oauth.Client = { client_id: provider.clientId };
  const params = oauth.validateAuthResponse(as, client, callbackUrl, transaction.state);
  const response = await oauth.authorizationCodeGrantRequest(
    as,
    client,
    oauth.ClientSecretBasic(provider.clientSecret),
    params,
    provider.redirectUri,
    transaction.codeVerifier,
  );
  const result = await oauth.processAuthorizationCodeResponse(as, client, response, {
    expectedNonce: transaction.nonce,
    requireIdToken: true,
  });
  await oauth.validateApplicationLevelSignature(as, response);
  const claims = oauth.getValidatedIdTokenClaims(result);
  if (!claims || claims.iss !== as.issuer) throw new Error("OIDC issuer validation failed");
  if (typeof claims.sub !== "string" || claims.sub.length < 1 || claims.sub.length > 512) throw new Error("OIDC subject is invalid");
  if (claims.email_verified !== true || typeof claims.email !== "string") throw new Error("A verified email claim is required");
  const email = claims.email.trim().toLowerCase();
  if (email.length < 3 || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("OIDC email is invalid");
  const name = typeof claims.name === "string" ? claims.name.trim() : "";
  return {
    issuer: as.issuer,
    subject: claims.sub,
    email,
    displayName: name.slice(0, 160) || email,
  };
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
