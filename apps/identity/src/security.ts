import {
  encryptCredentialEnvelope,
  issueGatewayAccessToken,
  verifyGatewayAccessToken,
  type CredentialEnvelope,
  type GatewayAccessTokenClaims,
} from "@ws-proxy/shared";
import { importJWK, type JWK } from "jose";

export type MachineJwk = JWK & { kid: string; alg?: string; use?: string };

export interface MachineClaims extends GatewayAccessTokenClaims {
  iss: string;
  aud: string | string[];
  exp: number;
}

export interface EnvelopeKeySet {
  current: string;
  keys: Record<string, string>;
}

type MachineEnv = Pick<Env, "MACHINE_ISSUER" | "MACHINE_JWT_PRIVATE_JWK" | "MACHINE_JWT_PUBLIC_JWKS">;

const b64urlPattern = /^[A-Za-z0-9_-]+$/;
const keyIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  if (!b64urlPattern.test(value)) throw new Error("Invalid base64url value");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("Invalid base64url value");
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new Error("Non-canonical base64url value");
  return bytes;
}

export function randomToken(size = 32): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

export function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return encodeBase64Url(new Uint8Array(digest));
}

/** Compare hashes without returning early on the first different byte. */
export function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}

export async function readJson(request: Request, maximumBytes = 16_384): Promise<Record<string, unknown>> {
  const text = await readTextBody(request, maximumBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new RequestBodyError("invalid_json", 400);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RequestBodyError("invalid_json", 400);
  }
  return parsed as Record<string, unknown>;
}

export async function readTextBody(request: Request, maximumBytes: number): Promise<string> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) > maximumBytes)) {
    throw new RequestBodyError("request_too_large", 413);
  }
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  if (reader) {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new RequestBodyError("request_too_large", 413);
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new RequestBodyError("invalid_encoding", 400);
  }
}

export class RequestBodyError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
  ) {
    super(code);
  }
}

function parseObject(raw: string | undefined, name: string): Record<string, unknown> {
  if (!raw || raw.length > 32_768) throw new Error(`${name} is not configured`);
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error(`${name} is invalid`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} is invalid`);
  return value as Record<string, unknown>;
}

function parseIssuer(raw: string | undefined): string {
  if (!raw) throw new Error("MACHINE_ISSUER is not configured");
  const issuer = new URL(raw);
  const loopback = issuer.hostname === "localhost" || issuer.hostname === "127.0.0.1" || issuer.hostname === "[::1]";
  if (issuer.protocol !== "https:" && !(issuer.protocol === "http:" && loopback)) {
    throw new Error("MACHINE_ISSUER must use HTTPS");
  }
  if (issuer.username || issuer.password || issuer.search || issuer.hash) throw new Error("MACHINE_ISSUER is invalid");
  return raw;
}

function parseMachinePrivateJwk(raw: string | undefined): MachineJwk {
  const parsed = parseObject(raw, "MACHINE_JWT_PRIVATE_JWK");
  const kid = parsed.kid;
  if (parsed.kty !== "EC" || parsed.crv !== "P-256" || typeof parsed.d !== "string" || typeof kid !== "string" || !keyIdPattern.test(kid)) {
    throw new Error("MACHINE_JWT_PRIVATE_JWK is invalid");
  }
  if (parsed.alg !== undefined && parsed.alg !== "ES256") throw new Error("MACHINE_JWT_PRIVATE_JWK uses an unsupported algorithm");
  return { ...parsed, kid, alg: "ES256", use: "sig" } as MachineJwk;
}

export function parsePublicJwks(raw: string | undefined): MachineJwk[] {
  const parsed = parseObject(raw, "MACHINE_JWT_PUBLIC_JWKS");
  if (!Array.isArray(parsed.keys) || parsed.keys.length > 16) throw new Error("MACHINE_JWT_PUBLIC_JWKS is invalid");
  const ids = new Set<string>();
  return parsed.keys.map((candidate) => {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) throw new Error("MACHINE_JWT_PUBLIC_JWKS is invalid");
    const jwk = candidate as Record<string, unknown>;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.kid !== "string" || !keyIdPattern.test(jwk.kid)) {
      throw new Error("MACHINE_JWT_PUBLIC_JWKS contains an invalid key");
    }
    if ("d" in jwk) throw new Error("MACHINE_JWT_PUBLIC_JWKS must contain public keys only");
    if (typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("MACHINE_JWT_PUBLIC_JWKS contains an invalid key");
    if (ids.has(jwk.kid)) throw new Error("MACHINE_JWT_PUBLIC_JWKS contains duplicate key ids");
    ids.add(jwk.kid);
    if (jwk.alg !== undefined && jwk.alg !== "ES256") throw new Error("MACHINE_JWT_PUBLIC_JWKS contains an unsupported algorithm");
    return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid: jwk.kid, alg: "ES256", use: "sig" } as MachineJwk;
  });
}

export function publicJwksResponse(raw: string | undefined): Response {
  const keys = parsePublicJwks(raw).map(({ kty, crv, x, y, kid, alg, use }) => ({ kty, crv, x, y, kid, alg, use }));
  return Response.json({ keys }, { headers: { "cache-control": "public, max-age=60" } });
}

export function parseEnvelopeKeys(raw: string | undefined): EnvelopeKeySet {
  const parsed = parseObject(raw, "ENVELOPE_KEYS");
  if (typeof parsed.current !== "string" || !keyIdPattern.test(parsed.current)) throw new Error("ENVELOPE_KEYS is invalid");
  if (!parsed.keys || typeof parsed.keys !== "object" || Array.isArray(parsed.keys)) throw new Error("ENVELOPE_KEYS is invalid");
  const keys = parsed.keys as Record<string, unknown>;
  const current = keys[parsed.current];
  if (typeof current !== "string" || decodeBase64Url(current).byteLength !== 32) throw new Error("ENVELOPE_KEYS current key is invalid");
  for (const [kid, encoded] of Object.entries(keys)) {
    if (!keyIdPattern.test(kid) || typeof encoded !== "string" || decodeBase64Url(encoded).byteLength !== 32) {
      throw new Error("ENVELOPE_KEYS contains an invalid key");
    }
  }
  return { current: parsed.current, keys: Object.fromEntries(Object.entries(keys) as [string, string][]) };
}

export function envelopeKeyVersions(raw: string | undefined): { current: string; keyVersions: string[] } {
  const config = parseEnvelopeKeys(raw);
  return { current: config.current, keyVersions: Object.keys(config.keys).sort() };
}

export async function createCredentialEnvelope(
  rawKey: string,
  metadata: { credentialId: string; userId: string; projectId: string; provider: string; exp: number },
  rawKeyConfig: string | undefined,
): Promise<CredentialEnvelope> {
  const config = parseEnvelopeKeys(rawKeyConfig);
  const keyBytes = decodeBase64Url(config.keys[config.current]);
  const plaintext = new TextEncoder().encode(rawKey);
  try {
    return await encryptCredentialEnvelope(
      plaintext,
      { ...metadata, kid: config.current },
      keyBytes,
    );
  } finally {
    plaintext.fill(0);
    keyBytes.fill(0);
  }
}

const importedKeyCache = new Map<string, Promise<CryptoKey>>();

export async function signMachineAccessToken(
  claims: { userId: string; sessionId: string; projectId: string; clientId: string; tokenId: string },
  env: MachineEnv,
  now = Math.floor(Date.now() / 1000),
): Promise<string> {
  const jwk = parseMachinePrivateJwk(env.MACHINE_JWT_PRIVATE_JWK);
  const publicKey = parsePublicJwks(env.MACHINE_JWT_PUBLIC_JWKS).find((candidate) => candidate.kid === jwk.kid);
  if (!publicKey || publicKey.x !== jwk.x || publicKey.y !== jwk.y) throw new Error("Active signing key is missing from public JWKS");
  const cacheKey = `private:${jwk.kid}:${jwk.x}:${jwk.y}`;
  let key = importedKeyCache.get(cacheKey);
  if (!key) {
    key = importJWK(jwk as JWK, "ES256") as Promise<CryptoKey>;
    importedKeyCache.set(cacheKey, key);
  }
  return issueGatewayAccessToken(claims, await key, {
    issuer: parseIssuer(env.MACHINE_ISSUER),
    kid: jwk.kid,
    now,
  });
}

export async function verifyMachineAccessToken(
  token: string,
  env: MachineEnv,
  now = Math.floor(Date.now() / 1000),
): Promise<MachineClaims> {
  const keys = parsePublicJwks(env.MACHINE_JWT_PUBLIC_JWKS);
  const issuer = parseIssuer(env.MACHINE_ISSUER);
  const claims = await verifyGatewayAccessToken(
    token,
    async (kid) => {
      const jwk = keys.find((candidate) => candidate.kid === kid);
      if (!jwk) return null;
      const cacheKey = `public:${jwk.kid}:${jwk.x}:${jwk.y}`;
      let key = importedKeyCache.get(cacheKey);
      if (!key) {
        key = importJWK(jwk as JWK, "ES256") as Promise<CryptoKey>;
        importedKeyCache.set(cacheKey, key);
      }
      return key;
    },
    { issuer, now, clockToleranceSeconds: 5 },
  );
  const { payload } = await import("jose").then(({ decodeJwt }) => ({ payload: decodeJwt(token) }));
  if (typeof payload.iss !== "string" || typeof payload.aud !== "string" && !Array.isArray(payload.aud) || typeof payload.exp !== "number") {
    throw new Error("Machine token claims are invalid");
  }
  return { ...claims, iss: payload.iss, aud: payload.aud, exp: payload.exp };
}

export function parseCookies(header: string | null): Record<string, string> {
  const result: Record<string, string> = {};
  for (const piece of (header ?? "").split(";")) {
    const separator = piece.indexOf("=");
    if (separator < 1) continue;
    const key = piece.slice(0, separator).trim();
    const value = piece.slice(separator + 1).trim();
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      continue;
    }
  }
  return result;
}

export function setSessionCookie(token: string, maxAgeSeconds: number): string {
  return `__Host-identity_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

export function clearSessionCookie(): string {
  return "__Host-identity_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}
