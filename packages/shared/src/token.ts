import { jwtVerify, SignJWT } from "jose";
import type { JWTVerifyGetKey, KeyInput } from "jose";
import { z } from "zod";

export const GATEWAY_TOKEN_AUDIENCE = "llm-socket-gateway";
export const GATEWAY_TOKEN_TTL_SECONDS = 300;

const IdentifierSchema = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/);
const UnixSecondsSchema = z.number().int().nonnegative().safe();

export const GatewayAccessTokenClaimsSchema = z
  .object({
    sub: IdentifierSchema,
    sid: IdentifierSchema,
    project_id: IdentifierSchema,
    client_id: IdentifierSchema,
    jti: IdentifierSchema,
    iat: UnixSecondsSchema,
    nbf: UnixSecondsSchema,
    exp: UnixSecondsSchema,
  })
  .passthrough();

export type GatewayAccessTokenClaims = z.infer<typeof GatewayAccessTokenClaimsSchema>;
export type GatewaySigningKey = KeyInput;
export type GatewayVerificationKey = KeyInput;

export interface GatewayAccessTokenVerificationOptions {
  issuer: string;
  audience?: string;
  /** Maximum accepted clock skew in seconds. Defaults to zero. */
  clockToleranceSeconds?: number;
  /** Current Unix time in seconds, useful for deterministic verification. */
  now?: number;
}

export type GatewayVerificationKeyResolver = (
  kid: string,
) => GatewayVerificationKey | null | undefined | Promise<GatewayVerificationKey | null | undefined>;

/**
 * Verifies ES256 machine tokens, including required timing claims and a
 * protected `kid`. The key resolver must return a trusted key for that `kid`.
 */
export async function verifyGatewayAccessToken(
  token: string,
  resolveKey: GatewayVerificationKeyResolver,
  options: GatewayAccessTokenVerificationOptions,
): Promise<GatewayAccessTokenClaims> {
  if (typeof token !== "string" || token.length === 0 || token.length > 16_384) {
    throw new TypeError("Gateway access token has an invalid length");
  }
  if (!options.issuer) {
    throw new TypeError("A gateway token issuer is required");
  }
  const clockToleranceSeconds = options.clockToleranceSeconds ?? 0;
  if (!Number.isSafeInteger(clockToleranceSeconds) || clockToleranceSeconds < 0 || clockToleranceSeconds > 60) {
    throw new TypeError("Gateway token clock tolerance must be between 0 and 60 seconds");
  }

  const getKey: JWTVerifyGetKey = async (protectedHeader) => {
    if (typeof protectedHeader.kid !== "string" || protectedHeader.kid.length < 1) {
      throw new TypeError("Gateway access token is missing its key id");
    }
    const key = await resolveKey(protectedHeader.kid);
    if (!key) {
      throw new TypeError("Gateway access token uses an unknown signing key");
    }
    return key;
  };

  const verifyOptions: Parameters<typeof jwtVerify>[2] = {
    algorithms: ["ES256"],
    issuer: options.issuer,
    audience: options.audience ?? GATEWAY_TOKEN_AUDIENCE,
    clockTolerance: clockToleranceSeconds,
  };
  if (options.now !== undefined) {
    if (!Number.isSafeInteger(options.now) || options.now < 0) {
      throw new TypeError("Current time must be a nonnegative Unix timestamp in seconds");
    }
    verifyOptions.currentDate = new Date(options.now * 1000);
  }

  const { payload, protectedHeader } = await jwtVerify(token, getKey, verifyOptions);
  if (typeof protectedHeader.kid !== "string" || protectedHeader.kid.length > 64) {
    throw new TypeError("Gateway access token has an invalid key id");
  }

  const claims = GatewayAccessTokenClaimsSchema.parse(payload);
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (claims.exp <= now) {
    throw new Error("Gateway access token has expired");
  }
  if (claims.exp <= claims.iat || claims.exp - claims.iat > GATEWAY_TOKEN_TTL_SECONDS) {
    throw new Error("Gateway access token has an invalid lifetime");
  }
  if (claims.iat > now + clockToleranceSeconds || claims.nbf < claims.iat || claims.nbf > claims.exp) {
    throw new Error("Gateway access token has inconsistent timing claims");
  }

  return claims;
}

export interface IssueGatewayAccessTokenClaims {
  userId: string;
  sessionId: string;
  projectId: string;
  clientId: string;
  tokenId: string;
}

export interface IssueGatewayAccessTokenOptions {
  issuer: string;
  kid: string;
  audience?: string;
  /** Current Unix time in seconds. Defaults to the current wall clock. */
  now?: number;
  ttlSeconds?: number;
}

/** Creates a short-lived ES256 gateway token with the agreed claim names. */
export async function issueGatewayAccessToken(
  claims: IssueGatewayAccessTokenClaims,
  signingKey: GatewaySigningKey,
  options: IssueGatewayAccessTokenOptions,
): Promise<string> {
  const { issuer, kid } = options;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const ttl = options.ttlSeconds ?? GATEWAY_TOKEN_TTL_SECONDS;
  const parsedClaims = GatewayAccessTokenClaimsSchema.pick({
    sub: true,
    sid: true,
    project_id: true,
    client_id: true,
    jti: true,
  }).parse({
    sub: claims.userId,
    sid: claims.sessionId,
    project_id: claims.projectId,
    client_id: claims.clientId,
    jti: claims.tokenId,
  });

  if (!issuer) {
    throw new TypeError("A gateway token issuer is required");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(kid)) {
    throw new TypeError("Gateway signing key id is invalid");
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError("Current time must be a nonnegative Unix timestamp in seconds");
  }
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > GATEWAY_TOKEN_TTL_SECONDS) {
    throw new TypeError(`Gateway token TTL must be between 1 and ${GATEWAY_TOKEN_TTL_SECONDS} seconds`);
  }

  return new SignJWT({
    sid: parsedClaims.sid,
    project_id: parsedClaims.project_id,
    client_id: parsedClaims.client_id,
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(options.audience ?? GATEWAY_TOKEN_AUDIENCE)
    .setSubject(parsedClaims.sub)
    .setJti(parsedClaims.jti)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + ttl)
    .sign(signingKey);
}
