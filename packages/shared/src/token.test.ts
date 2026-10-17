import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  GATEWAY_TOKEN_AUDIENCE,
  issueGatewayAccessToken,
  verifyGatewayAccessToken,
} from "./token.js";

const now = 1_800_000_000;
const issuer = "https://identity.example.test/machine";
const kid = "sign-2026-10";
const tokenClaims = {
  userId: "usr_01JABC",
  sessionId: "ses_01JABC",
  projectId: "prj_01JABC",
  clientId: "cli_01JABC",
  tokenId: "jti_01JABC",
};

async function signingPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

async function signedToken(
  privateKey: CryptoKey,
  overrides: {
    issuer?: string;
    audience?: string;
    iat?: number;
    nbf?: number;
    exp?: number;
    kid?: string;
    omitClaims?: boolean;
  } = {},
): Promise<string> {
  const payload = overrides.omitClaims
    ? {}
    : {
        sid: "ses_01JABC",
        project_id: "prj_01JABC",
        client_id: "cli_01JABC",
      };
  const builder = new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", kid: overrides.kid ?? kid })
    .setIssuer(overrides.issuer ?? issuer)
    .setAudience(overrides.audience ?? GATEWAY_TOKEN_AUDIENCE)
    .setSubject("usr_01JABC")
    .setJti("jti_01JABC");

  if (overrides.iat !== undefined) builder.setIssuedAt(overrides.iat);
  if (overrides.nbf !== undefined) builder.setNotBefore(overrides.nbf);
  if (overrides.exp !== undefined) builder.setExpirationTime(overrides.exp);
  return builder.sign(privateKey);
}

describe("Gateway machine JWT", () => {
  it("issues ES256 tokens with the shared claim contract and verifies them", async () => {
    const pair = await signingPair();
    const token = await issueGatewayAccessToken(tokenClaims, pair.privateKey, {
      issuer,
      kid,
      now,
    });
    const lookedUpKids: string[] = [];
    const verified = await verifyGatewayAccessToken(
      token,
      (requestedKid) => {
        lookedUpKids.push(requestedKid);
        return pair.publicKey;
      },
      { issuer, now },
    );

    expect(lookedUpKids).toEqual([kid]);
    expect(verified).toMatchObject({
      sub: tokenClaims.userId,
      sid: tokenClaims.sessionId,
      project_id: tokenClaims.projectId,
      client_id: tokenClaims.clientId,
      jti: tokenClaims.tokenId,
      iat: now,
      nbf: now,
      exp: now + 300,
    });
  });

  it("rejects a wrong issuer, audience, expired token, or unknown key", async () => {
    const pair = await signingPair();
    const wrongIssuer = await signedToken(pair.privateKey, { issuer: "https://wrong.example.test", iat: now, nbf: now, exp: now + 60 });
    const wrongAudience = await signedToken(pair.privateKey, { audience: "another-service", iat: now, nbf: now, exp: now + 60 });
    const expired = await signedToken(pair.privateKey, { iat: now - 100, nbf: now - 100, exp: now - 1 });
    const resolver = () => pair.publicKey;

    await expect(verifyGatewayAccessToken(wrongIssuer, resolver, { issuer, now })).rejects.toThrow();
    await expect(verifyGatewayAccessToken(wrongAudience, resolver, { issuer, now })).rejects.toThrow();
    await expect(
      verifyGatewayAccessToken(expired, resolver, { issuer, now, clockToleranceSeconds: 30 }),
    ).rejects.toThrow(/expired/i);
    await expect(verifyGatewayAccessToken(wrongAudience, () => undefined, { issuer, now })).rejects.toThrow(
      /unknown signing key/,
    );
  });

  it("requires timing and delegation claims and rejects future issue times", async () => {
    const pair = await signingPair();
    const missing = await signedToken(pair.privateKey, { omitClaims: true, iat: now, nbf: now, exp: now + 60 });
    const futureIat = await signedToken(pair.privateKey, { iat: now + 1, nbf: now, exp: now + 60 });
    const oversizedLifetime = await signedToken(pair.privateKey, { iat: now - 1, nbf: now - 1, exp: now + 300 });

    await expect(verifyGatewayAccessToken(missing, () => pair.publicKey, { issuer, now })).rejects.toThrow();
    await expect(verifyGatewayAccessToken(futureIat, () => pair.publicKey, { issuer, now })).rejects.toThrow();
    await expect(verifyGatewayAccessToken(oversizedLifetime, () => pair.publicKey, { issuer, now })).rejects.toThrow(
      /lifetime/,
    );
  });

  it("allows configured not-before skew but never extends token expiry", async () => {
    const pair = await signingPair();
    const withinSkew = await signedToken(pair.privateKey, { iat: now, nbf: now + 20, exp: now + 60 });
    const expiredWithinSkew = await signedToken(pair.privateKey, { iat: now - 60, nbf: now - 60, exp: now - 1 });

    await expect(
      verifyGatewayAccessToken(withinSkew, () => pair.publicKey, {
        issuer,
        now,
        clockToleranceSeconds: 30,
      }),
    ).resolves.toMatchObject({ nbf: now + 20 });
    await expect(
      verifyGatewayAccessToken(expiredWithinSkew, () => pair.publicKey, {
        issuer,
        now,
        clockToleranceSeconds: 30,
      }),
    ).rejects.toThrow(/expired/i);
  });
});
