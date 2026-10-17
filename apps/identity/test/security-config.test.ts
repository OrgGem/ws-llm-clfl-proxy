import { describe, expect, it } from "vitest";
import { verifyMachineAccessToken } from "../src/security.js";

describe("security configuration validation", () => {
  it("allows only HTTPS issuers or HTTP loopback, never FTP loopback", async () => {
    const invalidIssuer = {
      MACHINE_ISSUER: "ftp://localhost:8787",
      MACHINE_JWT_PUBLIC_JWKS: JSON.stringify({ keys: [] }),
      MACHINE_JWT_PRIVATE_JWK: "{}",
    } as unknown as Pick<Env, "MACHINE_ISSUER" | "MACHINE_JWT_PRIVATE_JWK" | "MACHINE_JWT_PUBLIC_JWKS">;
    await expect(verifyMachineAccessToken("not-a-jwt", invalidIssuer)).rejects.toThrow(/MACHINE_ISSUER must use HTTPS/i);

    const loopbackIssuer = {
      ...invalidIssuer,
      MACHINE_ISSUER: "http://localhost:8787",
    } as unknown as Pick<Env, "MACHINE_ISSUER" | "MACHINE_JWT_PRIVATE_JWK" | "MACHINE_JWT_PUBLIC_JWKS">;
    await expect(verifyMachineAccessToken("not-a-jwt", loopbackIssuer)).rejects.not.toThrow(/MACHINE_ISSUER must use HTTPS/i);
  });
});
