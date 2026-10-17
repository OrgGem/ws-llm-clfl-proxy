import { describe, expect, it } from "vitest";
import {
  CredentialEnvelopeSchema,
  MAX_CREDENTIAL_PLAINTEXT_BYTES,
  decryptCredentialEnvelope,
  encryptCredentialEnvelope,
} from "./envelope.js";

const metadata = {
  credentialId: "cred_01JABC",
  userId: "usr_01JABC",
  projectId: "prj_01JABC",
  provider: "openai",
  kid: "env-2026-10",
  exp: 2_000_000_000,
};

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

describe("credential envelope", () => {
  it("round trips transient bytes with authenticated metadata", async () => {
    const key = randomBytes(32);
    const plaintext = randomBytes(96);
    const envelope = await encryptCredentialEnvelope(plaintext, metadata, key);
    const result = await decryptCredentialEnvelope(envelope, key, { now: metadata.exp - 1 });

    expect(result.metadata).toEqual({ v: 1, alg: "A256GCM", ...metadata });
    expect(result.plaintext).toEqual(plaintext);
    expect(envelope.nonce).toHaveLength(16);
  });

  it("uses a new nonce for every encryption", async () => {
    const key = randomBytes(32);
    const plaintext = randomBytes(32);
    const first = await encryptCredentialEnvelope(plaintext, metadata, key);
    const second = await encryptCredentialEnvelope(plaintext, metadata, key);

    expect(first.nonce).not.toBe(second.nonce);
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it("rejects tampered ciphertext and cross-tenant metadata", async () => {
    const key = randomBytes(32);
    const envelope = await encryptCredentialEnvelope(randomBytes(48), metadata, key);
    const ciphertext = `${envelope.ciphertext[0] === "A" ? "B" : "A"}${envelope.ciphertext.slice(1)}`;
    await expect(
      decryptCredentialEnvelope({ ...envelope, ciphertext }, key, { now: metadata.exp - 1 }),
    ).rejects.toThrow();
    await expect(
      decryptCredentialEnvelope({ ...envelope, userId: "usr_other" }, key, { now: metadata.exp - 1 }),
    ).rejects.toThrow();
  });

  it("rejects expired envelopes and invalid key sizes", async () => {
    const key = randomBytes(32);
    const expired = await encryptCredentialEnvelope(randomBytes(24), { ...metadata, exp: 1_000 }, key);

    await expect(decryptCredentialEnvelope(expired, key, { now: 1_000 })).rejects.toThrow(/expired/i);
    await expect(encryptCredentialEnvelope(randomBytes(24), metadata, randomBytes(31))).rejects.toThrow(
      /32 bytes/,
    );
  });

  it("rejects newline-delimited ownership IDs and oversized provider key bytes", async () => {
    const key = randomBytes(32);
    expect(CredentialEnvelopeSchema.safeParse({
      v: 1,
      alg: "A256GCM",
      ...metadata,
      userId: "usr_one\nprojectId=prj_other",
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
    }).success).toBe(false);

    await expect(
      encryptCredentialEnvelope(randomBytes(MAX_CREDENTIAL_PLAINTEXT_BYTES + 1), metadata, key),
    ).rejects.toThrow(/exceed/);
  });
});
