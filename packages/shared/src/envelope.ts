import { z } from "zod";

export const MAX_CREDENTIAL_PLAINTEXT_BYTES = 8_192;
export const MAX_ENVELOPE_CIPHERTEXT_BYTES = MAX_CREDENTIAL_PLAINTEXT_BYTES + 16;
const MAX_BASE64URL_CIPHERTEXT_LENGTH = Math.ceil((MAX_ENVELOPE_CIPHERTEXT_BYTES * 4) / 3);

const IdentifierSchema = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/);
const KeyIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
const ProviderSchema = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/);
const UnixSecondsSchema = z.number().int().nonnegative().safe();

export const CredentialEnvelopeMetadataSchema = z
  .object({
    credentialId: IdentifierSchema,
    userId: IdentifierSchema,
    projectId: IdentifierSchema,
    provider: ProviderSchema,
    kid: KeyIdSchema,
    exp: UnixSecondsSchema,
  })
  .strict();

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Credential envelope contains invalid base64url data");
  }

  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new TypeError("Credential envelope contains invalid base64url data");
  }

  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) {
    throw new TypeError("Credential envelope contains non-canonical base64url data");
  }
  return bytes;
}

function isCanonicalBase64Url(value: string): boolean {
  try {
    decodeBase64Url(value);
    return true;
  } catch {
    return false;
  }
}

const CredentialEnvelopeFields = {
  v: z.literal(1),
  alg: z.literal("A256GCM"),
  credentialId: IdentifierSchema,
  userId: IdentifierSchema,
  projectId: IdentifierSchema,
  provider: ProviderSchema,
  kid: KeyIdSchema,
  exp: UnixSecondsSchema,
};

export const CredentialEnvelopeSchema = z
  .object({
    ...CredentialEnvelopeFields,
    nonce: z
      .string()
      .regex(/^[A-Za-z0-9_-]{16}$/)
      .refine(isCanonicalBase64Url),
    ciphertext: z
      .string()
      .min(22)
      .max(MAX_BASE64URL_CIPHERTEXT_LENGTH)
      .regex(/^[A-Za-z0-9_-]+$/)
      .refine(isCanonicalBase64Url),
  })
  .strict();

export type CredentialEnvelopeMetadata = z.infer<typeof CredentialEnvelopeMetadataSchema>;
export type CredentialEnvelope = z.infer<typeof CredentialEnvelopeSchema>;

export function parseCredentialEnvelope(input: unknown): CredentialEnvelope {
  return CredentialEnvelopeSchema.parse(input);
}

export interface DecryptedCredentialEnvelope {
  metadata: CredentialEnvelopeMetadata & { v: 1; alg: "A256GCM" };
  plaintext: Uint8Array;
}

export interface CredentialEnvelopeOptions {
  /** Current Unix time in seconds. Defaults to the current wall clock. */
  now?: number;
}

function metadataFromEnvelope(envelope: CredentialEnvelope): CredentialEnvelopeMetadata & {
  v: 1;
  alg: "A256GCM";
} {
  return {
    v: envelope.v,
    alg: envelope.alg,
    credentialId: envelope.credentialId,
    userId: envelope.userId,
    projectId: envelope.projectId,
    provider: envelope.provider,
    kid: envelope.kid,
    exp: envelope.exp,
  };
}

function additionalAuthenticatedData(metadata: CredentialEnvelopeMetadata): Uint8Array<ArrayBuffer> {
  const value = [
    "v1",
    metadata.credentialId,
    metadata.userId,
    metadata.projectId,
    metadata.provider,
    metadata.kid,
    String(metadata.exp),
  ].join("\n");
  return new TextEncoder().encode(value);
}

async function resolveAes256Key(
  key: Uint8Array | CryptoKey,
  usage: KeyUsage,
): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    if (key.byteLength !== 32) {
      throw new TypeError("AES-256-GCM keys must be exactly 32 bytes");
    }
    return crypto.subtle.importKey("raw", Uint8Array.from(key), { name: "AES-GCM" }, false, [usage]);
  }

  if (key.algorithm.name !== "AES-GCM" || !("length" in key.algorithm) || key.algorithm.length !== 256) {
    throw new TypeError("Credential envelope key must be an AES-256-GCM key");
  }
  if (!key.usages.includes(usage)) {
    throw new TypeError(`Credential envelope key does not allow ${usage}`);
  }
  return key;
}

/**
 * Encrypts provider credential bytes into the v1 JSON envelope. Callers must
 * keep the raw key in Worker Secrets and keep `plaintext` transient.
 */
export async function encryptCredentialEnvelope(
  plaintext: Uint8Array,
  metadataInput: CredentialEnvelopeMetadata,
  key: Uint8Array | CryptoKey,
): Promise<CredentialEnvelope> {
  const metadata = CredentialEnvelopeMetadataSchema.parse(metadataInput);
  if (!(plaintext instanceof Uint8Array)) {
    throw new TypeError("Credential plaintext must be bytes");
  }
  if (plaintext.byteLength > MAX_CREDENTIAL_PLAINTEXT_BYTES) {
    throw new TypeError(`Credential plaintext must not exceed ${MAX_CREDENTIAL_PLAINTEXT_BYTES} bytes`);
  }

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await resolveAes256Key(key, "encrypt");
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: additionalAuthenticatedData(metadata),
      tagLength: 128,
    },
    aesKey,
    Uint8Array.from(plaintext),
  );

  return CredentialEnvelopeSchema.parse({
    v: 1,
    alg: "A256GCM",
    ...metadata,
    nonce: encodeBase64Url(nonce),
    ciphertext: encodeBase64Url(new Uint8Array(encrypted)),
  });
}

/** Validates ownership metadata by authentication when decrypting the envelope. */
export async function decryptCredentialEnvelope(
  envelopeInput: unknown,
  key: Uint8Array | CryptoKey,
  options: CredentialEnvelopeOptions = {},
): Promise<DecryptedCredentialEnvelope> {
  const envelope = parseCredentialEnvelope(envelopeInput);
  const nonce = decodeBase64Url(envelope.nonce);
  const ciphertext = decodeBase64Url(envelope.ciphertext);
  if (nonce.byteLength !== 12) {
    throw new TypeError("Credential envelope nonce must be 12 bytes");
  }
  if (ciphertext.byteLength < 16 || ciphertext.byteLength > MAX_ENVELOPE_CIPHERTEXT_BYTES) {
    throw new TypeError("Credential envelope ciphertext has an invalid length");
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError("Current time must be a nonnegative Unix timestamp in seconds");
  }
  if (envelope.exp <= now) {
    throw new Error("Credential envelope has expired");
  }

  const aesKey = await resolveAes256Key(key, "decrypt");
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: additionalAuthenticatedData(envelope),
      tagLength: 128,
    },
    aesKey,
    ciphertext,
  );

  return { metadata: metadataFromEnvelope(envelope), plaintext: new Uint8Array(plaintext) };
}
