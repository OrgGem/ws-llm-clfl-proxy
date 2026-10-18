import { generateKeyPairSync, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const integrationDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(integrationDir, "..");
const issuer = "https://ws-llm-identity-staging.rpa-money.workers.dev";
const kid = "integration-signing-key";
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const privateJwk = { ...privateKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
const publicJwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
const oidcProviders = JSON.stringify([
  {
    id: "provider-a",
    label: "Provider A",
    issuer: "https://oidc-a.integration.test/tenant",
    clientId: "integration-client-a",
    clientSecret: "integration-secret-a",
    redirectUri: `${issuer}/auth/oidc/callback`,
  },
  {
    id: "provider-b",
    label: "Provider B",
    issuer: "https://oidc-b.integration.test/tenant",
    clientId: "integration-client-b",
    clientSecret: "integration-secret-b",
    redirectUri: `${issuer}/auth/oidc/callback`,
  },
]);
const bindings = {
  MACHINE_ISSUER: issuer,
  PUBLIC_ORIGIN: issuer,
  MACHINE_JWT_PRIVATE_JWK: JSON.stringify(privateJwk),
  MACHINE_JWT_PUBLIC_JWKS: JSON.stringify({ keys: [publicJwk] }),
  ENVELOPE_KEYS: JSON.stringify({ current: "integration-envelope-key", keys: { "integration-envelope-key": randomBytes(32).toString("base64url") } }),
  OIDC_PROVIDERS: oidcProviders,
  BOOTSTRAP_ADMIN_EMAILS: "",
};

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: path.resolve(rootDir, "apps/identity/wrangler.jsonc"),
        environment: "staging",
      },
      miniflare: {
        bindings,
        d1Databases: { DB: "ws-proxy-identity-integration" },
      },
    }),
  ],
  test: {
    include: ["integration/identity*.test.ts"],
    testTimeout: 15_000,
    hookTimeout: 15_000,
  },
});
