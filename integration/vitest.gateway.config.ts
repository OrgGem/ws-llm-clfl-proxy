import { generateKeyPairSync, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const integrationDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(integrationDir, "..");
const issuer = "https://ws-llm-identity-staging.rpa-money.workers.dev";
const kid = "integration-signing-key";

// Generate per-run keys in memory so fixtures never contain reusable secrets.
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const privateJwk = { ...privateKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
const publicJwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
const envelopeKey = randomBytes(32).toString("base64url");
const bindings = {
  MACHINE_ISSUER: issuer,
  MACHINE_JWT_PRIVATE_JWK: JSON.stringify(privateJwk),
  MACHINE_JWT_PUBLIC_JWKS: JSON.stringify({ keys: [publicJwk] }),
  ENVELOPE_KEYS: JSON.stringify({ current: "integration-envelope-key", keys: { "integration-envelope-key": envelopeKey } }),
  OIDC_PROVIDERS: "[]",
  BOOTSTRAP_ADMIN_EMAILS: "",
};

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: path.resolve(rootDir, "apps/gateway/wrangler.jsonc"),
        environment: "staging",
      },
      miniflare: {
        bindings,
        d1Databases: { DB: "ws-proxy-gateway-integration" },
        workers: [
          {
            name: "ws-llm-identity-staging",
            scriptPath: path.resolve(rootDir, ".wrangler/build/identity/worker.js"),
            modules: true,
            rootPath: rootDir,
            compatibilityDate: "2026-10-17",
            compatibilityFlags: ["nodejs_compat"],
            bindings,
            d1Databases: { DB: "ws-proxy-gateway-integration" },
          },
        ],
      },
    }),
  ],
  test: {
    include: ["integration/gateway.test.ts"],
    testTimeout: 15_000,
    hookTimeout: 15_000,
  },
});
