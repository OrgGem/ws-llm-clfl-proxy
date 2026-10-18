import { assertPublicEndpointResolution, normalizeBaseUrl } from "@ws-proxy/shared";

export type ProviderProtocol = "openai" | "anthropic";

const BUILTIN_PROVIDERS: Readonly<Record<string, { protocol: ProviderProtocol; baseUrl: string }>> = Object.freeze({
  openai: { protocol: "openai", baseUrl: "https://api.openai.com/v1/" },
  anthropic: { protocol: "anthropic", baseUrl: "https://api.anthropic.com/v1/" },
});
const CUSTOM_PROVIDER_ID = /^[a-z][a-z0-9_-]{0,31}$/;

export function isCanonicalBuiltinProvider(id: string, protocol: string, baseUrl: string, custom: number): boolean {
  if (custom !== 0) return false;
  const builtin = BUILTIN_PROVIDERS[id];
  return Boolean(builtin && builtin.protocol === protocol && builtin.baseUrl === baseUrl);
}

export function isCustomProviderId(id: string, custom: number): boolean {
  return custom === 1 && CUSTOM_PROVIDER_ID.test(id) && id !== "openai" && id !== "anthropic";
}

export function normalizeProviderBaseUrl(env: Env, input: string): string {
  return normalizeBaseUrl(input, { forbiddenOrigins: providerRegistryForbiddenOrigins(env) });
}

export async function assertProviderBaseUrlPublic(baseUrl: string): Promise<void> {
  await assertPublicEndpointResolution(baseUrl);
}

export async function normalizeAndCheckProviderBaseUrl(env: Env, input: string): Promise<string> {
  const normalized = normalizeProviderBaseUrl(env, input);
  await assertProviderBaseUrlPublic(normalized);
  return normalized;
}

export function providerRegistryForbiddenOrigins(env: Env): string[] {
  const origins = new Set<string>();
  for (const value of [env.PUBLIC_ORIGIN, env.MACHINE_ISSUER, env.GATEWAY_URL]) {
    try {
      const url = new URL(value);
      if (url.protocol === "wss:") url.protocol = "https:";
      else if (url.protocol === "ws:") url.protocol = "http:";
      origins.add(url.origin);
      if (url.protocol === "https:") {
        url.protocol = "http:";
        origins.add(url.origin);
      } else if (url.protocol === "http:") {
        url.protocol = "https:";
        origins.add(url.origin);
      }
    } catch {
      // Invalid service URLs are rejected by their own deployment configuration.
    }
  }
  return [...origins];
}
