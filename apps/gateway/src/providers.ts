export type ProviderProtocol = "openai" | "anthropic";
export type ProviderId = ProviderProtocol;

export interface BuiltinProvider {
  protocol: ProviderProtocol;
  baseUrl: string;
  endpoint: string;
}

export const BUILTIN_PROVIDERS: Readonly<Record<ProviderId, BuiltinProvider>> = Object.freeze({
  openai: {
    protocol: "openai",
    baseUrl: "https://api.openai.com/v1/",
    endpoint: "https://api.openai.com/v1/chat/completions",
  },
  anthropic: {
    protocol: "anthropic",
    baseUrl: "https://api.anthropic.com/v1/",
    endpoint: "https://api.anthropic.com/v1/messages",
  },
});

export const PROVIDER_ENDPOINTS: Readonly<Record<ProviderId, string>> = Object.freeze({
  openai: BUILTIN_PROVIDERS.openai.endpoint,
  anthropic: BUILTIN_PROVIDERS.anthropic.endpoint,
});

const SAFE_MODEL_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const MAX_PROVIDER_KEY_BYTES = 8_192;
const encoder = new TextEncoder();

export class ProviderCallError extends Error {
  constructor(
    readonly code: "invalid_request" | "upstream_error" | "upstream_rate_limited" | "upstream_timeout" | "response_too_large",
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "ProviderCallError";
  }
}

export function isProviderId(value: string): value is ProviderId {
  return value === "openai" || value === "anthropic";
}

export function isProviderProtocol(value: unknown): value is ProviderProtocol {
  return value === "openai" || value === "anthropic";
}

export function validateUpstreamModel(model: string): boolean {
  return SAFE_MODEL_ID.test(model);
}

export function providerKeyFromBytes(protocol: ProviderProtocol, plaintext: Uint8Array): string {
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_PROVIDER_KEY_BYTES) {
    throw new TypeError("Provider credential has an invalid size");
  }

  const key = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  if (key.trim() !== key || /[\u0000-\u001f\u007f]/.test(key)) {
    throw new TypeError("Provider credential has invalid characters");
  }
  if (!isProviderProtocol(protocol)) {
    throw new TypeError("Provider protocol is not supported");
  }
  return key;
}

export interface ProviderRequest {
  url: string;
  init: RequestInit;
}

/**
 * Build a fixed-method provider request against an already validated endpoint.
 * Endpoint selection and custom-host validation happen in the Gateway session,
 * using Identity's authorized provider registry result.
 */
export function buildProviderRequest(
  protocol: ProviderProtocol,
  endpoint: string,
  apiKey: string,
  upstreamModel: string,
  payload: Record<string, unknown>,
  signal: AbortSignal,
): ProviderRequest {
  if (!validateUpstreamModel(upstreamModel)) {
    throw new TypeError("Authorized upstream model is invalid");
  }

  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new TypeError("Authorized provider endpoint is invalid");
  }
  const expectedSuffix = protocol === "openai" ? "/chat/completions" : "/messages";
  if (!isProviderProtocol(protocol) || url.protocol !== "https:" || url.username || url.password ||
      url.search || url.hash || !url.pathname.endsWith(expectedSuffix)) {
    throw new TypeError("Authorized provider endpoint is invalid");
  }

  const headers = new Headers({
    "content-type": "application/json",
    accept: "text/event-stream",
  });
  if (protocol === "openai") {
    headers.set("authorization", `Bearer ${apiKey}`);
  } else {
    headers.set("x-api-key", apiKey);
    headers.set("anthropic-version", "2023-06-01");
  }

  const body = JSON.stringify({ ...payload, model: upstreamModel, stream: true });
  if (encoder.encode(body).byteLength > 1_048_576) {
    throw new ProviderCallError("invalid_request", "The provider request exceeds the Gateway payload limit.", false);
  }

  return {
    url: url.toString(),
    init: {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal,
    },
  };
}
