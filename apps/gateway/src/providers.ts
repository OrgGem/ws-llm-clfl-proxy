export type ProviderId = "openai" | "anthropic";

export const PROVIDER_ENDPOINTS: Readonly<Record<ProviderId, string>> = Object.freeze({
  openai: "https://api.openai.com/v1/chat/completions",
  anthropic: "https://api.anthropic.com/v1/messages",
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

export function validateUpstreamModel(model: string): boolean {
  return SAFE_MODEL_ID.test(model);
}

export function providerKeyFromBytes(provider: ProviderId, plaintext: Uint8Array): string {
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_PROVIDER_KEY_BYTES) {
    throw new TypeError("Provider credential has an invalid size");
  }

  const key = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  if (key.trim() !== key || /[\u0000-\u001f\u007f]/.test(key)) {
    throw new TypeError("Provider credential has invalid characters");
  }
  if (provider !== "openai" && provider !== "anthropic") {
    throw new TypeError("Provider is not supported");
  }
  return key;
}

export interface ProviderRequest {
  url: string;
  init: RequestInit;
}

export function buildProviderRequest(
  provider: ProviderId,
  apiKey: string,
  upstreamModel: string,
  payload: Record<string, unknown>,
  signal: AbortSignal,
): ProviderRequest {
  if (!validateUpstreamModel(upstreamModel)) {
    throw new TypeError("Authorized upstream model is invalid");
  }

  const headers = new Headers({
    "content-type": "application/json",
    accept: "text/event-stream",
  });
  if (provider === "openai") {
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
    url: PROVIDER_ENDPOINTS[provider],
    init: {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal,
    },
  };
}
