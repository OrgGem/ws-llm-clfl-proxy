import { MAX_JSON_DEPTH, MAX_JSON_NODES, type ProviderRequestApi } from "@ws-proxy/shared";

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

function inputContainsRemoteItemReference(value: unknown): boolean {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const visited = new Set<object>();
  let count = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) continue;
    count += 1;
    // Protocol validation imposes these bounds on JSON payloads. Treat a direct
    // call outside those bounds as invalid too, rather than scanning forever.
    if (count > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH) return true;

    const item = current.value;
    if (item === null || typeof item !== "object") continue;
    if (visited.has(item)) return true;
    visited.add(item);

    if (!Array.isArray(item) && (item as Record<string, unknown>).type === "item_reference") return true;
    for (const child of Array.isArray(item) ? item : Object.values(item)) {
      pending.push({ value: child, depth: current.depth + 1 });
    }
  }

  return false;
}

/** Force Responses into stateless mode and reject server-managed remote handles. */
export function providerPayloadForApi(
  api: ProviderRequestApi,
  payload: Record<string, unknown>,
): Record<string, unknown> {
  if (api !== "chat.completions" && api !== "responses" && api !== "completions") {
    throw new ProviderCallError("invalid_request", "The requested provider API is invalid.", false);
  }
  if (api !== "responses") return payload;

  const invalidBoolean = (name: "store" | "background") => payload[name] !== undefined && typeof payload[name] !== "boolean";
  if (payload.store === true || payload.background === true || invalidBoolean("store") || invalidBoolean("background") ||
      (payload.previous_response_id !== undefined && payload.previous_response_id !== null) ||
      (payload.conversation !== undefined && payload.conversation !== null) || inputContainsRemoteItemReference(payload.input)) {
    throw new ProviderCallError(
      "invalid_request",
      "Responses requests must be stateless and cannot use background generation.",
      false,
    );
  }
  return { ...payload, store: false };
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
  api: ProviderRequestApi = "chat.completions",
  providerSessionId?: string,
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
  if (api !== "chat.completions" && api !== "responses" && api !== "completions") {
    throw new TypeError("Requested provider API is invalid");
  }
  if (!isProviderProtocol(protocol) || (protocol === "anthropic" && api !== "chat.completions")) {
    throw new TypeError("Requested API is not supported by this provider");
  }
  const expectedSuffix = protocol === "anthropic"
    ? "/messages"
    : api === "chat.completions"
      ? "/chat/completions"
      : `/${api}`;
  if (url.protocol !== "https:" || url.username || url.password ||
      url.search || url.hash || !url.pathname.endsWith(expectedSuffix)) {
    throw new TypeError("Authorized provider endpoint is invalid");
  }

  const headers = new Headers({
    "content-type": "application/json",
    accept: "text/event-stream",
  });
  if (url.origin === "https://opencode.ai" && url.pathname.startsWith("/inference/go/")) {
    if (!providerSessionId || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(providerSessionId)) {
      throw new TypeError("A valid provider session ID is required for OpenCode Go");
    }
    headers.set("user-agent", "ws-llm-cloudflare-proxy/0.1.0");
    headers.set("x-opencode-session", providerSessionId);
    headers.set("accept", "application/json");
  }
  if (protocol === "openai") {
    headers.set("authorization", `Bearer ${apiKey}`);
  } else {
    headers.set("x-api-key", apiKey);
    headers.set("anthropic-version", "2023-06-01");
  }

  const apiPayload = providerPayloadForApi(api, payload);
  const body = JSON.stringify({ ...apiPayload, model: upstreamModel, stream: true });
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
