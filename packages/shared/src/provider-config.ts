import ipaddr from "ipaddr.js";

export type ProviderProtocol = "openai" | "anthropic";

export type ProviderEndpointSecurityErrorCode =
  | "invalid_base_url"
  | "forbidden_provider_host"
  | "forbidden_service_origin"
  | "unsafe_provider_path"
  | "base_url_is_endpoint"
  | "unsupported_provider_protocol"
  | "provider_dns_validation_failed"
  | "provider_dns_non_public_address"
  | "provider_dns_no_public_address";

/** Fixed diagnostic stages safe to return to an operator without exposing a URL or resolver detail. */
export type ProviderEndpointFailureStage =
  | "normalize"
  | "fetch"
  | "http"
  | "json"
  | "dns_status"
  | "address";

export interface ProviderEndpointSecurityDiagnostic {
  /** Included only for bounded HTTP status codes (100–599). */
  httpStatus?: number;
  /** Included only for bounded DNS response codes (0–15). */
  dnsStatus?: number;
}

const ERROR_MESSAGES: Readonly<Record<ProviderEndpointSecurityErrorCode, string>> = Object.freeze({
  invalid_base_url: "Provider BaseURL must be a valid HTTPS URL without credentials, query, fragment, or a nonstandard port.",
  forbidden_provider_host: "Provider BaseURL must use a public DNS hostname outside reserved network names.",
  forbidden_service_origin: "Provider BaseURL cannot target this service.",
  unsafe_provider_path: "Provider BaseURL contains an unsupported or unsafe path.",
  base_url_is_endpoint: "Provider BaseURL must be an API root; the operation path is added automatically.",
  unsupported_provider_protocol: "Provider protocol is not supported.",
  provider_dns_validation_failed: "Provider endpoint DNS validation failed.",
  provider_dns_non_public_address: "Provider endpoint resolves to a non-public IP address.",
  provider_dns_no_public_address: "Provider endpoint has no public IPv4 or IPv6 address.",
});

export class ProviderEndpointSecurityError extends Error {
  declare readonly httpStatus?: number;
  declare readonly dnsStatus?: number;

  constructor(
    readonly code: ProviderEndpointSecurityErrorCode,
    readonly stage: ProviderEndpointFailureStage = defaultStage(code),
    diagnostic: ProviderEndpointSecurityDiagnostic = {},
  ) {
    super(ERROR_MESSAGES[code]);
    this.name = "ProviderEndpointSecurityError";
    if (isBoundedHttpStatus(diagnostic.httpStatus)) this.httpStatus = diagnostic.httpStatus;
    if (isBoundedDnsStatus(diagnostic.dnsStatus)) this.dnsStatus = diagnostic.dnsStatus;
  }
}

export interface NormalizeBaseUrlOptions {
  /** Exact service origins that must never be used as an upstream. */
  forbiddenOrigins?: readonly string[];
}

const MAX_BASE_URL_LENGTH = 2_048;
const MAX_PATH_LENGTH = 256;
const MAX_PATH_SEGMENTS = 16;
const MAX_PATH_SEGMENT_LENGTH = 64;
const MAX_DOH_RESPONSE_BYTES = 65_536;
const DNS_TIMEOUT_MS = 5_000;
const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

const RESERVED_HOST_SUFFIXES = [
  "localhost",
  "local",
  "internal",
  "home.arpa",
  "onion",
  "test",
  "invalid",
  "example",
  "lan",
  "intranet",
  "localdomain",
  "arpa",
] as const;

interface ParsedHttpsUrl {
  url: URL;
  hostname: string;
  pathname: string;
}

function defaultStage(code: ProviderEndpointSecurityErrorCode): ProviderEndpointFailureStage {
  if (code === "provider_dns_non_public_address" || code === "provider_dns_no_public_address") return "address";
  if (code === "provider_dns_validation_failed") return "json";
  return "normalize";
}

function isBoundedHttpStatus(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599;
}

function isBoundedDnsStatus(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 15;
}

function error(
  code: ProviderEndpointSecurityErrorCode,
  stage: ProviderEndpointFailureStage = defaultStage(code),
  diagnostic?: ProviderEndpointSecurityDiagnostic,
): never {
  throw new ProviderEndpointSecurityError(code, stage, diagnostic);
}

function publicDnsHostname(value: string): string {
  let hostname = value.toLowerCase();
  if (hostname.startsWith("[") && hostname.endsWith("]")) hostname = hostname.slice(1, -1);
  if (hostname.endsWith(".")) hostname = hostname.slice(0, -1);

  if (!hostname || ipaddr.isValid(hostname)) error("forbidden_provider_host");
  if (hostname.length > 253 || !hostname.includes(".")) error("forbidden_provider_host");

  const labels = hostname.split(".");
  if (labels.some((label) => label.length < 1 || label.length > 63
    || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    error("forbidden_provider_host");
  }
  const tld = labels[labels.length - 1] ?? "";
  if (!/[a-z]/.test(tld)) error("forbidden_provider_host");
  if (RESERVED_HOST_SUFFIXES.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`))) {
    error("forbidden_provider_host");
  }
  return hostname;
}

function rawPathFromInput(input: string): string {
  const scheme = input.indexOf("://");
  if (scheme < 0) error("invalid_base_url");
  const authorityStart = scheme + 3;
  const slash = input.indexOf("/", authorityStart);
  return slash < 0 ? "" : input.slice(slash);
}

function safePath(pathname: string): string {
  if (pathname.length > MAX_PATH_LENGTH || !pathname.startsWith("/") || pathname.includes("%") || pathname.includes("\\") || pathname.includes("//")) {
    error("unsafe_provider_path");
  }
  const segments = pathname.split("/").slice(1);
  if (segments.length > MAX_PATH_SEGMENTS) error("unsafe_provider_path");
  for (const segment of segments) {
    if (!segment) continue; // One final slash is normalized below.
    if (segment === "." || segment === ".." || segment.length > MAX_PATH_SEGMENT_LENGTH || !/^[A-Za-z0-9._~-]+$/.test(segment)) {
      error("unsafe_provider_path");
    }
  }
  return pathname;
}

function parseHttpsUrl(input: string, rejectOperationPath: boolean): ParsedHttpsUrl {
  if (typeof input !== "string" || input.length < 1 || input.length > MAX_BASE_URL_LENGTH || input.trim() !== input
    || input.includes("?") || input.includes("#")) {
    error("invalid_base_url");
  }
  if (input.includes("\\")) error("unsafe_provider_path");

  const rawPath = rawPathFromInput(input);
  safePath(rawPath || "/");

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    error("invalid_base_url");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.port) {
    error("invalid_base_url");
  }

  const hostname = publicDnsHostname(url.hostname);
  url.hostname = hostname;
  const pathname = safePath(url.pathname);
  const operationPath = pathname.replace(/\/+$/, "").toLowerCase();
  if (rejectOperationPath && (operationPath.endsWith("/chat/completions") || operationPath.endsWith("/messages"))) {
    error("base_url_is_endpoint");
  }
  return { url, hostname, pathname };
}

/**
 * Validate and canonicalize an administrator-configured provider API root.
 * Percent-encoding is not accepted in paths; endpoint paths are added by the
 * protocol-specific builder below.
 */
export function normalizeBaseUrl(input: string, options: NormalizeBaseUrlOptions = {}): string {
  const parsed = parseHttpsUrl(input, true);
  for (const forbiddenOrigin of options.forbiddenOrigins ?? []) {
    let service: URL;
    try {
      service = new URL(forbiddenOrigin);
    } catch {
      error("invalid_base_url");
    }
    const serviceHost = service.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    const servicePort = service.port || (service.protocol === "https:" || service.protocol === "wss:" ? "443" : service.protocol === "http:" || service.protocol === "ws:" ? "80" : "");
    if (serviceHost === parsed.hostname && servicePort === "443") error("forbidden_service_origin");
  }
  const path = parsed.pathname.endsWith("/") ? parsed.pathname : `${parsed.pathname}/`;
  return `${parsed.url.origin}${path}`;
}

/** Build only the fixed operation URL for a trusted provider protocol. */
export function buildProviderEndpoint(protocol: ProviderProtocol, baseUrl: string): string {
  if (protocol !== "openai" && protocol !== "anthropic") error("unsupported_provider_protocol");
  const normalized = normalizeBaseUrl(baseUrl);
  const operation = protocol === "openai" ? "chat/completions" : "messages";
  return new URL(operation, normalized).toString();
}

function isPublicUnicastAddress(address: string, type: 1 | 28): boolean {
  if (!ipaddr.isValid(address)) return false;
  const parsed = ipaddr.parse(address);
  if (type === 1 && parsed.kind() !== "ipv4") return false;
  if (type === 28 && parsed.kind() !== "ipv6") return false;

  if (parsed.kind() === "ipv6" && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) return false;
  // ipaddr.js gives transition and reserved IPv6 blocks distinct range names;
  // allowing only `unicast` rejects those as well as private/special IPv4.
  return parsed.range() === "unicast";
}

async function readBoundedText(response: Response): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength && Number(contentLength) > MAX_DOH_RESPONSE_BYTES) error("provider_dns_validation_failed", "json");
  if (!response.body) error("provider_dns_validation_failed", "json");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_DOH_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        error("provider_dns_validation_failed", "json");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    error("provider_dns_validation_failed", "json");
  }
}

interface DnsJsonAnswer {
  type: number;
  data: string;
}

async function resolveAddressFamily(hostname: string, type: "A" | "AAAA", fetcher: typeof fetch): Promise<DnsJsonAnswer[]> {
  const endpoint = new URL(DOH_ENDPOINT);
  endpoint.searchParams.set("name", hostname);
  endpoint.searchParams.set("type", type);

  let response: Response;
  try {
    response = await fetcher(endpoint.toString(), {
      method: "GET",
      headers: { accept: "application/dns-json" },
      // Manual redirects remain visible as a non-OK response and are rejected
      // below; never let the trusted resolver request follow a redirect.
      redirect: "manual",
      signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
    });
  } catch {
    error("provider_dns_validation_failed", "fetch");
  }
  if (!response.ok) error("provider_dns_validation_failed", "http", { httpStatus: response.status });
  let payload: unknown;
  try {
    payload = JSON.parse(await readBoundedText(response)) as unknown;
  } catch (cause) {
    if (cause instanceof ProviderEndpointSecurityError) throw cause;
    error("provider_dns_validation_failed", "json");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) error("provider_dns_validation_failed", "json");
  const document = payload as { Status?: unknown; Answer?: unknown; TC?: unknown };
  if (typeof document.Status !== "number" || !Number.isInteger(document.Status) || document.Status < 0 || document.Status > 15) {
    error("provider_dns_validation_failed", "dns_status");
  }
  if (document.Status !== 0 || document.TC === true) {
    error("provider_dns_validation_failed", "dns_status", { dnsStatus: document.Status });
  }
  if ((document.TC !== undefined && typeof document.TC !== "boolean")
    || (document.Answer !== undefined && !Array.isArray(document.Answer))) {
    error("provider_dns_validation_failed", "json");
  }
  const answers = (document.Answer ?? []) as unknown[];
  const expectedType = type === "A" ? 1 : 28;
  const parsed: DnsJsonAnswer[] = [];
  for (const answer of answers) {
    if (!answer || typeof answer !== "object" || Array.isArray(answer)) error("provider_dns_validation_failed", "json");
    const record = answer as { type?: unknown; data?: unknown };
    if (record.type !== 1 && record.type !== 28) continue;
    if (typeof record.data !== "string" || record.data.includes("%") || !ipaddr.isValid(record.data)) {
      error("provider_dns_validation_failed", "address");
    }
    const addressType = record.type as 1 | 28;
    if (!isPublicUnicastAddress(record.data, addressType)) error("provider_dns_non_public_address", "address");
    if (addressType === expectedType) parsed.push({ type: expectedType, data: record.data });
  }
  return parsed;
}

/** Resolve a trusted custom provider endpoint and reject every non-public A/AAAA answer. */
export async function assertPublicEndpointResolution(endpoint: string | URL, fetcher?: typeof fetch): Promise<void> {
  // Keep the native Worker `fetch` receiver intact. In Workers, extracting the
  // global fetch into a default parameter and invoking it later can fail its
  // native receiver check even though an injected test fetcher works.
  const request = fetcher ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
  const parsed = parseHttpsUrl(String(endpoint), false);
  const [a, aaaa] = await Promise.allSettled([
    resolveAddressFamily(parsed.hostname, "A", request),
    resolveAddressFamily(parsed.hostname, "AAAA", request),
  ]);
  for (const result of [a, aaaa]) {
    if (result.status === "rejected") {
      if (result.reason instanceof ProviderEndpointSecurityError) throw result.reason;
      error("provider_dns_validation_failed");
    }
  }
  if (a.status !== "fulfilled" || aaaa.status !== "fulfilled") error("provider_dns_validation_failed");
  const addresses = [...a.value, ...aaaa.value];
  if (addresses.length === 0) error("provider_dns_no_public_address", "address");
}
