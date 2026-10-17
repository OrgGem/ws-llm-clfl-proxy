import { isIP } from "node:net";
import { HttpsProxyAgent } from "https-proxy-agent";
import { getProxyForUrl } from "proxy-from-env";
import { ProxyAgent, type Dispatcher } from "undici";

const fetchAgents = new Map<string, ProxyAgent>();

/** Resolve environment proxy variables without exposing proxy URLs in thrown errors. */
export function resolveEnvironmentProxyUrl(target: string | URL): string | undefined {
  const targetUrl = target instanceof URL ? target : safeUrl(target);
  if (isLoopbackHost(targetUrl.hostname)) return undefined;

  const proxyValue = getProxyForUrl(targetUrl.toString());
  if (!proxyValue) return undefined;

  let proxyUrl: URL;
  try {
    proxyUrl = new URL(proxyValue);
  } catch {
    throw new Error("Configured proxy URL is invalid");
  }
  if (proxyUrl.protocol !== "http:" && proxyUrl.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS environment proxies are supported");
  }
  return proxyUrl.toString();
}

/** Create a ws-compatible HTTP CONNECT agent when proxy environment applies. */
export function createGatewayProxyAgent(gatewayUrl: string): HttpsProxyAgent<string> | undefined {
  const target = safeUrl(gatewayUrl);
  if (target.protocol === "wss:") target.protocol = "https:";
  else if (target.protocol === "ws:") target.protocol = "http:";
  else throw new Error("Gateway URL must use ws or wss");

  const proxyUrl = resolveEnvironmentProxyUrl(target);
  if (!proxyUrl) return undefined;
  try {
    return new HttpsProxyAgent(proxyUrl);
  } catch {
    throw new Error("Could not configure the Gateway proxy agent");
  }
}

/** Return a cached Undici dispatcher for the applicable environment proxy. */
export function getEnvironmentProxyDispatcher(target: string | URL): Dispatcher | undefined {
  const proxyUrl = resolveEnvironmentProxyUrl(target);
  if (!proxyUrl) return undefined;
  const existing = fetchAgents.get(proxyUrl);
  if (existing) return existing;
  try {
    const dispatcher = new ProxyAgent(proxyUrl);
    fetchAgents.set(proxyUrl, dispatcher);
    return dispatcher;
  } catch {
    throw new Error("Could not configure the Identity proxy dispatcher");
  }
}

/** Native fetch is used directly when no proxy applies, including NO_PROXY hosts. */
export function fetchWithEnvironmentProxy(input: string | URL, init?: RequestInit): Promise<Response> {
  const dispatcher = getEnvironmentProxyDispatcher(input);
  if (!dispatcher) return fetch(input, init);
  return fetch(input, { ...init, dispatcher } as RequestInit & { dispatcher: Dispatcher });
}

function safeUrl(value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new Error("Proxy target URL is invalid");
  }
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  return isIP(host) === 4 && Number(host.split(".", 1)[0]) === 127;
}
