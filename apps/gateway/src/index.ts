import { GatewaySession, validateHandshakeToken } from "./session.js";
import type { GatewayDependencies, IdentityInternalBinding } from "./types.js";

const WS_SUBPROTOCOL = "llm-proxy.v1";
const MAX_ACCESS_TOKEN_CHARS = 16_384;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function jsonError(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: { code } }), { status, headers: JSON_HEADERS });
}

function bearerToken(request: Request): string | undefined {
  const value = request.headers.get("authorization");
  if (!value || value.length > MAX_ACCESS_TOKEN_CHARS + 7) return undefined;
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/i.exec(value);
  if (!match?.[1] || match[1].length > MAX_ACCESS_TOKEN_CHARS) return undefined;
  return match[1];
}

function offersGatewayProtocol(request: Request): boolean {
  const protocols = request.headers.get("sec-websocket-protocol");
  return protocols?.split(",").some((protocol) => protocol.trim() === WS_SUBPROTOCOL) ?? false;
}

export function issuerConfigurationIsValid(
  env: { MACHINE_ISSUER: string; GATEWAY_ENVIRONMENT: string; ENVELOPE_KEYS?: string },
): boolean {
  if (!env.MACHINE_ISSUER || !env.ENVELOPE_KEYS || env.MACHINE_ISSUER.includes("example.invalid")) return false;
  let issuer: URL;
  try {
    issuer = new URL(env.MACHINE_ISSUER);
  } catch {
    return false;
  }
  if (issuer.username || issuer.password || issuer.search || issuer.hash) return false;
  const isLoopback = issuer.hostname === "localhost" || issuer.hostname === "127.0.0.1" || issuer.hostname === "[::1]";
  if (env.GATEWAY_ENVIRONMENT === "local") {
    return issuer.protocol === "http:" && isLoopback;
  }
  return env.GATEWAY_ENVIRONMENT === "staging" && issuer.protocol === "https:" && !isLoopback;
}

async function handleGatewayRequest(request: Request, env: Env, context: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== "/v1/socket") return jsonError(404, "not_found");
  if (url.search !== "") return jsonError(400, "query_not_allowed");
  if (request.method !== "GET") return jsonError(405, "method_not_allowed");
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return new Response("WebSocket upgrade required", { status: 426, headers: { "upgrade": "websocket" } });
  }
  if (!offersGatewayProtocol(request)) return jsonError(400, "subprotocol_required");
  if (!issuerConfigurationIsValid(env)) {
    return jsonError(503, "gateway_not_configured");
  }

  const accessToken = bearerToken(request);
  if (!accessToken) return jsonError(401, "unauthorized");
  const dependencies: GatewayDependencies = {
    identity: env.IDENTITY as IdentityInternalBinding,
    machineIssuer: env.MACHINE_ISSUER,
    envelopeKeys: env.ENVELOPE_KEYS ?? "",
    fetcher: (input, init) => globalThis.fetch(input, init),
    ...((env as Env & { GATEWAY_PUBLIC_ORIGIN?: string }).GATEWAY_PUBLIC_ORIGIN
      ? { gatewayOrigin: (env as Env & { GATEWAY_PUBLIC_ORIGIN?: string }).GATEWAY_PUBLIC_ORIGIN }
      : {}),
  };
  const authorization = await validateHandshakeToken(accessToken, dependencies);
  if (!authorization) return jsonError(401, "unauthorized");

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  const session = new GatewaySession(server, accessToken, authorization.claims, dependencies, context, authorization.limits);
  session.attach();

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { "sec-websocket-protocol": WS_SUBPROTOCOL },
  });
}

export default {
  fetch(request: Request, env: Env, context: ExecutionContext): Promise<Response> {
    return handleGatewayRequest(request, env, context);
  },
} satisfies ExportedHandler<Env>;
