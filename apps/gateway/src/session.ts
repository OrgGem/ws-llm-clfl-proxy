import {
  ACK_TIMEOUT_MS,
  ACK_WINDOW,
  MAX_CHUNK_BYTES,
  MAX_CONTROL_FRAME_BYTES,
  MAX_GATEWAY_FRAME_BYTES,
  MAX_IN_FLIGHT_REQUESTS,
  MIN_REQUEST_PAYLOAD_BYTES,
  MAX_REQUEST_DURATION_MS,
  MAX_REQUEST_FRAME_BYTES,
  MAX_REQUEST_IDS_PER_SOCKET,
  MAX_RESPONSE_FRAME_BYTES,
  MAX_RESPONSE_BYTES,
  assertPublicEndpointResolution,
  buildProviderEndpoint,
  normalizeBaseUrl,
  parseGatewayFrame,
  type RequestStartMessage,
  type GatewayServerFrame,
} from "@ws-proxy/shared";
import { decryptCredentialEnvelope, type CredentialEnvelope } from "@ws-proxy/shared";
import {
  buildProviderRequest,
  BUILTIN_PROVIDERS,
  isProviderId,
  isProviderProtocol,
  ProviderCallError,
  providerKeyFromBytes,
  validateUpstreamModel,
  type ProviderProtocol,
} from "./providers.js";
import type {
  AuthorizedModel,
  AuthorizedCredentialMetadata,
  AuthorizedPrincipal,
  GatewayDependencies,
  MachineClaims,
  ProjectLimits,
} from "./types.js";

const SESSION_IDLE_TIMEOUT_MS = 60_000;
const UPSTREAM_READ_IDLE_TIMEOUT_MS = 60_000;
const HANDSHAKE_AUTH_TIMEOUT_MS = 5_000;
const MAX_PENDING_PROVIDER_READ_BYTES = 2_097_152;
const MAX_OUTBOUND_FRAME_BYTES = MAX_RESPONSE_FRAME_BYTES;
const MAX_PENDING_OUTBOUND_FRAME_BYTES = 4 * 1_048_576;
const MAX_LIFETIME_OUTBOUND_FRAME_BYTES = 8 * 1_048_576;
const POLICY_DRAIN_RESERVE_BYTES = MAX_CONTROL_FRAME_BYTES;
const MAX_ACTUAL_CHUNK_BYTES = 16_384;
const MAX_SESSION_DURATION_SECONDS = 300;
const HARD_MAX_PAYLOAD_BYTES = 1_048_576;
const HARD_MAX_CONCURRENCY = MAX_IN_FLIGHT_REQUESTS;
const TOKEN_DRAIN_BEFORE_EXPIRY_MS = 30_000;
const encoder = new TextEncoder();

export interface GatewayExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

interface RequestFailureInit {
  code: "invalid_request" | "unauthorized" | "forbidden" | "credential_invalid" | "provider_disallowed" | "model_disallowed" |
    "overloaded" | "upstream_rate_limited" | "upstream_error" | "upstream_timeout" | "response_too_large" |
    "slow_client" | "cancelled" | "session_expired" | "internal_error";
  message: string;
  retryable?: boolean;
}

class RequestFailure extends Error {
  readonly code: RequestFailureInit["code"];
  readonly retryable: boolean;

  constructor(input: RequestFailureInit) {
    super(input.message);
    this.name = "RequestFailure";
    this.code = input.code;
    this.retryable = input.retryable ?? false;
  }
}

interface ActiveRequest {
  readonly message: RequestStartMessage;
  readonly controller: AbortController;
  readonly sentAt: Map<number, { at: number; frameBytes: number }>;
  readonly creditWaiters: Set<() => void>;
  readonly deadlinePromise: Promise<never>;
  readonly cancelPromise: Promise<never>;
  rejectDeadline(error: RequestFailure): void;
  rejectCancel(error: RequestFailure): void;
  deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  ackTimer: ReturnType<typeof setTimeout> | undefined;
  reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  upstreamStarted: boolean;
  terminalSent: boolean;
  lastSentSeq: number;
  lastAckedSeq: number;
}

interface EnvelopeKeySet {
  keys: Record<string, string>;
}

interface ProviderRoute {
  readonly id: string;
  readonly protocol: ProviderProtocol;
  readonly baseUrl: string;
  readonly endpoint: string;
  readonly custom: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function providerDisallowed(): RequestFailure {
  return new RequestFailure({
    code: "provider_disallowed",
    message: "This provider is not enabled for the project.",
  });
}

function resolveProviderRoute(
  value: unknown,
  requestedProvider: string,
  forbiddenOrigins: readonly string[],
): ProviderRoute {
  if (value === undefined) {
    if (!isProviderId(requestedProvider)) throw providerDisallowed();
    const builtin = BUILTIN_PROVIDERS[requestedProvider];
    return {
      id: requestedProvider,
      protocol: builtin.protocol,
      baseUrl: builtin.baseUrl,
      endpoint: builtin.endpoint,
      custom: false,
    };
  }

  if (!isRecord(value) || typeof value.id !== "string" || typeof value.displayName !== "string" ||
      !isProviderProtocol(value.protocol) || typeof value.baseUrl !== "string" || typeof value.custom !== "boolean" ||
      value.id !== requestedProvider) {
    throw providerDisallowed();
  }

  let baseUrl: string;
  try {
    baseUrl = normalizeBaseUrl(value.baseUrl, { forbiddenOrigins });
  } catch {
    throw providerDisallowed();
  }

  if (value.custom) {
    // Custom rows have their own identities; they cannot shadow the built-in
    // credential namespaces or bypass the official endpoint configuration.
    if (isProviderId(value.id)) throw providerDisallowed();
    let endpoint: string;
    try {
      endpoint = buildProviderEndpoint(value.protocol, baseUrl);
    } catch {
      throw providerDisallowed();
    }
    return { id: value.id, protocol: value.protocol, baseUrl, endpoint, custom: true };
  }

  if (!isProviderId(value.id) || value.protocol !== value.id) throw providerDisallowed();
  const builtin = BUILTIN_PROVIDERS[value.id];
  if (baseUrl !== builtin.baseUrl) throw providerDisallowed();
  return {
    id: value.id,
    protocol: builtin.protocol,
    baseUrl: builtin.baseUrl,
    endpoint: builtin.endpoint,
    custom: false,
  };
}

export function boundedProjectLimits(value: unknown): ProjectLimits | undefined {
  if (value === undefined) {
    return {
      maxPayloadBytes: HARD_MAX_PAYLOAD_BYTES,
      maxConcurrency: HARD_MAX_CONCURRENCY,
      maxSessionSeconds: MAX_SESSION_DURATION_SECONDS,
    };
  }
  if (!isRecord(value) || !Number.isSafeInteger(value.maxPayloadBytes) ||
      !Number.isSafeInteger(value.maxConcurrency) || !Number.isSafeInteger(value.maxSessionSeconds) ||
      (value.maxPayloadBytes as number) < MIN_REQUEST_PAYLOAD_BYTES || (value.maxConcurrency as number) < 1 ||
      (value.maxSessionSeconds as number) < 30) return undefined;
  return {
    maxPayloadBytes: Math.min(value.maxPayloadBytes as number, HARD_MAX_PAYLOAD_BYTES),
    maxConcurrency: Math.min(value.maxConcurrency as number, HARD_MAX_CONCURRENCY),
    maxSessionSeconds: Math.min(value.maxSessionSeconds as number, MAX_SESSION_DURATION_SECONDS),
  };
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Envelope key has invalid encoding");
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new TypeError("Envelope key has invalid encoding");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.byteLength !== 32) throw new TypeError("Envelope key has invalid size");
  return bytes;
}

function envelopeKeySet(value: string): EnvelopeKeySet {
  let decoded: unknown;
  try {
    decoded = JSON.parse(value) as unknown;
  } catch {
    throw new TypeError("Envelope key configuration is invalid");
  }
  if (!isRecord(decoded) || !isRecord(decoded.keys)) {
    throw new TypeError("Envelope key configuration is invalid");
  }
  const keys: Record<string, string> = {};
  for (const [kid, key] of Object.entries(decoded.keys)) {
    if (typeof key === "string") keys[kid] = key;
  }
  return { keys };
}

function resolveEnvelopeKey(keySet: EnvelopeKeySet, kid: string): Uint8Array {
  const encoded = keySet.keys[kid];
  if (encoded === undefined) throw new TypeError("Envelope key version is unavailable");
  return decodeBase64Url(encoded);
}

function identityFailure(reasonCode: string | undefined): RequestFailure {
  switch (reasonCode) {
    case "invalid_request":
      return new RequestFailure({ code: "invalid_request", message: "The request is invalid." });
    case "unauthorized":
    case "token_invalid":
    case "session_expired":
    case "session_revoked":
    case "invalid_or_inactive_token":
      return new RequestFailure({ code: "unauthorized", message: "Gateway authorization is no longer valid." });
    case "credential_invalid":
    case "credential_unavailable":
    case "credential_revoked":
    case "credential_expired":
      return new RequestFailure({ code: "credential_invalid", message: "The provider credential is unavailable." });
    case "credential_owner_mismatch":
    case "provider_disallowed":
    case "provider_disabled":
      if (reasonCode === "credential_owner_mismatch") {
        return new RequestFailure({ code: "forbidden", message: "This request is not authorized." });
      }
      return new RequestFailure({ code: "provider_disallowed", message: "This provider is not enabled for the project." });
    case "model_disallowed":
    case "model_disabled":
    case "provider_or_model_not_allowed":
      return new RequestFailure({ code: "model_disallowed", message: "This model is not enabled for the project." });
    case "forbidden":
    case "ownership_mismatch":
      return new RequestFailure({ code: "forbidden", message: "This request is not authorized." });
    default:
      return new RequestFailure({ code: "internal_error", message: "Gateway authorization could not be completed.", retryable: true });
  }
}

function credentialMetadataMatches(
  envelope: Pick<CredentialEnvelope, "credentialId" | "userId" | "projectId" | "provider" | "exp" | "kid">,
  metadata: AuthorizedCredentialMetadata,
  claims: MachineClaims,
  request: RequestStartMessage,
): boolean {
  return envelope.credentialId === metadata.credentialId &&
    envelope.userId === metadata.userId && envelope.userId === claims.sub &&
    envelope.projectId === metadata.projectId && envelope.projectId === claims.project_id &&
    envelope.provider === metadata.provider && envelope.provider === request.provider &&
    envelope.exp === metadata.expiresAt && envelope.kid === metadata.keyVersion;
}

export function splitUtf8(text: string, maxBytes: number): string[] {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new RangeError("UTF-8 chunk size must be positive");
  const bytes = encoder.encode(text);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const result: string[] = [];
  for (let offset = 0; offset < bytes.byteLength;) {
    let end = Math.min(offset + maxBytes, bytes.byteLength);
    while (end < bytes.byteLength && (bytes[end]! & 0xc0) === 0x80) end -= 1;
    if (end === offset) throw new RangeError("UTF-8 chunk limit is too small for a code point");
    result.push(decoder.decode(bytes.subarray(offset, end)));
    offset = end;
  }
  return result;
}

export class GatewaySession {
  private readonly active = new Map<string, ActiveRequest>();
  private readonly requestIds = new Set<string>();
  private closed = false;
  private stopNewStarts = false;
  private tokenExpired = false;
  private pendingProviderReadBytes = 0;
  private pendingOutboundFrameBytes = 0;
  private lifetimeOutboundFrameBytes = 0;
  private readonly outboundCreditWaiters = new Set<() => void>();
  private providerReadLocked = false;
  private readonly providerReadWaiters = new Set<() => void>();
  private drainNoticeSent = false;
  private policyDrainSent = false;
  private outboundLimitTriggered = false;
  private drainTimer: ReturnType<typeof setTimeout> | undefined;
  private expiryTimer: ReturnType<typeof setTimeout> | undefined;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;
  private sessionLimitTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly socket: WebSocket,
    private readonly accessToken: string,
    private readonly claims: MachineClaims,
    private readonly dependencies: GatewayDependencies,
    private readonly context: GatewayExecutionContext,
    private readonly limits: ProjectLimits = {
      maxPayloadBytes: HARD_MAX_PAYLOAD_BYTES,
      maxConcurrency: HARD_MAX_CONCURRENCY,
      maxSessionSeconds: MAX_SESSION_DURATION_SECONDS,
    },
    private readonly now: () => number = Date.now,
  ) {}

  attach(): void {
    this.socket.binaryType = "arraybuffer";
    this.socket.accept();
    this.socket.addEventListener("message", (event: MessageEvent<unknown>) => {
      try {
        this.onMessage(event.data);
      } catch {
        this.protocolError();
      }
    });
    this.socket.addEventListener("close", () => this.onSocketClosed());
    this.socket.addEventListener("error", () => this.onSocketClosed());

    const now = this.now();
    const expiresInMs = Math.max(0, this.claims.exp * 1000 - now);
    this.drainTimer = setTimeout(
      () => this.sendDraining("token_expiring", false),
      Math.max(0, expiresInMs - TOKEN_DRAIN_BEFORE_EXPIRY_MS),
    );
    this.expiryTimer = setTimeout(() => this.onTokenExpired(), expiresInMs);
    this.sessionLimitTimer = setTimeout(() => {
      this.sendDraining("policy", true);
      this.close(1000, "Gateway session duration limit reached");
    }, this.limits.maxSessionSeconds * 1000);
    this.send({
      event: "session.ready",
      protocol: 1,
      connectionId: crypto.randomUUID(),
      maxInFlight: this.limits.maxConcurrency,
      maxPayloadBytes: this.limits.maxPayloadBytes,
      maxSessionSeconds: this.limits.maxSessionSeconds,
      maxChunkBytes: MAX_CHUNK_BYTES,
      ackWindow: ACK_WINDOW,
      maxRequestFrameBytes: MAX_REQUEST_FRAME_BYTES,
      maxResponseFrameBytes: MAX_RESPONSE_FRAME_BYTES,
      tokenExpiresAt: this.claims.exp,
    });
    this.refreshIdleTimer();
  }

  private onMessage(data: unknown): void {
    if (this.closed) return;
    if (typeof data !== "string") {
      this.close(1003, "JSON text frames are required");
      return;
    }
    if (data.length > MAX_GATEWAY_FRAME_BYTES) {
      this.close(1009, "Frame exceeds the gateway limit");
      return;
    }

    let message: ReturnType<typeof parseGatewayFrame>;
    try {
      message = parseGatewayFrame(data);
    } catch (error) {
      const code = isRecord(error) && error.code === "frame_too_large" ? 1009 : 1002;
      this.close(code, "Invalid gateway protocol frame");
      return;
    }
    if (message.event !== "request.start" && message.event !== "request.cancel") {
      this.close(1002, "Client sent a server-only event");
      return;
    }

    if (message.event === "request.cancel") {
      this.onCancel(message.requestId);
      return;
    }
    if ("op" in message) {
      this.onAcknowledgement(message.requestId, message.ackSeq);
      return;
    }
    this.onStart(message);
  }

  private onAcknowledgement(requestId: string, ackSeq: number): void {
    const task = this.active.get(requestId);
    if (!task) {
      if (this.requestIds.has(requestId)) return;
      this.protocolError();
      return;
    }
    if (ackSeq > task.lastSentSeq) {
      this.protocolError();
      return;
    }
    if (ackSeq <= task.lastAckedSeq) return;

    task.lastAckedSeq = ackSeq;
    for (const [seq, item] of task.sentAt) {
      if (seq <= ackSeq) {
        task.sentAt.delete(seq);
        this.pendingOutboundFrameBytes -= item.frameBytes;
      }
    }
    this.armAcknowledgementTimer(task);
    this.wakeCreditWaiters(task);
    this.wakeOutboundCreditWaiters();
    if (task.terminalSent && task.sentAt.size === 0) this.cleanupTask(task);
  }

  private onCancel(requestId: string): void {
    const task = this.active.get(requestId);
    if (!task) return;
    this.failTask(task, new RequestFailure({ code: "cancelled", message: "The request was cancelled." }));
  }

  private onStart(message: RequestStartMessage): void {
    if (this.requestIds.has(message.requestId)) {
      this.close(1002, "Request IDs must be unique for the session");
      return;
    }
    if (this.requestIds.size >= MAX_REQUEST_IDS_PER_SOCKET) {
      this.sendDraining("policy", true);
      this.maybeCloseDrained();
      return;
    }
    this.requestIds.add(message.requestId);

    if (this.stopNewStarts) {
      const error = this.tokenExpired
        ? new RequestFailure({ code: "session_expired", message: "The Gateway session has expired." })
        : new RequestFailure({ code: "overloaded", message: "This Gateway session is draining." });
      this.sendRequestError(message.requestId, error, -1, false);
      this.maybeCloseDrained();
      return;
    }
    if (this.now() >= this.claims.exp * 1000) {
      this.tokenExpired = true;
      this.stopNewStarts = true;
      this.sendRequestError(
        message.requestId,
        new RequestFailure({ code: "session_expired", message: "The Gateway session has expired." }),
        -1,
        false,
      );
      this.maybeCloseDrained();
      return;
    }
    if (this.active.size >= this.limits.maxConcurrency) {
      this.sendRequestError(
        message.requestId,
        new RequestFailure({ code: "overloaded", message: "Too many requests are active on this session." }),
        -1,
        false,
      );
      return;
    }
    if (message.envelope.provider !== message.provider) {
      this.sendRequestError(
        message.requestId,
        new RequestFailure({ code: "credential_invalid", message: "The provider credential is unavailable." }),
        -1,
        false,
      );
      return;
    }

    const task = this.createTask(message);
    this.active.set(message.requestId, task);
    this.clearIdleTimer();
    if (this.requestIds.size === MAX_REQUEST_IDS_PER_SOCKET) this.sendDraining("policy", true);
    const run = this.runRequest(task).catch(() => {
      if (!task.terminalSent) {
        this.failTask(task, new RequestFailure({ code: "internal_error", message: "The Gateway could not complete this request." }));
      }
    });
    this.context.waitUntil(run);
  }

  private createTask(message: RequestStartMessage): ActiveRequest {
    let rejectDeadline!: (error: RequestFailure) => void;
    let rejectCancel!: (error: RequestFailure) => void;
    const deadlinePromise = new Promise<never>((_resolve, reject) => { rejectDeadline = reject; });
    const cancelPromise = new Promise<never>((_resolve, reject) => { rejectCancel = reject; });
    const task: ActiveRequest = {
      message,
      controller: new AbortController(),
      sentAt: new Map(),
      creditWaiters: new Set(),
      deadlinePromise,
      cancelPromise,
      rejectDeadline,
      rejectCancel,
      deadlineTimer: undefined,
      ackTimer: undefined,
      reader: undefined,
      upstreamStarted: false,
      terminalSent: false,
      lastSentSeq: -1,
      lastAckedSeq: -1,
    };
    task.deadlineTimer = setTimeout(() => {
      task.controller.abort();
      void this.cancelReader(task);
      task.rejectDeadline(new RequestFailure({
        code: "upstream_timeout",
        message: "The provider request exceeded the Gateway time limit.",
        retryable: true,
      }));
    }, MAX_REQUEST_DURATION_MS);
    return task;
  }

  private async runRequest(task: ActiveRequest): Promise<void> {
    let plaintext: Uint8Array | undefined;
    let response: Response | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let reservedReadBytes = 0;
    try {
      const forbiddenOrigins = [new URL(this.dependencies.machineIssuer).origin];
      if (this.dependencies.gatewayOrigin) {
        forbiddenOrigins.push(new URL(this.dependencies.gatewayOrigin).origin);
      }
      const authorize = () => this.dependencies.identity.authorizeTokenRequest({
        accessToken: this.accessToken,
        credentialId: task.message.envelope.credentialId,
        provider: task.message.provider,
        model: task.message.model,
      });
      const readAuthorization = (authorization: unknown) => {
        if (!isRecord(authorization) || typeof authorization.allowed !== "boolean") {
          throw new RequestFailure({ code: "internal_error", message: "Gateway authorization returned an invalid result." });
        }
        if (!authorization.allowed) {
          throw identityFailure(typeof authorization.reasonCode === "string" ? authorization.reasonCode : undefined);
        }
        const requestLimits = boundedProjectLimits(authorization.limits);
        if (!requestLimits) {
          throw new RequestFailure({ code: "internal_error", message: "Gateway authorization returned invalid project limits." });
        }
        if (this.active.size > Math.min(this.limits.maxConcurrency, requestLimits.maxConcurrency)) {
          throw new RequestFailure({ code: "overloaded", message: "Too many requests are active on this session." });
        }
        const metadata = authorization.credentialMetadata as AuthorizedCredentialMetadata | undefined;
        const principal = authorization.principal as AuthorizedPrincipal | undefined;
        const authorizedModel = authorization.authorizedModel as AuthorizedModel | undefined;
        if (!metadata || !principal || !authorizedModel) {
          throw new RequestFailure({ code: "internal_error", message: "Gateway authorization returned incomplete data." });
        }
        if (principal.userId !== this.claims.sub || principal.projectId !== this.claims.project_id ||
            principal.clientId !== this.claims.client_id || principal.sessionId !== this.claims.sid ||
            !credentialMetadataMatches(task.message.envelope, metadata, this.claims, task.message)) {
          throw new RequestFailure({ code: "credential_invalid", message: "The provider credential is unavailable." });
        }
        if (authorizedModel.alias !== task.message.model || !validateUpstreamModel(authorizedModel.upstreamModel)) {
          throw new RequestFailure({ code: "model_disallowed", message: "This model is not enabled for the project." });
        }
        const providerPayloadBytes = encoder.encode(JSON.stringify({
          ...task.message.payload,
          model: authorizedModel.upstreamModel,
          stream: true,
        })).byteLength;
        if (providerPayloadBytes > requestLimits.maxPayloadBytes) {
          throw new RequestFailure({ code: "invalid_request", message: "The request payload exceeds the project limit." });
        }
        const route = resolveProviderRoute(authorization.authorizedProvider, task.message.provider, forbiddenOrigins);
        if (metadata.provider !== route.id) throw providerDisallowed();
        return { metadata, authorizedModel, requestLimits, route };
      };

      let authorization = await this.awaitTask(task, authorize());
      if (task.terminalSent) return;
      let validated = readAuthorization(authorization);
      if (validated.route.custom) {
        try {
          const dnsValidation = assertPublicEndpointResolution(
            validated.route.endpoint,
            this.dependencies.endpointDnsFetcher ?? this.dependencies.fetcher,
          );
          await this.awaitTask(task, dnsValidation);
        } catch (error) {
          if (error instanceof RequestFailure) throw error;
          throw providerDisallowed();
        }
        if (task.terminalSent) return;
        if (this.now() >= this.claims.exp * 1000) {
          this.tokenExpired = true;
          this.stopNewStarts = true;
          throw new RequestFailure({ code: "session_expired", message: "The Gateway session has expired." });
        }

        // DNS checks can take several seconds; reauthorize custom providers
        // afterward so a revoked D1 registration or project grant cannot race
        // the lookup and still launch upstream.
        authorization = await this.awaitTask(task, authorize());
        if (task.terminalSent) return;
        const refreshed = readAuthorization(authorization);
        if (refreshed.route.custom !== validated.route.custom ||
            refreshed.route.id !== validated.route.id ||
            refreshed.route.protocol !== validated.route.protocol ||
            refreshed.route.baseUrl !== validated.route.baseUrl ||
            refreshed.route.endpoint !== validated.route.endpoint) {
          throw providerDisallowed();
        }
        validated = refreshed;
      }
      const { metadata, authorizedModel, route } = validated;
      const provider = route.protocol;
      if (task.terminalSent || this.closed || this.socket.readyState !== 1) return;
      if (this.now() >= this.claims.exp * 1000) {
        this.tokenExpired = true;
        this.stopNewStarts = true;
        throw new RequestFailure({ code: "session_expired", message: "The Gateway session has expired." });
      }
      let key: Uint8Array;
      try {
        const keySet = envelopeKeySet(this.dependencies.envelopeKeys);
        key = resolveEnvelopeKey(keySet, task.message.envelope.kid);
      } catch {
        throw new RequestFailure({
          code: "internal_error",
          message: "Gateway credential configuration is unavailable.",
        });
      }
      let decrypted: Awaited<ReturnType<typeof decryptCredentialEnvelope>>;
      try {
        decrypted = await this.awaitTask(task, decryptCredentialEnvelope(task.message.envelope, key));
      } catch (error) {
        if (error instanceof RequestFailure) throw error;
        throw new RequestFailure({
          code: "credential_invalid",
          message: "The provider credential is unavailable.",
        });
      } finally {
        key.fill(0);
      }
      if (task.terminalSent) {
        decrypted.plaintext.fill(0);
        return;
      }
      if (decrypted.metadata.credentialId !== metadata.credentialId ||
          decrypted.metadata.userId !== metadata.userId || decrypted.metadata.userId !== this.claims.sub ||
          decrypted.metadata.projectId !== metadata.projectId || decrypted.metadata.projectId !== this.claims.project_id ||
          decrypted.metadata.provider !== metadata.provider || decrypted.metadata.provider !== task.message.provider ||
          decrypted.metadata.exp !== metadata.expiresAt || decrypted.metadata.kid !== metadata.keyVersion) {
        decrypted.plaintext.fill(0);
        throw new RequestFailure({ code: "credential_invalid", message: "The provider credential is unavailable." });
      }
      plaintext = decrypted.plaintext;
      let apiKey: string;
      try {
        apiKey = providerKeyFromBytes(provider, plaintext);
      } catch {
        throw new RequestFailure({
          code: "credential_invalid",
          message: "The provider credential is unavailable.",
        });
      }
      const providerRequest = buildProviderRequest(
        provider,
        route.endpoint,
        apiKey,
        authorizedModel.upstreamModel,
        task.message.payload,
        task.controller.signal,
      );

      task.upstreamStarted = true;
      const upstreamPromise = this.dependencies.fetcher(providerRequest.url, providerRequest.init);
      plaintext.fill(0);
      plaintext = undefined;
      response = await this.awaitTaskWithIdleTimeout(task, upstreamPromise);
      if (task.terminalSent) {
        await this.discardResponse(response);
        return;
      }
      if (response.status >= 300 && response.status < 400) {
        await this.discardResponse(response);
        throw new RequestFailure({ code: "upstream_error", message: "The provider returned a redirect, which Gateway does not follow." });
      }
      if (response.status === 429) {
        await this.discardResponse(response);
        throw new RequestFailure({
          code: "upstream_rate_limited",
          message: "The provider is rate limiting this request.",
          retryable: true,
        });
      }
      if (!response.ok) {
        await this.discardResponse(response);
        throw new RequestFailure({
          code: "upstream_error",
          message: "The provider could not complete this request.",
          retryable: response.status >= 500,
        });
      }
      const contentType = response.headers.get("content-type") ?? "";
      if (!/^text\/event-stream(?:\s*;|$)/i.test(contentType) || !response.body) {
        await this.discardResponse(response);
        throw new RequestFailure({ code: "upstream_error", message: "The provider returned an invalid stream." });
      }

      reader = response.body.getReader();
      task.reader = reader;
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let responseBytes = 0;
      while (true) {
        const releaseReadSlot = await this.acquireProviderReadSlot(task);
        if (task.terminalSent) return;
        let reachedEof = false;
        try {
          const result = await this.awaitTaskWithIdleTimeout(task, reader.read());
          if (task.terminalSent) return;
          if (result.done) {
            reachedEof = true;
          } else {
            const readBytes = result.value.byteLength;
            if (responseBytes + readBytes > MAX_RESPONSE_BYTES) {
              throw new RequestFailure({
                code: "response_too_large",
                message: "The provider response exceeded the Gateway limit.",
              });
            }
            if (readBytes > MAX_PENDING_PROVIDER_READ_BYTES ||
                this.pendingProviderReadBytes + readBytes > MAX_PENDING_PROVIDER_READ_BYTES) {
              throw new RequestFailure({
                code: "upstream_error",
                message: "The provider stream read exceeded the Gateway buffer limit.",
                retryable: true,
              });
            }
            responseBytes += readBytes;
            reservedReadBytes = readBytes;
            this.pendingProviderReadBytes += readBytes;
            const text = decoder.decode(result.value, { stream: true });
            await this.sendText(task, text);
            this.pendingProviderReadBytes -= reservedReadBytes;
            reservedReadBytes = 0;
          }
        } finally {
          releaseReadSlot();
        }
        if (task.terminalSent) return;
        if (reachedEof) break;
      }
      const finalText = decoder.decode();
      await this.sendText(task, finalText);
      if (task.terminalSent) return;
      this.succeedTask(task);
    } catch (error) {
      if (task.terminalSent) return;
      const failure = error instanceof RequestFailure
        ? error
        : error instanceof ProviderCallError
          ? new RequestFailure({ code: error.code, message: error.message, retryable: error.retryable })
          : new RequestFailure({
              code: task.controller.signal.aborted ? "upstream_timeout" : "upstream_error",
              message: task.controller.signal.aborted
                ? "The provider request was interrupted."
                : "The provider could not complete this request.",
              retryable: true,
            });
      this.failTask(task, failure);
    } finally {
      if (reservedReadBytes > 0) this.pendingProviderReadBytes -= reservedReadBytes;
      if (plaintext) plaintext.fill(0);
      if (reader && !task.terminalSent) await this.cancelReader(task);
      this.finishTask(task);
    }
  }

  private async sendText(task: ActiveRequest, text: string): Promise<void> {
    if (text.length === 0) return;
    for (const piece of splitUtf8(text, MAX_ACTUAL_CHUNK_BYTES)) {
      await this.waitForCredit(task);
      if (task.terminalSent) return;
      const seq = task.lastSentSeq + 1;
      const frame: GatewayServerFrame = { event: "response.chunk", requestId: task.message.requestId, seq, data: piece };
      const frameBytes = await this.sendChunkWithCredit(task, frame);
      if (frameBytes === undefined) return;
      task.lastSentSeq = seq;
      task.sentAt.set(seq, { at: this.now(), frameBytes });
      this.armAcknowledgementTimer(task);
    }
  }

  private async waitForCredit(task: ActiveRequest): Promise<void> {
    while (task.lastSentSeq - task.lastAckedSeq >= ACK_WINDOW) {
      if (task.terminalSent) return;
      let wake!: () => void;
      const credit = new Promise<void>((resolve) => {
        wake = resolve;
        task.creditWaiters.add(resolve);
      });
      try {
        await this.awaitTask(task, credit);
      } finally {
        task.creditWaiters.delete(wake);
      }
    }
  }

  private armAcknowledgementTimer(task: ActiveRequest): void {
    if (task.ackTimer) clearTimeout(task.ackTimer);
    const oldest = task.sentAt.get(task.lastAckedSeq + 1);
    if (oldest === undefined) {
      task.ackTimer = undefined;
      return;
    }
    const remaining = Math.max(0, ACK_TIMEOUT_MS - (this.now() - oldest.at));
    task.ackTimer = setTimeout(() => {
      if (!task.sentAt.has(task.lastAckedSeq + 1)) return;
      if (task.terminalSent) {
        this.close(1013, "Gateway acknowledgement deadline expired");
        return;
      }
      this.failTask(task, new RequestFailure({
        code: "slow_client",
        message: "The response receiver stopped acknowledging stream data.",
        retryable: true,
      }));
      this.sendDraining("policy", true);
      this.close(1013, "Gateway acknowledgement deadline expired");
    }, remaining);
  }

  private async sendChunkWithCredit(task: ActiveRequest, frame: GatewayServerFrame): Promise<number | undefined> {
    const serialized = JSON.stringify(frame);
    const frameBytes = encoder.encode(serialized).byteLength;
    if (frameBytes > MAX_OUTBOUND_FRAME_BYTES) {
      this.close(1013, "Gateway output frame limit reached");
      return undefined;
    }
    while (this.pendingOutboundFrameBytes + frameBytes > MAX_PENDING_OUTBOUND_FRAME_BYTES) {
      if (task.terminalSent || this.closed) return undefined;
      let wake!: () => void;
      const available = new Promise<void>((resolve) => {
        wake = resolve;
        this.outboundCreditWaiters.add(resolve);
      });
      try {
        await this.awaitTask(task, available);
      } finally {
        this.outboundCreditWaiters.delete(wake);
      }
    }
    if (task.terminalSent || this.closed || this.socket.readyState !== 1) return undefined;
    if (!this.sendSerialized(serialized)) return undefined;
    this.pendingOutboundFrameBytes += frameBytes;
    return frameBytes;
  }

  private wakeCreditWaiters(task: ActiveRequest): void {
    for (const wake of task.creditWaiters) wake();
    task.creditWaiters.clear();
  }

  private wakeOutboundCreditWaiters(): void {
    for (const wake of this.outboundCreditWaiters) wake();
    this.outboundCreditWaiters.clear();
  }

  private async acquireProviderReadSlot(task: ActiveRequest): Promise<() => void> {
    while (this.providerReadLocked) {
      if (task.terminalSent) return () => undefined;
      let wake!: () => void;
      const available = new Promise<void>((resolve) => {
        wake = resolve;
        this.providerReadWaiters.add(resolve);
      });
      try {
        await this.awaitTask(task, available);
      } finally {
        this.providerReadWaiters.delete(wake);
      }
    }
    if (task.terminalSent || this.closed) return () => undefined;
    this.providerReadLocked = true;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.providerReadLocked = false;
      for (const wake of this.providerReadWaiters) wake();
      this.providerReadWaiters.clear();
    };
  }

  private async awaitTask<T>(task: ActiveRequest, promise: Promise<T>): Promise<T> {
    return await Promise.race([promise, task.deadlinePromise, task.cancelPromise]);
  }

  private async awaitTaskWithIdleTimeout<T>(task: ActiveRequest, promise: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const idle = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new RequestFailure({
        code: "upstream_timeout",
        message: "The provider stream became idle.",
        retryable: true,
      })), UPSTREAM_READ_IDLE_TIMEOUT_MS);
    });
    try {
      return await Promise.race([promise, task.deadlinePromise, task.cancelPromise, idle]);
    } catch (error) {
      if (error instanceof RequestFailure) {
        task.controller.abort();
        void this.cancelReader(task);
      }
      throw error;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private failTask(task: ActiveRequest, failure: RequestFailure): void {
    if (task.terminalSent) return;
    task.terminalSent = true;
    task.controller.abort();
    task.rejectCancel(failure);
    this.wakeCreditWaiters(task);
    void this.cancelReader(task);
    this.sendRequestError(task.message.requestId, failure, task.lastSentSeq, task.upstreamStarted);
    this.finishTerminal(task);
    if (failure.code === "slow_client") this.sendDraining("policy", true);
  }

  private succeedTask(task: ActiveRequest): void {
    if (task.terminalSent) return;
    task.terminalSent = true;
    this.send({ event: "response.end", requestId: task.message.requestId, lastSeq: task.lastSentSeq });
    this.finishTerminal(task);
  }

  private finishTerminal(task: ActiveRequest): void {
    if (task.deadlineTimer) clearTimeout(task.deadlineTimer);
    task.deadlineTimer = undefined;
    this.wakeCreditWaiters(task);
    if (task.sentAt.size === 0) this.cleanupTask(task);
    else this.armAcknowledgementTimer(task);
  }

  private sendRequestError(
    requestId: string,
    failure: RequestFailure,
    lastSeq: number,
    upstreamStarted: boolean,
  ): void {
    this.send({
      event: "response.error",
      requestId,
      lastSeq,
      code: failure.code,
      message: failure.message,
      upstreamStarted,
      retryable: failure.retryable,
    });
    this.refreshIdleTimer();
    this.maybeCloseDrained();
  }

  private cleanupTask(task: ActiveRequest): void {
    if (task.deadlineTimer) clearTimeout(task.deadlineTimer);
    if (task.ackTimer) clearTimeout(task.ackTimer);
    task.deadlineTimer = undefined;
    task.ackTimer = undefined;
    this.wakeCreditWaiters(task);
    if (this.active.get(task.message.requestId) === task) this.active.delete(task.message.requestId);
    this.refreshIdleTimer();
    this.maybeCloseDrained();
  }

  private finishTask(task: ActiveRequest): void {
    if (task.terminalSent) return;
    this.cleanupTask(task);
  }

  private async cancelReader(task: ActiveRequest): Promise<void> {
    const reader = task.reader;
    task.reader = undefined;
    if (!reader) return;
    try {
      await reader.cancel();
    } catch {
      // Cancellation is best-effort after abort; no provider data is logged.
    }
  }

  private async discardResponse(response: Response): Promise<void> {
    if (!response.body) return;
    try {
      const cancellation = response.body.cancel();
      void cancellation.catch(() => undefined);
    } catch {
      // The response is discarded without exposing its body.
    }
  }

  private send(frame: GatewayServerFrame): boolean {
    if (this.closed || this.socket.readyState !== 1) return false;
    const serialized = JSON.stringify(frame);
    return this.sendSerialized(serialized, frame.event === "session.draining" && frame.reason === "policy");
  }

  private sendSerialized(serialized: string, isPolicyDrain = false): boolean {
    if (this.closed || this.socket.readyState !== 1) return false;
    const frameBytes = encoder.encode(serialized).byteLength;
    if (frameBytes > MAX_OUTBOUND_FRAME_BYTES) {
      this.close(1013, "Gateway output frame limit reached");
      return false;
    }
    const allowedBytes = isPolicyDrain
      ? MAX_LIFETIME_OUTBOUND_FRAME_BYTES
      : MAX_LIFETIME_OUTBOUND_FRAME_BYTES - POLICY_DRAIN_RESERVE_BYTES;
    if (this.lifetimeOutboundFrameBytes + frameBytes > allowedBytes) {
      this.closeForOutboundLimit();
      return false;
    }
    this.lifetimeOutboundFrameBytes += frameBytes;
    try {
      this.socket.send(serialized);
      return true;
    } catch {
      this.close(1013, "Gateway could not queue a response");
      return false;
    }
  }

  private sendDraining(reason: "token_expiring" | "policy", stop: boolean): void {
    if (this.closed) return;
    if (stop) this.stopNewStarts = true;
    if (this.drainNoticeSent) {
      return;
    }
    const sent = this.send({ event: "session.draining", reason, reconnectAfterMs: 0 });
    if (sent) {
      this.drainNoticeSent = true;
      if (reason === "policy") this.policyDrainSent = true;
    }
  }

  private closeForOutboundLimit(): void {
    if (this.closed) return;
    if (!this.outboundLimitTriggered) {
      this.outboundLimitTriggered = true;
      this.stopNewStarts = true;
      if (!this.policyDrainSent) {
        const drain = JSON.stringify({ event: "session.draining", reason: "policy", reconnectAfterMs: 0 });
        const drainBytes = encoder.encode(drain).byteLength;
        if (this.lifetimeOutboundFrameBytes + drainBytes <= MAX_LIFETIME_OUTBOUND_FRAME_BYTES) {
          this.lifetimeOutboundFrameBytes += drainBytes;
          this.drainNoticeSent = true;
          this.policyDrainSent = true;
          try {
            this.socket.send(drain);
          } catch {
            // The following close still aborts all work if the peer stopped accepting frames.
          }
        }
      }
    }
    this.close(1013, "Gateway outbound session byte limit reached");
  }

  private onTokenExpired(): void {
    if (this.closed) return;
    this.tokenExpired = true;
    this.stopNewStarts = true;
    if (this.active.size === 0) this.close(1000, "Gateway token expired");
  }

  private maybeCloseDrained(): void {
    if (!this.closed && this.stopNewStarts && this.active.size === 0) {
      this.close(1000, "Gateway session is draining");
    }
  }

  private refreshIdleTimer(): void {
    this.clearIdleTimer();
    if (this.closed || this.active.size > 0) return;
    this.idleTimer = setTimeout(() => this.close(1000, "Gateway session idle"), SESSION_IDLE_TIMEOUT_MS);
  }

  private clearIdleTimer(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = undefined;
  }

  private protocolError(): void {
    this.close(1002, "Invalid gateway protocol frame");
  }

  private close(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.clearTimers();
    this.pendingOutboundFrameBytes = 0;
    this.wakeOutboundCreditWaiters();
    for (const wake of this.providerReadWaiters) wake();
    this.providerReadWaiters.clear();
    for (const task of this.active.values()) {
      task.terminalSent = true;
      task.controller.abort();
      task.rejectCancel(new RequestFailure({ code: "cancelled", message: "The Gateway session closed." }));
      this.wakeCreditWaiters(task);
      void this.cancelReader(task);
      this.cleanupTask(task);
    }
    try {
      if (this.socket.readyState === 1 || this.socket.readyState === 0) this.socket.close(code, reason.slice(0, 120));
    } catch {
      // The peer may already have closed the connection.
    }
  }

  private onSocketClosed(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearTimers();
    for (const task of this.active.values()) {
      task.terminalSent = true;
      task.controller.abort();
      task.rejectCancel(new RequestFailure({ code: "cancelled", message: "The Gateway connection closed." }));
      this.wakeCreditWaiters(task);
      void this.cancelReader(task);
      this.cleanupTask(task);
    }
  }

  private clearTimers(): void {
    if (this.drainTimer) clearTimeout(this.drainTimer);
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (this.sessionLimitTimer) clearTimeout(this.sessionLimitTimer);
    this.drainTimer = undefined;
    this.expiryTimer = undefined;
    this.idleTimer = undefined;
    this.sessionLimitTimer = undefined;
  }
}

export function validateIdentityClaims(
  validation: { valid: boolean; claims?: unknown },
  issuer: string,
  nowSeconds: number,
): MachineClaims | undefined {
  if (!validation.valid || !isRecord(validation.claims)) return undefined;
  const claims = validation.claims;
  if (typeof claims.sub !== "string" || typeof claims.sid !== "string" ||
      typeof claims.project_id !== "string" || typeof claims.client_id !== "string" ||
      typeof claims.jti !== "string" || claims.jti.length === 0 ||
      typeof claims.iss !== "string" || claims.iss !== issuer ||
      !Number.isSafeInteger(claims.exp) || (claims.exp as number) <= nowSeconds ||
      !Number.isSafeInteger(claims.iat) || (claims.iat as number) < 0 || (claims.iat as number) > nowSeconds + 30 ||
      !Number.isSafeInteger(claims.nbf) || (claims.nbf as number) < 0 || (claims.nbf as number) > nowSeconds + 30 ||
      (claims.nbf as number) < (claims.iat as number) || (claims.nbf as number) > (claims.exp as number) ||
      (claims.exp as number) <= (claims.iat as number) || (claims.exp as number) - (claims.iat as number) > 300) return undefined;
  const audience = claims.aud;
  if (!(audience === "llm-socket-gateway" ||
      (Array.isArray(audience) && audience.every((entry) => typeof entry === "string") && audience.includes("llm-socket-gateway")))) {
    return undefined;
  }
  return {
    sub: claims.sub,
    sid: claims.sid,
    project_id: claims.project_id,
    client_id: claims.client_id,
    iss: claims.iss,
    aud: audience as string | string[],
    exp: claims.exp as number,
    iat: claims.iat as number,
    nbf: claims.nbf as number,
    jti: claims.jti,
  };
}

export async function validateHandshakeToken(
  accessToken: string,
  dependencies: GatewayDependencies,
  now: () => number = Date.now,
): Promise<{ claims: MachineClaims; limits: ProjectLimits } | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error("identity_timeout")), HANDSHAKE_AUTH_TIMEOUT_MS);
  });
  try {
    const validation = await Promise.race([
      dependencies.identity.validateToken(accessToken),
      timeout,
    ]);
    const claims = validateIdentityClaims(validation, dependencies.machineIssuer, Math.floor(now() / 1000));
    const limits = boundedProjectLimits(validation.limits);
    return claims && limits ? { claims, limits } : undefined;
  } catch {
    return undefined;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function isSupportedProvider(provider: string): boolean {
  return /^[a-z0-9][a-z0-9_-]{0,63}$/.test(provider);
}

export function isCredentialEnvelope(value: unknown): value is CredentialEnvelope {
  return isRecord(value) && value.v === 1 && value.alg === "A256GCM";
}
