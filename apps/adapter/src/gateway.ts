import WebSocket, { type RawData } from "ws";
import {
  ACK_WINDOW,
  MAX_IN_FLIGHT,
  MAX_REQUEST_FRAME_BYTES,
  MAX_RESPONSE_FRAME_BYTES,
  MAX_REQUEST_PAYLOAD_BYTES,
  GatewayServerFrameSchema,
  parseGatewayFrame,
  parseGatewayMessage,
} from "@ws-proxy/shared";
import type {
  CredentialEnvelope,
  GatewayServerFrame,
  RequestStartMessage,
  ResponseEndMessage,
  ResponseErrorMessage,
} from "@ws-proxy/shared";
import type { GatewayProviderPayload } from "./types.js";
import { createGatewayProxyAgent } from "./proxy.js";

export interface GatewayRequestInput {
  requestId: string;
  provider: string;
  model: string;
  envelope: CredentialEnvelope;
  payload: GatewayProviderPayload;
}

export interface GatewayCallbacks {
  /** Resolves only after local output has been accepted and any writable drain has completed. */
  onChunk(seq: number, data: string): Promise<void>;
  onEnd(frame: ResponseEndMessage): Promise<void>;
  onError(frame: ResponseErrorMessage): Promise<void>;
  onInterrupted(message: string): Promise<void>;
  onLocalFailure(error: Error): Promise<void>;
}

interface PendingRequest {
  requestId: string;
  expectedSeq: number;
  queue: GatewayServerFrame[];
  processing: boolean;
  abandoned: boolean;
  terminal: boolean;
  interrupted: boolean;
  signal?: AbortSignal;
  abortListener?: () => void;
  callbacks: GatewayCallbacks;
  resolve: () => void;
}

export class GatewayUnavailableError extends Error {
  constructor(message = "Gateway is unavailable") {
    super(message);
    this.name = "GatewayUnavailableError";
  }
}

export class GatewayOverloadedError extends Error {
  constructor(message = "Gateway has reached the local in-flight request limit") {
    super(message);
    this.name = "GatewayOverloadedError";
  }
}

export class GatewayPayloadTooLargeError extends Error {
  constructor() {
    super("The request payload exceeds this Gateway session's configured frame or payload limit");
    this.name = "GatewayPayloadTooLargeError";
  }
}

export type AccessTokenSource = { getAccessToken(): Promise<string> };

export class GatewayClient {
  private readonly sessions = new Set<GatewaySession>();
  private current: GatewaySession | undefined;
  private connecting: Promise<GatewaySession> | undefined;

  constructor(
    private readonly gatewayUrl: string,
    private readonly tokens: AccessTokenSource,
    private readonly maxSessions = 2,
  ) {
    if (!Number.isInteger(maxSessions) || maxSessions < 1 || maxSessions > 2) {
      throw new Error("Gateway session limit must be one or two");
    }
  }

  async execute(input: GatewayRequestInput, callbacks: GatewayCallbacks, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return;
    const session = await this.getSession();
    if (signal?.aborted) return;
    await session.execute(input, callbacks, signal);
  }

  close(): void {
    for (const session of this.sessions) session.close(1000, "adapter shutdown");
    this.sessions.clear();
    this.current = undefined;
  }

  private async getSession(): Promise<GatewaySession> {
    if (this.current?.canStart()) return this.current;
    if (this.connecting) return this.connecting;
    const reusable = [...this.sessions].find((session) => session.canStart());
    if (reusable) {
      this.current = reusable;
      return reusable;
    }
    if ([...this.sessions].some((session) => session.acceptingRequests())) {
      throw new GatewayOverloadedError("The active Gateway socket has reached its configured in-flight limit");
    }
    for (const session of this.sessions) {
      if (session.activeCount === 0) {
        session.close(1000, "replaced idle session");
        this.sessions.delete(session);
      }
    }
    if (this.sessions.size >= this.maxSessions) throw new GatewayOverloadedError("Gateway is rotating sessions with active requests");
    this.connecting = this.createSession().finally(() => { this.connecting = undefined; });
    return this.connecting;
  }

  private async createSession(): Promise<GatewaySession> {
    const token = await this.tokens.getAccessToken();
    let session!: GatewaySession;
    session = new GatewaySession(this.gatewayUrl, token, (closed) => {
      this.sessions.delete(closed);
      if (this.current === closed) this.current = undefined;
    }, () => {
      if (this.current === session) this.current = undefined;
    });
    this.sessions.add(session);
    try {
      await session.connect();
    } catch (error) {
      session.close(1000, "connection failed");
      this.sessions.delete(session);
      if (this.current === session) this.current = undefined;
      throw error;
    }
    this.current = session;
    return session;
  }
}

class GatewaySession {
  private readonly socket: WebSocket;
  private readonly pending = new Map<string, PendingRequest>();
  private readonly readyPromise: Promise<void>;
  private resolveReady!: () => void;
  private rejectReady!: (error: Error) => void;
  private ready = false;
  private accepting = true;
  private closed = false;
  private startedCount = 0;
  private negotiatedMaxInFlight = MAX_IN_FLIGHT;
  private negotiatedMaxPayloadBytes = MAX_REQUEST_PAYLOAD_BYTES;
  private sessionLimitTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly terminalIds = new Set<string>();

  constructor(
    private readonly gatewayUrl: string,
    accessToken: string,
    private readonly onClose: (session: GatewaySession) => void,
    private readonly onDraining: () => void,
  ) {
    this.readyPromise = new Promise<void>((resolve, reject) => {
      this.resolveReady = resolve;
      this.rejectReady = reject;
    });
    const proxyAgent = createGatewayProxyAgent(gatewayUrl);
    this.socket = new WebSocket(gatewayUrl, ["llm-proxy.v1"], {
      headers: { authorization: `Bearer ${accessToken}` },
      maxPayload: MAX_RESPONSE_FRAME_BYTES,
      handshakeTimeout: 15_000,
      perMessageDeflate: false,
      ...(proxyAgent ? { agent: proxyAgent } : {}),
    });
    this.socket.on("open", () => {
      if (this.socket.protocol !== "llm-proxy.v1") {
        this.failProtocol("Gateway did not select the required protocol");
      }
    });
    this.socket.on("message", (data: RawData, isBinary: boolean) => this.onMessage(data, isBinary));
    this.socket.on("error", () => {
      if (!this.ready) this.rejectReady(new GatewayUnavailableError("Gateway WebSocket handshake failed"));
    });
    this.socket.on("close", (code) => this.onSocketClose(code));
  }

  get activeCount(): number {
    return this.pending.size;
  }

  canStart(): boolean {
    return this.ready && this.accepting && !this.closed && this.pending.size < this.negotiatedMaxInFlight;
  }

  acceptingRequests(): boolean {
    return this.ready && this.accepting && !this.closed;
  }

  async connect(): Promise<void> {
    await this.readyPromise;
  }

  async execute(input: GatewayRequestInput, callbacks: GatewayCallbacks, signal?: AbortSignal): Promise<void> {
    await this.readyPromise;
    if (!this.acceptingRequests()) throw new GatewayUnavailableError("Gateway session is draining or unavailable");
    if (this.pending.size >= this.negotiatedMaxInFlight) throw new GatewayOverloadedError();
    if (signal?.aborted) throw new GatewayUnavailableError("Request was cancelled before Gateway dispatch");
    if (this.startedCount >= 1024) {
      this.accepting = false;
      this.onDraining();
      throw new GatewayUnavailableError("Gateway session reached its request limit and is reconnecting");
    }
    const frame: RequestStartMessage = {
      event: "request.start",
      requestId: input.requestId,
      provider: input.provider,
      model: input.model,
      envelope: input.envelope,
      payload: input.payload,
    };
    let serialized: string;
    try {
      const validated = parseGatewayMessage(frame);
      if (validated.event !== "request.start" || "op" in validated) throw new GatewayUnavailableError("Invalid request frame");
      serialized = JSON.stringify(validated);
    } catch {
      throw new GatewayUnavailableError("Adapter could not validate the Gateway request frame");
    }
    if (Buffer.byteLength(serialized) > MAX_REQUEST_FRAME_BYTES) throw new GatewayPayloadTooLargeError();
    if (Buffer.byteLength(JSON.stringify(input.payload)) > this.negotiatedMaxPayloadBytes) {
      throw new GatewayPayloadTooLargeError();
    }

    const completion = new Promise<void>((resolve, reject) => {
      const pending: PendingRequest = {
        requestId: input.requestId,
        expectedSeq: 0,
        queue: [],
        processing: false,
        abandoned: false,
        terminal: false,
        interrupted: false,
        callbacks,
        resolve,
        ...(signal ? { signal } : {}),
      };
      if (signal) {
        pending.abortListener = () => {
          if (pending.terminal || pending.abandoned) return;
          pending.abandoned = true;
          this.send({ event: "request.cancel", requestId: pending.requestId });
          this.process(pending);
        };
        signal.addEventListener("abort", pending.abortListener, { once: true });
      }
      this.pending.set(pending.requestId, pending);
      this.startedCount += 1;
      if (this.startedCount >= 1024) {
        this.accepting = false;
        this.onDraining();
      }
      try {
        this.sendRaw(serialized);
      } catch (error) {
        this.pending.delete(pending.requestId);
        pending.signal?.removeEventListener("abort", pending.abortListener as () => void);
        this.startedCount -= 1;
        pending.terminal = true;
        reject(error instanceof Error ? error : new GatewayUnavailableError());
      }
    });
    return completion;
  }

  close(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    if (this.sessionLimitTimer) clearTimeout(this.sessionLimitTimer);
    if (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING) {
      this.socket.close(code, reason.slice(0, 120));
    }
  }

  private onMessage(data: RawData, isBinary: boolean): void {
    if (isBinary) {
      this.failProtocol("Gateway sent a binary frame");
      return;
    }
    let frame: GatewayServerFrame;
    try {
      const generic = parseGatewayFrame(rawDataToString(data));
      const parsed = GatewayServerFrameSchema.safeParse(generic);
      if (!parsed.success) throw new Error("invalid server frame");
      frame = parsed.data;
    } catch {
      this.failProtocol("Gateway sent an invalid protocol frame");
      return;
    }
    if (frame.event === "session.ready") {
      if (this.ready) {
        this.failProtocol("Gateway repeated session.ready");
        return;
      }
      this.negotiatedMaxInFlight = frame.maxInFlight;
      this.negotiatedMaxPayloadBytes = frame.maxPayloadBytes;
      this.ready = true;
      this.sessionLimitTimer = setTimeout(() => {
        this.accepting = false;
        this.onDraining();
        if (this.pending.size === 0) this.close(1000, "session duration limit");
      }, Math.max(1, frame.maxSessionSeconds - 5) * 1000);
      this.sessionLimitTimer.unref?.();
      this.resolveReady();
      return;
    }
    if (!this.ready) {
      this.failProtocol("Gateway sent data before session.ready");
      return;
    }
    if (frame.event === "session.draining") {
      this.accepting = false;
      this.onDraining();
      if (this.pending.size === 0) this.close(1000, "session draining");
      return;
    }
    const requestId = frame.requestId;
    const pending = this.pending.get(requestId);
    if (!pending) {
      if (this.terminalIds.has(requestId)) {
        this.failProtocol("Gateway sent a frame after a terminal response");
        return;
      }
      this.failProtocol("Gateway sent a frame for an unknown request");
      return;
    }
    if (pending.queue.length >= ACK_WINDOW + 1) {
      this.failProtocol("Gateway exceeded the bounded acknowledgement window");
      return;
    }
    pending.queue.push(frame);
    this.process(pending);
  }

  private process(pending: PendingRequest): void {
    if (pending.processing || pending.terminal) return;
    pending.processing = true;
    void (async () => {
      try {
        while (pending.queue.length > 0) {
          const frame = pending.queue.shift();
          if (!frame) continue;
          if (frame.event === "response.chunk") {
            if (frame.seq !== pending.expectedSeq) throw new Error("Gateway response sequence was not contiguous");
            if (!pending.abandoned) await pending.callbacks.onChunk(frame.seq, frame.data);
            pending.expectedSeq += 1;
            if (this.socket.readyState === WebSocket.OPEN) {
              this.send({ event: "request.start", op: "ack", requestId: pending.requestId, ackSeq: frame.seq });
            }
            continue;
          }
          if (frame.event === "response.end") {
            if (frame.lastSeq !== pending.expectedSeq - 1) throw new Error("Gateway terminal sequence did not match consumed chunks");
            if (!pending.abandoned) {
              try {
                await pending.callbacks.onEnd(frame);
              } catch (error) {
                await pending.callbacks.onLocalFailure(error instanceof Error ? error : new Error("Gateway stream failed")).catch(() => undefined);
              }
            }
            const sentAfterTerminal = pending.queue.length > 0;
            this.finishPending(pending);
            if (sentAfterTerminal) this.failProtocol("Gateway sent response data after a terminal frame");
            break;
          }
          if (frame.event === "response.error") {
            if (frame.lastSeq !== pending.expectedSeq - 1) throw new Error("Gateway error sequence did not match consumed chunks");
            if (!pending.abandoned) {
              try {
                await pending.callbacks.onError(frame);
              } catch (error) {
                await pending.callbacks.onLocalFailure(error instanceof Error ? error : new Error("Gateway stream failed")).catch(() => undefined);
              }
            }
            const sentAfterTerminal = pending.queue.length > 0;
            this.finishPending(pending);
            if (sentAfterTerminal) this.failProtocol("Gateway sent response data after a terminal frame");
            break;
          }
        }
        if (pending.interrupted && !pending.terminal) {
          if (!pending.abandoned) await pending.callbacks.onInterrupted("Gateway connection closed before a terminal response; the request may have been processed or billed.");
          this.finishPending(pending);
        }
      } catch (error) {
        pending.abandoned = true;
        if (this.socket.readyState === WebSocket.OPEN) this.send({ event: "request.cancel", requestId: pending.requestId });
        const safeError = error instanceof Error ? error : new Error("Gateway stream failed");
        await pending.callbacks.onLocalFailure(safeError).catch(() => undefined);
        if (this.closed || this.socket.readyState !== WebSocket.OPEN) this.finishPending(pending);
      } finally {
        pending.processing = false;
        if (pending.queue.length > 0 && !pending.terminal) this.process(pending);
      }
    })();
  }

  private finishPending(pending: PendingRequest): void {
    if (pending.terminal) return;
    pending.terminal = true;
    pending.queue.length = 0;
    pending.signal?.removeEventListener("abort", pending.abortListener as () => void);
    this.pending.delete(pending.requestId);
    this.terminalIds.add(pending.requestId);
    if (this.terminalIds.size > 1024) this.terminalIds.delete(this.terminalIds.values().next().value as string);
    pending.resolve();
    if (!this.accepting && this.pending.size === 0) this.close(1000, "session drained");
  }

  private onSocketClose(code: number): void {
    if (this.sessionLimitTimer) clearTimeout(this.sessionLimitTimer);
    if (this.closed && this.pending.size === 0) {
      this.onClose(this);
      return;
    }
    this.closed = true;
    this.accepting = false;
    if (!this.ready) this.rejectReady(new GatewayUnavailableError(`Gateway closed before the session was ready (${code})`));
    for (const pending of this.pending.values()) {
      pending.interrupted = true;
      this.process(pending);
    }
    this.onClose(this);
  }

  private failProtocol(message: string): void {
    this.accepting = false;
    if (!this.ready) this.rejectReady(new GatewayUnavailableError(message));
    this.close(1002, "invalid protocol frame");
    for (const pending of this.pending.values()) {
      pending.interrupted = true;
      this.process(pending);
    }
  }

  private send(frame: unknown): void {
    try {
      const validated = parseGatewayMessage(frame);
      this.sendRaw(JSON.stringify(validated));
    } catch {
      this.failProtocol("Adapter generated an invalid Gateway frame");
    }
  }

  private sendRaw(serialized: string): void {
    if (this.socket.readyState !== WebSocket.OPEN) throw new GatewayUnavailableError("Gateway connection is closed");
    this.socket.send(serialized, { binary: false }, (error) => {
      if (error) this.failProtocol("Gateway send failed");
    });
  }
}

function rawDataToString(data: RawData): string {
  if (typeof data === "string") return data;
  if (Array.isArray(data)) return Buffer.concat(data).toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  return data.toString("utf8");
}
