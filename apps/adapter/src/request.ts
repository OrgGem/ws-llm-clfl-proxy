import { open } from "node:fs/promises";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { ConfigStore } from "./config.js";
import { EnvironmentConfigStore } from "./env-config.js";
import { ChatGptOAuthManager } from "./oauth.js";
import { SseParser } from "./sse.js";
import { startAdapter } from "./server.js";
import type { AdapterServerOptions, RunningAdapter } from "./server.js";

const MAX_REQUEST_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAX_SSE_EVENT_CHARS = 1_048_576;

export type RequestApi = "chat.completions" | "responses" | "completions";

export class RequestCommandError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestCommandError";
  }
}

export interface RequestCommandDependencies {
  stdin?: Readable;
  stdout?: Writable;
  fetchImpl?: typeof fetch;
  startAdapterImpl?: (options: AdapterServerOptions) => Promise<RunningAdapter>;
}

export async function runRequestCommand(
  args: string[],
  configStore: ConfigStore,
  dependencies: RequestCommandDependencies = {},
): Promise<void> {
  const options = parseRequestOptions(args);
  const stdin = dependencies.stdin ?? process.stdin;
  const stdout = dependencies.stdout ?? process.stdout;
  const fetchImpl = dependencies.fetchImpl ?? fetch;
  const start = dependencies.startAdapterImpl ?? startAdapter;
  const interruptController = new AbortController();
  const onInterrupt = () => interruptController.abort();
  process.once("SIGINT", onInterrupt);
  const signal = interruptController.signal;
  let server: RunningAdapter | undefined;
  let oauthManager: ChatGptOAuthManager | undefined;

  try {
    const inputText = options.inputPath === undefined || options.inputPath === "-"
      ? await readLimitedStream(stdin, MAX_REQUEST_BYTES, signal)
      : await readLimitedFile(options.inputPath, MAX_REQUEST_BYTES, signal);
    if (signal.aborted) throw new RequestCommandError("Request cancelled.");

    const config = await configStore.load();
    const requestBody = parseRequestJson(inputText, config);
    const serializedBody = JSON.stringify(requestBody);
    if (Buffer.byteLength(serializedBody, "utf8") > MAX_REQUEST_BYTES) {
      throw new RequestCommandError("Request JSON exceeds the 1 MiB limit.");
    }

    if (!(configStore instanceof EnvironmentConfigStore) && (config.oauthModels?.length ?? 0) > 0) {
      oauthManager = new ChatGptOAuthManager(configStore);
    }
    try {
      server = await start({
        configStore,
        portOverride: 0,
        maxGatewaySessions: 1,
        ...(oauthManager ? { oauthManager } : {}),
      });
    } catch {
      await oauthManager?.close().catch(() => undefined);
      oauthManager = undefined;
      throw new RequestCommandError("The local adapter could not start.");
    }

    const pathByApi: Record<RequestApi, string> = {
      "chat.completions": "/v1/chat/completions",
      responses: "/v1/responses",
      completions: "/v1/completions",
    };
    let response: Response;
    try {
      response = await fetchImpl(`http://127.0.0.1:${server.port}${pathByApi[options.api]}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${config.localBearerToken}`,
          "content-type": "application/json",
        },
        body: serializedBody,
        signal,
      });
    } catch {
      if (signal.aborted) throw new RequestCommandError("Request cancelled.");
      throw new RequestCommandError("The adapter request failed before receiving an HTTP response.");
    }

    if (!response.ok) {
      throw new RequestCommandError(`Request failed with HTTP status ${response.status}.`);
    }
    if (signal.aborted) throw new RequestCommandError("Request cancelled.");
    if (requestBody.stream === true) {
      await writeStreamingResponse(response, options.api, stdout, signal);
    } else {
      await writeJsonResponse(response, stdout, signal);
    }
  } finally {
    process.removeListener("SIGINT", onInterrupt);
    if (server) await server.close().catch(() => undefined);
    else await oauthManager?.close().catch(() => undefined);
  }
}

export async function readLimitedStream(stream: Readable, maximumBytes: number, signal?: AbortSignal): Promise<string> {
  if (signal?.aborted) throw new RequestCommandError("Request cancelled.");
  const chunks: Buffer[] = [];
  let total = 0;
  return new Promise<string>((resolve, reject) => {
    const cleanup = () => {
      stream.off("data", onData);
      stream.off("end", onEnd);
      stream.off("error", onError);
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onData = (chunk: Buffer | Uint8Array | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buffer.byteLength;
      if (total > maximumBytes) {
        stream.destroy();
        fail(new RequestCommandError("Request JSON exceeds the 1 MiB limit."));
        return;
      }
      chunks.push(buffer);
    };
    const onEnd = () => {
      cleanup();
      resolve(Buffer.concat(chunks, total).toString("utf8"));
    };
    const onError = () => fail(signal?.aborted
      ? new RequestCommandError("Request cancelled.")
      : new RequestCommandError("Request input could not be read."));
    const onAbort = () => {
      stream.destroy();
      fail(new RequestCommandError("Request cancelled."));
    };
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
    stream.resume();
  });
}

async function readLimitedFile(filePath: string, maximumBytes: number, signal: AbortSignal): Promise<string> {
  let handle;
  try {
    handle = await open(path.resolve(filePath), "r");
    const fileStat = await handle.stat();
    if (!fileStat.isFile() || fileStat.size > maximumBytes) throw new RequestCommandError("Request JSON must be a regular file no larger than 1 MiB.");
    if (signal.aborted) throw new RequestCommandError("Request cancelled.");
    const chunks: Buffer[] = [];
    let total = 0;
    const buffer = Buffer.alloc(64 * 1024);
    while (true) {
      if (signal.aborted) throw new RequestCommandError("Request cancelled.");
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximumBytes) throw new RequestCommandError("Request JSON exceeds the 1 MiB limit.");
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    return Buffer.concat(chunks, total).toString("utf8");
  } catch (error) {
    if (error instanceof RequestCommandError) throw error;
    throw new RequestCommandError("Request input could not be read.");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function parseRequestOptions(args: string[]): { api: RequestApi; inputPath?: string } {
  let api: RequestApi | undefined;
  let inputPath: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option !== "--api" && option !== "--input") throw new RequestCommandError("Usage: request --api chat.completions|responses|completions [--input FILE|-]");
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new RequestCommandError(`Missing value for ${option}.`);
    if (option === "--api") {
      if (api) throw new RequestCommandError("Duplicate option --api.");
      if (value !== "chat.completions" && value !== "responses" && value !== "completions") {
        throw new RequestCommandError("--api must be chat.completions, responses, or completions.");
      }
      api = value;
    } else {
      if (inputPath !== undefined) throw new RequestCommandError("Duplicate option --input.");
      inputPath = value;
    }
    index += 1;
  }
  if (!api) throw new RequestCommandError("Missing required option --api.");
  return { api, ...(inputPath === undefined ? {} : { inputPath }) };
}

function parseRequestJson(text: string, config: Awaited<ReturnType<ConfigStore["load"]>>): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new RequestCommandError("Request input must be valid JSON.");
  }
  if (!isRecord(value)) throw new RequestCommandError("Request input must be a JSON object.");
  if (value.model === undefined) {
    const aliases = [...config.models.map((model) => model.id), ...(config.oauthModels ?? []).map((model) => model.alias)];
    if (aliases.length !== 1) throw new RequestCommandError("Request JSON must include model unless exactly one alias is configured.");
    value.model = aliases[0];
  }
  if (typeof value.model !== "string" || value.model.length === 0) throw new RequestCommandError("Request JSON model must be a configured alias.");
  if (value.stream !== undefined && typeof value.stream !== "boolean") throw new RequestCommandError("Request JSON stream must be a boolean.");
  return value;
}

async function writeJsonResponse(response: Response, stdout: Writable, signal: AbortSignal): Promise<void> {
  if (!response.headers.get("content-type")?.toLowerCase().includes("application/json")) {
    throw new RequestCommandError("The adapter returned an unexpected response format.");
  }
  const bytes = await readLimitedResponse(response, signal);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8")) as unknown;
  } catch {
    throw new RequestCommandError("The adapter returned invalid JSON.");
  }
  if (isRecord(parsed) && (parsed.type === "error" || parsed.error !== undefined)) {
    throw new RequestCommandError("The API returned an error response.");
  }
  if (signal.aborted) throw new RequestCommandError("Request cancelled.");
  await writeWithBackpressure(stdout, bytes, signal);
  if (isRecord(parsed) && parsed.status === "incomplete") {
    throw new RequestCommandError("The API returned an incomplete response.");
  }
}

async function writeStreamingResponse(response: Response, api: RequestApi, stdout: Writable, signal: AbortSignal): Promise<void> {
  if (!response.headers.get("content-type")?.toLowerCase().includes("text/event-stream")) {
    throw new RequestCommandError("The adapter returned an unexpected stream format.");
  }
  if (!response.body) throw new RequestCommandError("The API stream ended before producing a response.");
  const parser = new SseParser(MAX_SSE_EVENT_CHARS);
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let totalBytes = 0;
  let successTerminal = false;
  let incompleteTerminal = false;
  let sawError = false;
  let postTerminalData = false;
  const inspect = (events: ReturnType<SseParser["push"]>) => {
    for (const event of events) {
      if (successTerminal && event.data.length > 0) {
        postTerminalData = true;
        continue;
      }
      const parsed = event.data === "[DONE]" ? undefined : tryJson(event.data);
      const eventName = event.event ?? (isRecord(parsed) && typeof parsed.type === "string" ? parsed.type : undefined);
      if (eventName === "error" || eventName === "response.failed" || (isRecord(parsed) && (parsed.type === "error" || parsed.error !== undefined))) {
        sawError = true;
      }
      if ((api === "chat.completions" || api === "completions") && event.data.trim() === "[DONE]") successTerminal = true;
      if (api === "responses" && eventName === "response.completed") successTerminal = true;
      if (api === "responses" && eventName === "response.incomplete") {
        successTerminal = true;
        incompleteTerminal = true;
      }
    }
  };

  try {
    while (true) {
      if (signal.aborted) throw new RequestCommandError("Request cancelled.");
      const next = await reader.read();
      if (next.done) break;
      totalBytes += next.value.byteLength;
      if (totalBytes > MAX_RESPONSE_BYTES) throw new RequestCommandError("The API stream exceeded the 32 MiB limit.");
      let text: string;
      try {
        text = decoder.decode(next.value, { stream: true });
        inspect(parser.push(text));
      } catch {
        throw new RequestCommandError("The API stream was invalid or exceeded its event limit.");
      }
      await writeWithBackpressure(stdout, next.value, signal);
    }
    const tail = decoder.decode();
    if (tail) inspect(parser.push(tail));
    inspect(parser.finish());
    if (signal.aborted) throw new RequestCommandError("Request cancelled.");
    if (sawError) throw new RequestCommandError("The API stream reported an error.");
    if (incompleteTerminal) throw new RequestCommandError("The API returned an incomplete response.");
    if (postTerminalData || !successTerminal) throw new RequestCommandError("The API stream ended before a valid terminal event.");
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    if (error instanceof RequestCommandError) throw error;
    if (signal.aborted) throw new RequestCommandError("Request cancelled.");
    throw new RequestCommandError("The API stream was interrupted.");
  } finally {
    reader.releaseLock();
  }
}

async function readLimitedResponse(response: Response, signal: AbortSignal): Promise<Buffer> {
  if (!response.body) throw new RequestCommandError("The adapter returned an empty response.");
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      if (signal.aborted) throw new RequestCommandError("Request cancelled.");
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) throw new RequestCommandError("The API response exceeded the 32 MiB limit.");
      chunks.push(Buffer.from(next.value));
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    if (error instanceof RequestCommandError) throw error;
    if (signal.aborted) throw new RequestCommandError("Request cancelled.");
    throw new RequestCommandError("The API response was interrupted.");
  } finally {
    reader.releaseLock();
  }
}

export async function writeWithBackpressure(output: Writable, data: Uint8Array, signal: AbortSignal): Promise<void> {
  if (signal.aborted) throw new RequestCommandError("Request cancelled.");
  await new Promise<void>((resolve, reject) => {
    let callbackDone = false;
    let drainDone = false;
    let promiseSettled = false;
    let callbackHadError = false;
    let errorEventSeen = false;
    let fallbackTimer: ReturnType<typeof setTimeout> | undefined;
    const cleanupAll = () => {
      if (fallbackTimer) clearTimeout(fallbackTimer);
      output.off("drain", onDrain);
      output.off("error", onError);
      output.off("close", onClose);
      signal.removeEventListener("abort", onAbort);
    };
    const detachNonErrorListeners = () => {
      output.off("drain", onDrain);
      output.off("close", onClose);
      signal.removeEventListener("abort", onAbort);
    };
    const rejectOnce = (error: RequestCommandError) => {
      if (promiseSettled) return;
      promiseSettled = true;
      detachNonErrorListeners();
      reject(error);
    };
    const finishCleanup = () => {
      if (!callbackDone || !promiseSettled) return;
      if (callbackHadError && !errorEventSeen) {
        fallbackTimer ??= setTimeout(cleanupAll, 100);
        return;
      }
      cleanupAll();
    };
    const maybeFinish = () => {
      if (promiseSettled || !callbackDone || !drainDone) return;
      promiseSettled = true;
      cleanupAll();
      resolve();
    };
    const onDrain = () => { drainDone = true; maybeFinish(); };
    const onError = () => {
      errorEventSeen = true;
      rejectOnce(new RequestCommandError("Output stream failed."));
      finishCleanup();
    };
    const onClose = () => rejectOnce(new RequestCommandError("Output stream closed before the response finished."));
    const onAbort = () => rejectOnce(new RequestCommandError("Request cancelled."));
    output.once("drain", onDrain);
    output.once("error", onError);
    output.once("close", onClose);
    signal.addEventListener("abort", onAbort, { once: true });
    try {
      drainDone = output.write(data, (error?: Error | null) => {
        if (error) {
          callbackDone = true;
          callbackHadError = true;
          rejectOnce(new RequestCommandError("Output stream failed."));
          // Node emits the matching 'error' event after invoking a Writable
          // callback with an error. Keep the listener through that event, with
          // a short fallback for custom Writable implementations.
          finishCleanup();
          return;
        }
        callbackDone = true;
        maybeFinish();
        finishCleanup();
      });
    } catch {
      callbackDone = true;
      rejectOnce(new RequestCommandError("Output stream failed."));
      cleanupAll();
    }
  });
}

function tryJson(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return undefined; }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
