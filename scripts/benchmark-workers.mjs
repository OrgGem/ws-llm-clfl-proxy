import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, open, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { ConfigStore, defaultConfigPath } from "../apps/adapter/dist/config.js";

const MODEL_ALIAS = process.env.BENCHMARK_MODEL_ALIAS;
const UPSTREAM_MODEL = process.env.BENCHMARK_UPSTREAM_MODEL;
const PROMPT_PATH = process.env.BENCHMARK_PROMPT_FILE;
const OUTPUT_PATH = process.env.BENCHMARK_OUTPUT_FILE;
const WORKERS_PLAN = process.env.BENCHMARK_WORKERS_PLAN ?? "unverified";
const MAX_PROMPT_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 310_000;

if (!MODEL_ALIAS || !UPSTREAM_MODEL || !PROMPT_PATH) {
  throw new Error("Set BENCHMARK_MODEL_ALIAS, BENCHMARK_UPSTREAM_MODEL, and BENCHMARK_PROMPT_FILE to run a real Workers benchmark");
}
if (UPSTREAM_MODEL.length > 128 || !/^[A-Za-z0-9._:/-]+$/.test(UPSTREAM_MODEL)) throw new Error("BENCHMARK_UPSTREAM_MODEL must be a short model identifier");
if (WORKERS_PLAN.length > 100 || !/^[A-Za-z0-9 ._-]+$/.test(WORKERS_PLAN)) throw new Error("BENCHMARK_WORKERS_PLAN must be a short label");

const config = await new ConfigStore(defaultConfigPath()).load();
const model = config.models.find((entry) => entry.id === MODEL_ALIAS);
if (!model) throw new Error("BENCHMARK_MODEL_ALIAS is not configured in the local adapter");
const identity = new URL(config.identityUrl);
const gateway = new URL(config.gatewayUrl);
if (identity.protocol !== "https:" || gateway.protocol !== "wss:" || isLoopback(identity.hostname) || isLoopback(gateway.hostname)) {
  throw new Error("Benchmark requires configured remote HTTPS Identity and WSS Gateway services");
}

const promptStat = await stat(PROMPT_PATH);
if (process.platform !== "win32" && (promptStat.mode & 0o077) !== 0) {
  throw new Error("Benchmark prompt file must be owner-only (0600)");
}
const promptBytes = await readFile(PROMPT_PATH);
if (promptBytes.byteLength === 0 || promptBytes.byteLength > MAX_PROMPT_BYTES) {
  throw new Error("Benchmark prompt must contain 1 to 65,536 bytes");
}
const prompt = promptBytes.toString("utf8");
if (!prompt.trim()) throw new Error("Benchmark prompt must contain non-whitespace text");

const baseUrl = `http://127.0.0.1:${config.port}/v1`;
const authHeaders = { authorization: `Bearer ${config.localBearerToken}` };
const modelsResponse = await fetch(`${baseUrl}/models`, { headers: authHeaders, signal: AbortSignal.timeout(10_000) });
if (!modelsResponse.ok) throw new Error(`Local adapter health check failed with HTTP ${modelsResponse.status}`);
if (modelsResponse.headers.get("x-ws-proxy-gateway-session-limit") !== "1") {
  throw new Error("Restart the adapter with WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS=1; benchmark mode requires one Gateway socket");
}
const listedModels = await modelsResponse.json();
if (!Array.isArray(listedModels?.data) || !listedModels.data.some((entry) => entry.id === MODEL_ALIAS)) {
  throw new Error("Local adapter does not advertise the requested benchmark model");
}

const commit = tryGit(["rev-parse", "HEAD"]);
const report = {
  runId: randomUUID(),
  createdAt: new Date().toISOString(),
  commit,
  runtime: { node: process.version, platform: process.platform, architecture: process.arch },
  workers: { plan: WORKERS_PLAN, cpu: "unavailable", memory: "unavailable" },
  measurementScope: "local end-to-end wall-clock through adapter, Gateway, and provider",
  adapter: `http://127.0.0.1:${config.port}`,
  identityOrigin: identity.origin,
  gatewayOrigin: gateway.origin,
  gatewaySessionLimit: 1,
  model: MODEL_ALIAS,
  provider: model.provider,
  declaredUpstreamModel: UPSTREAM_MODEL,
  promptBytes: promptBytes.byteLength,
  promptSha256: createHash("sha256").update(promptBytes).digest("hex"),
  scenarios: [],
};

for (const concurrency of [1, 5, 10]) {
  const results = await Promise.all(Array.from({ length: concurrency }, () => runRequest({ baseUrl, authHeaders, modelAlias: MODEL_ALIAS, prompt })));
  const successful = results.filter((result) => result.success);
  report.scenarios.push({
    concurrency,
    requested: concurrency,
    succeeded: successful.length,
    failed: results.length - successful.length,
    timeToFirstByteMs: summarize(successful.map((result) => result.timeToFirstByteMs)),
    timeToFirstContentMs: summarize(successful.map((result) => result.timeToFirstContentMs)),
    totalMs: summarize(successful.map((result) => result.totalMs)),
    results,
  });
}

const serialized = `${JSON.stringify(report, null, 2)}\n`;
if (OUTPUT_PATH) {
  const outputPath = path.resolve(OUTPUT_PATH);
  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const file = await open(outputPath, "wx", 0o600);
  try {
    await file.writeFile(serialized, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
  if (process.platform !== "win32") await chmod(outputPath, 0o600);
  process.stdout.write(`Saved real Workers benchmark report to ${outputPath}\n`);
} else {
  process.stdout.write(serialized);
}

if (report.scenarios.every((scenario) => scenario.succeeded === 0)) process.exitCode = 1;

async function runRequest({ baseUrl, authHeaders, modelAlias, prompt }) {
  const startedAt = performance.now();
  let timeToFirstByteMs;
  let timeToFirstContentMs;
  let totalBytes = 0;
  let eventCount = 0;
  let done = false;
  let errorCode;
  let httpStatus;
  try {
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: { ...authHeaders, "content-type": "application/json", accept: "text/event-stream" },
      body: JSON.stringify({ model: modelAlias, messages: [{ role: "user", content: prompt }], stream: true }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    httpStatus = response.status;
    if (!response.body) throw new Error("missing_response_body");
    if (!response.ok) {
      errorCode = await readJsonErrorCode(response);
    } else {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let eventData = [];
      let eventChars = 0;
      while (true) {
        const { value, done: readerDone } = await reader.read();
        if (readerDone) break;
        if (!value || value.byteLength === 0) continue;
        if (timeToFirstByteMs === undefined) timeToFirstByteMs = rounded(performance.now() - startedAt);
        totalBytes += value.byteLength;
        buffer += decoder.decode(value, { stream: true });
        if (buffer.length > 1_048_576) throw new Error("local_sse_event_exceeded_limit");
        const lines = takeCompleteLines(buffer);
        buffer = lines.rest;
        for (const line of lines.complete) {
          if (line === "") {
            const data = eventData.join("\n");
            if (data) {
              eventCount += 1;
              if (data === "[DONE]") done = true;
              else {
                const payload = parseEventJson(data);
                if (payload?.error?.code && typeof payload.error.code === "string") errorCode = payload.error.code;
                const choices = Array.isArray(payload?.choices) ? payload.choices : [];
                if (choices.some((choice) => hasContent(choice?.delta)) && timeToFirstContentMs === undefined) {
                  timeToFirstContentMs = rounded(performance.now() - startedAt);
                }
              }
            }
            eventData = [];
            eventChars = 0;
          } else if (line.startsWith("data:")) {
            const data = line.slice(5).replace(/^ /, "");
            eventChars += data.length + 1;
            if (eventChars > 1_048_576) throw new Error("local_sse_event_exceeded_limit");
            eventData.push(data);
          }
        }
      }
      buffer += decoder.decode();
      if (buffer.length > 0 && buffer.startsWith("data:")) eventData.push(buffer.slice(5).replace(/^ /, ""));
    }
    const totalMs = rounded(performance.now() - startedAt);
    return {
      success: response.ok && done && !errorCode,
      httpStatus,
      eventCount,
      totalBytes,
      timeToFirstByteMs: timeToFirstByteMs ?? null,
      timeToFirstContentMs: timeToFirstContentMs ?? null,
      totalMs,
      ...(errorCode ? { errorCode } : !done && response.ok ? { errorCode: "missing_done" } : {}),
    };
  } catch (error) {
    const totalMs = rounded(performance.now() - startedAt);
    return {
      success: false,
      httpStatus: httpStatus ?? null,
      eventCount,
      totalBytes,
      timeToFirstByteMs: timeToFirstByteMs ?? null,
      timeToFirstContentMs: timeToFirstContentMs ?? null,
      totalMs,
      errorCode: error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : "request_failed",
    };
  }
}

async function readJsonErrorCode(response) {
  try {
    const payload = await response.json();
    const code = payload?.error?.code;
    return typeof code === "string" && /^[a-z0-9_]+$/.test(code) ? code : `http_${response.status}`;
  } catch {
    return `http_${response.status}`;
  }
}

function takeCompleteLines(input) {
  const complete = [];
  let start = 0;
  for (let index = 0; index < input.length; index += 1) {
    if (input[index] !== "\n" && input[index] !== "\r") continue;
    if (input[index] === "\r" && index + 1 === input.length) break;
    complete.push(input.slice(start, index));
    if (input[index] === "\r" && input[index + 1] === "\n") index += 1;
    start = index + 1;
  }
  return { complete, rest: input.slice(start) };
}

function parseEventJson(data) {
  try {
    return JSON.parse(data);
  } catch {
    return undefined;
  }
}

function hasContent(delta) {
  return typeof delta?.content === "string" && delta.content.length > 0
    || typeof delta?.refusal === "string" && delta.refusal.length > 0
    || Array.isArray(delta?.tool_calls) && delta.tool_calls.length > 0;
}

function summarize(values) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return {
    min: sorted[0],
    p50: percentile(sorted, 0.5),
    p95: percentile(sorted, 0.95),
    max: sorted.at(-1),
  };
}

function percentile(sorted, fraction) {
  return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
}

function rounded(value) {
  return Math.round(value * 100) / 100;
}

function tryGit(args) {
  try {
    return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function isLoopback(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}
