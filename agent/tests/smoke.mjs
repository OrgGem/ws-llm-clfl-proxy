import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";

const root = fileURLToPath(new URL("../../", import.meta.url));
const metadata = JSON.parse(execFileSync(process.env.CARGO ?? "cargo", [
  "metadata", "--manifest-path", path.join(root, "agent/Cargo.toml"),
  "--no-deps", "--format-version", "1",
], { encoding: "utf8", maxBuffer: 1_048_576, stdio: ["ignore", "pipe", "pipe"] }));
const binary = path.join(metadata.target_directory, "debug", process.platform === "win32" ? "ws-llm-agent.exe" : "ws-llm-agent");

for (const scenario of ["success", "error", "disconnect", "cancel"]) {
  const directory = await mkdtemp(path.join(tmpdir(), "native-agent-wire-"));
  let starts = 0;
  let acknowledged = false;
  let cancelled = false;
  let peerClosed = false;
  const identity = createServer((request, response) => {
    assert.equal(request.url, "/oauth/token");
    assert.equal(request.headers.authorization, `Basic ${Buffer.from("fixture-client:fixture-secret").toString("base64")}`);
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ access_token: "fixture-access-token", token_type: "Bearer", expires_in: 300 }));
  });
  await new Promise((resolve) => identity.listen(0, "127.0.0.1", resolve));
  const gateway = new WebSocketServer({ port: 0, host: "127.0.0.1" });
  await new Promise((resolve) => gateway.once("listening", resolve));
  gateway.on("connection", (socket, request) => {
    assert.equal(request.headers.authorization, "Bearer fixture-access-token");
    assert.equal(request.url, "/v1/socket");
    assert.equal(request.headers["sec-websocket-protocol"], "llm-proxy.v1");
    socket.on("close", () => { peerClosed = true; });
    socket.send(JSON.stringify({
      event: "session.ready", protocol: 1, connectionId: "native-fixture",
      maxInFlight: 1, maxPayloadBytes: 1_048_576, maxSessionSeconds: 300,
      maxChunkBytes: 32_768, ackWindow: 8, maxRequestFrameBytes: 1_048_576,
      maxResponseFrameBytes: 262_144, tokenExpiresAt: Math.floor(Date.now() / 1000) + 300,
    }));
    socket.on("message", (raw) => {
      const frame = JSON.parse(raw.toString());
      if (frame.event === "request.cancel") { cancelled = true; return; }
      if (frame.event !== "request.start") return;
      if (frame.op === "ack") { acknowledged = true; return; }
      starts += 1;
      assert.equal(frame.model, "fixture-alias");
      assert.equal(frame.provider, "open-code");
      assert.equal(frame.envelope.credentialId, "cred_fixture");
      assert.equal(frame.payload.model, undefined);
      assert.equal(frame.payload.stream, undefined);
      assert.equal(frame.payload.messages.at(-1).content, "fixture task");
      assert.ok(!frame.payload.tools || frame.payload.tools.length === 0);
      if (scenario === "error") {
        socket.send(JSON.stringify({ event: "response.error", requestId: frame.requestId, lastSeq: -1,
          code: "upstream_error", message: "private-provider-error-sentinel", upstreamStarted: true, retryable: true }));
        return;
      }
      const chunk = { choices: [{ index: 0, delta: { content: "fixture answer" }, finish_reason: null }] };
      const finish = { choices: [{ index: 0, delta: {}, finish_reason: "stop" }] };
      const data = `data: ${JSON.stringify(chunk)}\n\n`
        + (scenario === "success" ? `data: ${JSON.stringify(finish)}\n\ndata: [DONE]\n\n` : "");
      socket.send(JSON.stringify({ event: "response.chunk", requestId: frame.requestId, seq: 0, data }));
      if (scenario === "success") socket.send(JSON.stringify({ event: "response.end", requestId: frame.requestId, lastSeq: 0 }));
      if (scenario === "disconnect") socket.close();
    });
  });
  try {
    const envelope = { v: 1, alg: "A256GCM", kid: "fixture-key", credentialId: "cred_fixture",
      userId: "usr_fixture", projectId: "prj_fixture", provider: "open-code",
      exp: Math.floor(Date.now() / 1000) + 3600, nonce: "AAAAAAAAAAAAAAAA", ciphertext: "AAAAAAAAAAAAAAAAAAAAAA" };
    await writeFile(path.join(directory, "envelope.json"), JSON.stringify(envelope), { mode: 0o600 });
    const settings = { WS_PROXY_CONFIG_SOURCE: "env", WS_PROXY_IDENTITY_URL: `http://127.0.0.1:${identity.address().port}`,
      WS_PROXY_GATEWAY_URL: `ws://127.0.0.1:${gateway.address().port}/v1/socket`, WS_PROXY_CLIENT_ID: "fixture-client",
      WS_PROXY_CLIENT_SECRET: "fixture-secret", WS_PROXY_ENVELOPE_FILE: path.join(directory, "envelope.json"),
      WS_PROXY_MODEL_ALIAS: "fixture-alias", WS_PROXY_PROVIDER: "open-code", WS_PROXY_PROTOCOL: "openai" };
    const envFile = path.join(directory, ".env");
    await writeFile(envFile, Object.entries(settings).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join("\n"), { mode: 0o600 });
    const env = { ...process.env, NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" };
    for (const key of Object.keys(env)) if (key.startsWith("WS_PROXY_")) delete env[key];
    const result = await new Promise((resolve, reject) => {
      const child = spawn(binary, ["--config-env", envFile], { cwd: root, env, stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "", stderr = "", interrupted = false;
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("native CLI smoke timed out")); }, 15_000);
      child.stdout.on("data", (data) => {
        stdout += data;
        if (scenario === "cancel" && !interrupted && stdout.includes("fixture answer")) {
          interrupted = true;
          child.kill("SIGINT");
        }
      });
      child.stderr.on("data", (data) => { stderr += data; });
      child.once("error", () => { clearTimeout(timer); reject(new Error("build the native agent before running its smoke test")); });
      child.once("close", (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
      child.stdin.on("error", () => {});
      child.stdin.end("fixture task");
    });
    assert.equal(starts, 1, "a failed or interrupted generation must never be retried silently");
    assert.ok(!result.stderr.includes("private-provider-error-sentinel"));
    assert.ok(!result.stderr.includes("fixture-secret"));
    if (scenario === "success") {
      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.stdout, "fixture answer");
      assert.equal(result.stderr, "");
      assert.ok(acknowledged);
    } else {
      assert.notEqual(result.code, 0);
      if (scenario === "error") assert.equal(result.stdout, "");
      if (scenario === "cancel") {
        assert.equal(result.code, 130);
        assert.ok(cancelled || peerClosed, "cancellation must reach the Gateway");
      }
    }
    console.log(`PASS native agent: ${scenario}`);
  } finally {
    gateway.clients.forEach((socket) => socket.terminate());
    await new Promise((resolve) => gateway.close(resolve));
    await new Promise((resolve) => identity.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}
