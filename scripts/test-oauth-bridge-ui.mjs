import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";

const publicDir = fileURLToPath(new URL("../apps/identity/public/", import.meta.url));
const projectId = "prj_oauth_ui_test";
const csrfToken = "mock-oauth-csrf";
const pairingToken = "ogt_" + "A".repeat(43);
const pairingId = "pairing_ui_test";
const controlToken = "B".repeat(43);
const apiCalls = [];
const bridgeCalls = [];
const serverErrors = [];
let uiOrigin = "";
let bridgePort = 0;

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const uiServer = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://127.0.0.1");
    let payload;
    if (url.pathname.startsWith("/api/")) {
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.setHeader("content-security-policy", "default-src 'self'; connect-src 'self'");
      if (url.pathname === "/api/session" && req.method === "GET") {
        payload = {
          authenticated: true, csrfToken,
          user: { id: "usr_oauth_ui", email: "oauth-ui@example.test", displayName: "OAuth UI Test", isAdmin: false },
          projects: [{ id: projectId, name: "OAuth UI project", role: "owner" }],
          activeProjectId: projectId,
          session: { id: "web_oauth_ui", kind: "web", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
        };
      } else if (url.pathname === "/api/dashboard" && req.method === "GET") {
        payload = { summary: { activeClients: 0, activeSessions: 0 }, providers: [], credentials: [] };
      } else if (url.pathname === "/api/oauth/connectors" && req.method === "GET") {
        payload = { connectors: [
          { id: "chatgpt", provider: "openai", localOAuth: { enabled: true }, remoteInference: { enabled: false, reasonCode: "eligibility_pending" } },
          { id: "claude", provider: "anthropic", localOAuth: { enabled: false, reasonCode: "subscription_oauth_unavailable" }, remoteInference: { enabled: false, reasonCode: "subscription_oauth_unavailable" } },
        ] };
      } else if (url.pathname === "/api/oauth/pairing" && req.method === "POST") {
        assert.equal(req.headers["x-csrf-token"], csrfToken, "Identity pairing must include CSRF protection");
        const body = await readBody(req);
        apiCalls.push({ path: url.pathname, body });
        assert.deepEqual(body, { projectId, connectorId: "chatgpt" });
        payload = { pairingToken, expiresAt: Math.floor(Date.now() / 1000) + 120 };
      } else {
        res.statusCode = 404;
        payload = { error: "not_found" };
      }
      res.end(JSON.stringify(payload));
      return;
    }
    if (url.pathname === "/favicon.ico") { res.writeHead(204).end(); return; }
    const name = url.pathname === "/ui" || url.pathname === "/ui/" ? "index.html" : path.basename(url.pathname);
    if (!/^[a-z.]+$/.test(name)) { res.writeHead(404).end(); return; }
    const contents = await readFile(path.join(publicDir, name));
    res.setHeader("content-type", name.endsWith(".js") ? "application/javascript" : name.endsWith(".css") ? "text/css" : "text/html");
    if (name === "index.html") {
      res.setHeader("content-security-policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:*");
    } else res.setHeader("content-security-policy", "default-src 'self'; connect-src 'self'");
    res.setHeader("cache-control", "no-store");
    res.end(contents);
  } catch (error) {
    serverErrors.push(error instanceof Error ? error.message : String(error));
    if (!res.headersSent) res.writeHead(500);
    res.end();
  }
});

const bridgeServer = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.headers.origin !== uiOrigin || req.headers.host !== "127.0.0.1:" + bridgePort) {
      res.writeHead(403).end(JSON.stringify({ error: { code: "forbidden" } }));
      return;
    }
    res.setHeader("access-control-allow-origin", uiOrigin);
    res.setHeader("vary", "Origin");
    res.setHeader("cache-control", "no-store");
    if (req.method === "OPTIONS") {
      const requestedMethod = req.headers["access-control-request-method"];
      const requestedHeaders = req.headers["access-control-request-headers"];
      const headerNames = typeof requestedHeaders === "string" ? requestedHeaders.split(",").map((header) => header.trim().toLowerCase()) : [];
      if (!["GET", "POST"].includes(requestedMethod) || headerNames.length > 2 || !headerNames.every((header) => header === "authorization" || header === "content-type")) {
        res.writeHead(403).end();
        return;
      }
      res.setHeader("access-control-allow-methods", requestedMethod);
      res.setHeader("access-control-allow-headers", "authorization, content-type");
      res.setHeader("access-control-max-age", "300");
      if (req.headers["access-control-request-private-network"] === "true") res.setHeader("access-control-allow-private-network", "true");
      res.writeHead(204).end();
      return;
    }
    const protectedRoute = ["/local/oauth/status", "/local/oauth/models", "/local/oauth/model"];
    if (protectedRoute.includes(url.pathname)) assert.equal(req.headers.authorization, "Bearer " + controlToken);
    if (url.pathname === "/local/oauth/health" && req.method === "GET") {
      res.end(JSON.stringify({ reachable: true, oauthAvailable: true }));
    } else if (url.pathname === "/local/oauth/pair/start" && req.method === "POST") {
      const body = await readBody(req);
      bridgeCalls.push({ path: url.pathname, body });
      assert.deepEqual(body, { pairingToken });
      res.writeHead(202).end(JSON.stringify({ pairingId, expiresAt: Math.floor(Date.now() / 1000) + 120 }));
    } else if (url.pathname === "/local/oauth/pair/approve" && req.method === "POST") {
      const body = await readBody(req);
      bridgeCalls.push({ path: url.pathname, body });
      assert.deepEqual(body, { pairingId, approvalCode: "12345678" });
      res.end(JSON.stringify({ controlToken, expiresAt: Math.floor(Date.now() / 1000) + 600, authorizationUrl: "https://auth.openai.com/api/accounts/authorize?state=safe" }));
    } else if (url.pathname === "/local/oauth/status" && req.method === "GET") {
      res.end(JSON.stringify({ status: "connected", email: "person@example.test", modelsAvailable: 1 }));
    } else if (url.pathname === "/local/oauth/models" && req.method === "GET") {
      res.end(JSON.stringify({
        models: [{ id: "gpt-safe-model", displayName: "Safe model", contextWindow: 128000, inputModalities: ["text", "image"], reasoningEfforts: ["low", "high"] }],
        boundAliases: ["project-openai-alias"],
      }));
    } else if (url.pathname === "/local/oauth/model" && req.method === "POST") {
      const body = await readBody(req);
      bridgeCalls.push({ path: url.pathname, body });
      res.end(JSON.stringify({ alias: body.alias, bound: true }));
    } else {
      res.writeHead(404).end(JSON.stringify({ error: { code: "not_found" } }));
    }
  } catch (error) {
    serverErrors.push(error instanceof Error ? error.message : String(error));
    if (!res.headersSent) res.writeHead(500);
    res.end();
  }
});

await new Promise((resolve) => uiServer.listen(0, "127.0.0.1", resolve));
const uiAddress = uiServer.address();
if (!uiAddress || typeof uiAddress === "string") throw new Error("Could not start UI mock server");
uiOrigin = "http://127.0.0.1:" + uiAddress.port;
await new Promise((resolve) => bridgeServer.listen(0, "127.0.0.1", resolve));
const bridgeAddress = bridgeServer.address();
if (!bridgeAddress || typeof bridgeAddress === "string") throw new Error("Could not start the loopback OAuth mock");
bridgePort = bridgeAddress.port;

const profile = await mkdtemp(path.join(os.tmpdir(), "ws-proxy-oauth-ui-"));
const browser = spawn(process.env.CHROMIUM_BIN || "/usr/bin/chromium", [
  "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--remote-debugging-port=0",
  "--user-data-dir=" + profile, "about:blank",
], { stdio: "ignore" });
let browserError;
browser.on("error", (error) => { browserError = error; });
let ws;
let nextId = 0;
const pending = new Map();
const browserExceptions = [];

async function until(fn) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (browserError) throw browserError;
    try { const result = await fn(); if (result) return result; } catch { /* browser starting or rerendering */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("OAuth bridge UI condition timed out");
}

function command(method, params = {}) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const result = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
  return result.result.value;
}

try {
  const devtoolsPort = await until(async () => (await readFile(path.join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]);
  const pages = await (await fetch("http://127.0.0.1:" + devtoolsPort + "/json/list")).json();
  ws = new WebSocket(pages.find((page) => page.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.once("open", resolve); ws.once("error", reject); });
  ws.on("message", (data) => {
    const message = JSON.parse(data.toString());
    if (message.method === "Runtime.exceptionThrown") browserExceptions.push(message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text);
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error.message)); else request.resolve(message.result);
  });
  await command("Runtime.enable");
  await command("Page.navigate", { url: uiOrigin + "/ui" });
  await until(() => evaluate("document.querySelector('#app')?.getAttribute('aria-busy')==='false' && [...document.querySelectorAll('.nav-item')].some(button=>button.textContent.includes('Connections'))"));
  const htmlResponse = await fetch(uiOrigin + "/ui");
  assert.ok(htmlResponse.headers.get("content-security-policy")?.includes("http://127.0.0.1:*"), "UI CSP must allow only the loopback bridge host");
  const scriptResponse = await fetch(uiOrigin + "/ui/app.js");
  assert.equal(scriptResponse.headers.get("content-security-policy"), "default-src 'self'; connect-src 'self'", "script and API responses must retain self-only connect-src");
  const apiResponse = await fetch(uiOrigin + "/api/session");
  assert.equal(apiResponse.headers.get("content-security-policy"), "default-src 'self'; connect-src 'self'", "API responses must retain self-only connect-src");
  await evaluate("[...document.querySelectorAll('.nav-item')].find(button=>button.textContent.includes('Connections')).click()");
  await until(() => evaluate("[...document.querySelectorAll('h2')].some(node=>node.textContent==='ChatGPT')"));
  const initialText = await evaluate("document.querySelector('.content').innerText");
  assert.match(initialText, /eligibility is pending/i);
  assert.match(initialText, /Claude subscription OAuth/i);
  assert.match(initialText, /unavailable/i);

  await evaluate("(() => {const input=document.querySelector('[aria-label=\"Local adapter port\"]');input.value=" + JSON.stringify(String(bridgePort)) + ";input.dispatchEvent(new Event('input',{bubbles:true}))})()");
  await evaluate("[...document.querySelectorAll('button')].find(button=>button.textContent==='Check local adapter').click()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('exact-origin bridge health check')"));
  await evaluate("[...document.querySelectorAll('button')].find(button=>button.textContent==='Connect ChatGPT').click()");
  await until(() => evaluate("Boolean(document.querySelector('input[autocomplete=one-time-code]'))"));
  assert.equal(apiCalls.length, 1);
  assert.deepEqual(bridgeCalls[0], { path: "/local/oauth/pair/start", body: { pairingToken } });

  await evaluate("(() => {window.confirm=()=>true; const input=document.querySelector('input[autocomplete=one-time-code]');input.value='12345678';input.dispatchEvent(new Event('input',{bubbles:true}));input.closest('form').requestSubmit()})()");
  await until(() => evaluate("Boolean([...document.querySelectorAll('a')].find(link=>link.textContent==='Open ChatGPT sign-in'))"));
  await evaluate("(() => {const input=document.querySelector('[aria-label=\"Local adapter port\"]');input.value='1';input.dispatchEvent(new Event('input',{bubbles:true}))})()");
  await evaluate("[...document.querySelectorAll('button')].find(button=>button.textContent==='Check sign-in status and models').click()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('gpt-safe-model')"));
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('accessToken')"), false);
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('project-openai-alias')"), true);

  await until(() => evaluate("Boolean([...document.querySelectorAll('button')].find(button=>button.textContent==='Bind local profile'&&!button.disabled))"));
  await evaluate("(() => {window.confirm=()=>true;const field=document.querySelector('[aria-label=\"Existing OpenAI project model alias\"]');field.value='project-openai-alias';field.dispatchEvent(new Event('input',{bubbles:true}));[...document.querySelectorAll('button')].find(button=>button.textContent==='Bind local profile').click()})()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('Identity still checks this user')"));
  assert.deepEqual(bridgeCalls.at(-1), { path: "/local/oauth/model", body: { alias: "project-openai-alias" } });
  assert.equal(apiCalls.some((call) => JSON.stringify(call).includes(pairingToken)), false, "Identity does not receive the pairing token again after local redeem");
  assert.equal(bridgeCalls.some((call) => JSON.stringify(call).includes("accessToken")), false, "Provider tokens never enter bridge payloads");
  assert.deepEqual(serverErrors, []);
  assert.deepEqual(browserExceptions, []);
  console.log("Chromium OAuth bridge UI passed: exact-origin loopback, pairing and local code approval, safe model discovery, pending/Claude states, and confirmed alias mapping.");
} catch (error) {
  console.error({ browserExceptions, serverErrors, apiCalls, bridgeCalls, page: ws?.readyState === WebSocket.OPEN ? await evaluate("document.body.innerText") : "unavailable" });
  throw error;
} finally {
  ws?.close();
  browser.kill("SIGKILL");
  await new Promise((resolve) => uiServer.close(resolve));
  await new Promise((resolve) => bridgeServer.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
