import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";

// Real Chromium DOM against a loopback-only mock Identity API. No live secrets.
const publicDir = fileURLToPath(new URL("../apps/identity/public/", import.meta.url));
let authenticated = false;
let saved = false;
const config = { providers: [], bootstrapAdminEmails: [], allowedIssuers: ["https://accounts.google.com/"], redirectUri: "https://identity.test/auth/oidc/callback" };
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname.startsWith("/api/")) {
      res.setHeader("Content-Type", "application/json");
      let value;
      if (url.pathname === "/api/session") value = { authenticated: false, authSetupRequired: !saved, loginProviders: config.providers };
      else if (url.pathname === "/api/setup/status") value = { bootstrapAvailable: true, authenticated, csrfToken: authenticated ? "mock-csrf" : undefined, ...config };
      else if (url.pathname === "/api/setup/login") { authenticated = true; value = { csrfToken: "mock-csrf", expiresAt: 4_000_000_000 }; }
      else if (url.pathname === "/api/setup/logout") { authenticated = false; value = { ok: true }; }
      else if (url.pathname === "/api/setup/oidc" && req.method === "PUT") {
        assert.equal(req.headers["x-csrf-token"], "mock-csrf");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        assert.equal(body.providers[0].clientSecret, "mock-oidc-secret");
        config.providers = body.providers.map(({ clientSecret, ...provider }) => ({ ...provider, hasClientSecret: Boolean(clientSecret) }));
        config.bootstrapAdminEmails = body.bootstrapAdminEmails;
        saved = true;
        value = config;
      } else if (url.pathname === "/api/setup/oidc") value = config;
      else { res.statusCode = 404; value = { error: "not_found" }; }
      res.end(JSON.stringify(value));
      return;
    }
    const name = url.pathname === "/ui" ? "index.html" : url.pathname.replace(/^\/ui\//, "");
    if (!/^[a-z.]+$/.test(name)) { res.writeHead(404).end(); return; }
    const contents = await readFile(path.join(publicDir, name));
    res.setHeader("Content-Type", name.endsWith(".js") ? "application/javascript" : name.endsWith(".css") ? "text/css" : "text/html");
    res.end(contents);
  } catch { res.writeHead(500).end(); }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const profile = await mkdtemp(path.join(os.tmpdir(), "ws-proxy-ui-"));
const browser = spawn(process.env.CHROMIUM_BIN || "/usr/bin/chromium", ["--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: "ignore" });
let browserError;
browser.on("error", error => { browserError = error; });
let ws;
let id = 0;
const pending = new Map();
const browserExceptions = [];
async function until(fn) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (browserError) throw browserError;
    try { const result = await fn(); if (result) return result; } catch { /* browser starting or DOM transitioning */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("Browser setup UI condition timed out");
}
function command(method, params = {}) {
  const requestId = ++id;
  return new Promise((resolve, reject) => {
    pending.set(requestId, { resolve, reject });
    ws.send(JSON.stringify({ id: requestId, method, params }));
  });
}
async function evaluate(expression) {
  const r = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
  return r.result.value;
}
try {
  const port = await until(async () => (await readFile(path.join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]);
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  ws = new WebSocket(pages.find(p => p.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.once("open", resolve); ws.once("error", reject); });
  ws.on("message", data => {
    const message = JSON.parse(data.toString());
    if (message.method === "Runtime.exceptionThrown") browserExceptions.push(message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text);
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error.message)); else request.resolve(message.result);
  });
  await command("Runtime.enable");
  await command("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/ui` });
  await until(() => evaluate("Boolean(document.querySelector('input[name=setup-password]'))"));
  await evaluate("document.querySelector('input[name=setup-password]').value='mock-password'; document.querySelector('.setup-login-form').requestSubmit()");
  await until(() => evaluate("Boolean(document.querySelector('.setup-config-form')) && document.querySelector('#app').getAttribute('aria-busy') === 'false'"));
  assert.equal(await evaluate("[...document.querySelectorAll('.setup-config-form button')].every(b=>!b.disabled)"), true, "setup buttons must be enabled after login");
  assert.equal(await evaluate("document.querySelector('.setup-config-form input').value"), "google", "canonical Google issuer uses Google defaults");
  await evaluate(`(() => {const set=(label,value)=>{const l=[...document.querySelectorAll('label')].find(l=>l.textContent===label);document.getElementById(l.htmlFor).value=value;};set('OAuth client ID','mock-client');set('OAuth client secret','mock-oidc-secret');set('Bootstrap admin email addresses','owner@example.test');document.querySelector('.setup-config-form').requestSubmit();})()`);
  await until(() => saved && evaluate("document.querySelector('#app').getAttribute('aria-busy') === 'false'"));
  assert.equal(await evaluate("[...document.querySelectorAll('.setup-config-form button')].every(b=>!b.disabled)"), true, "setup buttons must be enabled after save");
  assert.equal(await evaluate("document.querySelector('.setup-config-form input[type=password]').value"), "", "client secret must clear after save");
  await command("Page.reload");
  await until(() => evaluate("Boolean(document.querySelector('.setup-config-form')) && document.querySelector('#app').getAttribute('aria-busy') === 'false'"));
  assert.equal(await evaluate("[...document.querySelectorAll('.setup-config-form button')].every(b=>!b.disabled)"), true, "restored setup buttons must be enabled");
  await evaluate("[...document.querySelectorAll('button')].find(b=>b.textContent==='Sign out of setup').click()");
  await until(() => evaluate("Boolean(document.querySelector('input[name=setup-password]'))"));
  console.log("Chromium setup UI passed: login, enabled controls, Google defaults, save, secret clearing, reload and logout.");
} catch (error) {
  console.error({ browserExceptions, page: ws?.readyState === WebSocket.OPEN ? await evaluate("document.body.innerText") : "unavailable" });
  throw error;
} finally {
  ws?.close();
  browser.kill("SIGKILL");
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
