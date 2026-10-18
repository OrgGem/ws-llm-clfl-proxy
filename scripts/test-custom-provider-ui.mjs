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
const projectId = "prj_ui_custom_provider";
const csrfToken = "mock-admin-csrf";
const providers = [
  { provider: "openai", id: "openai", displayName: "OpenAI", protocol: "openai", baseUrl: "https://api.openai.com/v1/", custom: false, enabled: true, models: [] },
  { provider: "anthropic", id: "anthropic", displayName: "Anthropic", protocol: "anthropic", baseUrl: "https://api.anthropic.com/v1/", custom: false, enabled: true, models: [] },
];
const registrations = [];
const providerUpdates = [];
const serverErrors = [];
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname.startsWith("/api/")) {
      res.setHeader("Content-Type", "application/json");
      let value;
      let status = 200;
      if (url.pathname === "/api/session" && req.method === "GET") {
        value = {
          authenticated: true,
          csrfToken,
          user: { id: "usr_ui_admin", email: "admin@example.test", displayName: "UI Admin", isAdmin: true },
          projects: [{ id: projectId, name: "UI test project", role: "owner" }],
          activeProjectId: projectId,
          session: { id: "web_ui_admin", kind: "web", expiresAt: Math.floor(Date.now() / 1000) + 3_600 },
        };
      } else if (url.pathname === "/api/dashboard" && req.method === "GET") {
        value = { summary: { activeClients: 0, activeSessions: 0 }, providers, credentials: [] };
      } else if (url.pathname === "/api/providers" && req.method === "GET") {
        value = { providers, credentials: [] };
      } else if (url.pathname === "/api/providers" && req.method === "POST") {
        assert.equal(req.headers["x-csrf-token"], csrfToken, "provider creation must include the session CSRF token");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        registrations.push(body);
        if (body.baseUrl === "https://127.0.0.1/v1/") {
          status = 400;
          value = { error: "endpoint_not_allowed" };
        } else {
          assert.deepEqual(Object.keys(body).sort(), ["baseUrl", "displayName", "id", "protocol"]);
          assert.equal(body.protocol, "openai");
          const provider = {
            id: body.id,
            provider: body.id,
            displayName: body.displayName,
            baseUrl: body.baseUrl,
            protocol: body.protocol,
            custom: true,
            enabled: true,
            models: [],
          };
          providers.push(provider);
          value = { provider };
        }
      } else if (/^\/api\/providers\/[a-z][a-z0-9_-]{0,31}$/.test(url.pathname) && req.method === "PUT") {
        assert.equal(req.headers["x-csrf-token"], csrfToken, "provider enable/disable must include the session CSRF token");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const id = decodeURIComponent(url.pathname.split("/").at(-1));
        providerUpdates.push({ id, body });
        const provider = providers.find((item) => item.id === id);
        if (!provider || Object.keys(body).length !== 1 || typeof body.enabled !== "boolean") {
          status = 400;
          value = { error: "invalid_request" };
        } else {
          provider.enabled = body.enabled;
          value = { provider };
        }
      } else {
        status = 404;
        value = { error: "not_found" };
      }
      res.statusCode = status;
      res.end(JSON.stringify(value));
      return;
    }
    if (url.pathname === "/favicon.ico") { res.writeHead(204).end(); return; }
    const name = url.pathname === "/ui" || url.pathname === "/ui/" ? "index.html" : path.basename(url.pathname);
    if (!/^[a-z.]+$/.test(name)) { res.writeHead(404).end(); return; }
    const contents = await readFile(path.join(publicDir, name));
    res.setHeader("Content-Type", name.endsWith(".js") ? "application/javascript" : name.endsWith(".css") ? "text/css" : "text/html");
    res.end(contents);
  } catch (error) {
    serverErrors.push(error instanceof Error ? error.message : String(error));
    if (!res.headersSent) res.writeHead(500);
    res.end();
  }
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
if (!address || typeof address === "string") throw new Error("Could not start the UI mock server");
const profile = await mkdtemp(path.join(os.tmpdir(), "ws-proxy-custom-provider-ui-"));
const browser = spawn(process.env.CHROMIUM_BIN || "/usr/bin/chromium", [
  "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--remote-debugging-port=0",
  `--user-data-dir=${profile}`, "about:blank",
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
    try {
      const result = await fn();
      if (result) return result;
    } catch { /* Chromium is starting or the view is rerendering. */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Custom provider UI condition timed out");
}

function command(method, params = {}) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const response = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
  return response.result.value;
}

function setField(label, value) {
  return `(() => { const group=[...document.querySelectorAll('.field')].find(x=>x.querySelector('label')?.textContent.trim()===${JSON.stringify(label)}); if(!group) throw Error('Missing field: '+${JSON.stringify(label)}); const input=group.querySelector('input'); input.value=${JSON.stringify(value)}; input.dispatchEvent(new Event('input',{bubbles:true})); input.dispatchEvent(new Event('change',{bubbles:true})); })()`;
}

try {
  const port = await until(async () => (await readFile(path.join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]);
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  ws = new WebSocket(pages.find((page) => page.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.once("open", resolve); ws.once("error", reject); });
  ws.on("message", (data) => {
    const message = JSON.parse(data.toString());
    if (message.method === "Runtime.exceptionThrown") {
      browserExceptions.push(message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text);
    }
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
  });

  await command("Runtime.enable");
  await command("Page.navigate", { url: `http://127.0.0.1:${address.port}/ui` });
  await until(() => evaluate("document.querySelector('.nav-item')?.textContent.includes('Dashboard') && document.querySelector('#app')?.getAttribute('aria-busy')==='false'"));
  await evaluate("[...document.querySelectorAll('.nav-item')].find(button=>button.textContent.includes('Providers')).click()");
  await until(() => evaluate("Boolean([...document.querySelectorAll('h2')].find(node=>node.textContent==='Add a custom provider'))"));

  const providerFormStatus = await evaluate(`(() => {const form=[...document.querySelectorAll('form')].find(f=>f.textContent.includes('Add a custom provider')); return {enabled:!form.querySelector('button[type=submit]').disabled, labels:[...form.querySelectorAll('label')].map(l=>l.textContent.trim())}})()`);
  assert.equal(providerFormStatus.enabled, true);
  assert.deepEqual(providerFormStatus.labels, ["Provider ID", "Display name", "Base URL"]);

  await evaluate(setField("Provider ID", "my_provider"));
  await evaluate(setField("Display name", "My Provider"));
  await evaluate(setField("Base URL", "https://provider.example.org/v1/"));
  await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Register provider').click()");
  await until(() => evaluate("[...document.querySelectorAll('select')].filter(select=>[...select.options].some(option=>option.value==='my_provider')).length===2"));

  assert.deepEqual(registrations[0], {
    id: "my_provider",
    displayName: "My Provider",
    baseUrl: "https://provider.example.org/v1/",
    protocol: "openai",
  });
  assert.equal(await evaluate("[...document.querySelectorAll('select')].filter(select=>[...select.options].some(option=>option.value==='my_provider')).length"), 2, "custom provider should appear in the API-key and model-mapping selectors");
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('https://provider.example.org/v1/')"), true, "registered base URL should be visible in the provider card");

  await evaluate("window.confirm=()=>true");
  await evaluate("[...document.querySelectorAll('.panel')].find(panel=>panel.querySelector('h2')?.textContent==='My Provider').querySelector('button').click()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('Enable provider')"));
  assert.deepEqual(providerUpdates[0], { id: "my_provider", body: { enabled: false } });
  assert.equal(await evaluate("[...document.querySelectorAll('select')].filter(select=>[...select.options].some(option=>option.value==='my_provider')).length"), 0, "disabled provider should leave active key/model selectors");

  await evaluate("[...document.querySelectorAll('.panel')].find(panel=>panel.querySelector('h2')?.textContent==='My Provider').querySelector('button').click()");
  await until(() => evaluate("[...document.querySelectorAll('select')].filter(select=>[...select.options].some(option=>option.value==='my_provider')).length===2"));
  assert.deepEqual(providerUpdates[1], { id: "my_provider", body: { enabled: true } });

  await evaluate(setField("Provider ID", "private_test"));
  await evaluate(setField("Display name", "Private Test"));
  await evaluate(setField("Base URL", "https://127.0.0.1/v1/"));
  await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Register provider').click()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('Private, local, or insecure endpoints are blocked.')"));
  assert.equal(registrations.length, 2, "private URL should be sent only to the mock API for its rejection response");
  assert.equal(await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Register provider').disabled"), false, "register button should recover after an endpoint error");
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('private_test')"), false, "rejected provider should not appear in the provider list");
  assert.deepEqual(serverErrors, []);
  assert.deepEqual(browserExceptions, []);
  console.log("Chromium custom-provider UI passed: admin registration, enable/disable refresh, provider dropdowns, URL display, and private-endpoint error recovery.");
} catch (error) {
  console.error({ browserExceptions, serverErrors, page: ws?.readyState === WebSocket.OPEN ? await evaluate("document.body.innerText") : "unavailable" });
  throw error;
} finally {
  ws?.close();
  browser.kill("SIGKILL");
  await new Promise((resolve) => server.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
