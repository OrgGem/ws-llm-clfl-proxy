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
const credentialRequests = [];
const serverErrors = [];
let sessionIsAdmin = true;
let simulateCredentialConflict = true;
let simulateProviderUpdateConflict = false;
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
          user: { id: "usr_ui_admin", email: "admin@example.test", displayName: "UI Admin", isAdmin: sessionIsAdmin },
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
      } else if (url.pathname === "/api/credentials" && req.method === "POST") {
        assert.equal(req.headers["x-csrf-token"], csrfToken, "credential enrollment must include the session CSRF token");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        credentialRequests.push(body);
        if (simulateCredentialConflict) {
          simulateCredentialConflict = false;
          const custom = providers.find((provider) => provider.id === "my_provider");
          custom.baseUrl = "https://credential-raced.example.net/v1/";
          status = 409;
          value = { error: "provider_conflict" };
        } else {
          value = { credential: { id: "cred_ui_test" } };
        }
      } else if (/^\/api\/providers\/[a-z][a-z0-9_-]{0,31}$/.test(url.pathname) && req.method === "PUT") {
        assert.equal(req.headers["x-csrf-token"], csrfToken, "provider updates must include the session CSRF token");
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const id = decodeURIComponent(url.pathname.split("/").at(-1));
        providerUpdates.push({ id, body });
        const provider = providers.find((item) => item.id === id);
        if (!provider) {
          status = 400;
          value = { error: "invalid_request" };
        } else if (Object.keys(body).sort().join(",") === "baseUrl,expectedBaseUrl" && provider.custom === true) {
          if (simulateProviderUpdateConflict) {
            simulateProviderUpdateConflict = false;
            provider.baseUrl = "https://concurrent-provider.example.net/v1/";
            status = 409;
            value = { error: "provider_conflict" };
          } else if (body.expectedBaseUrl !== provider.baseUrl) {
            status = 409;
            value = { error: "provider_conflict" };
          } else {
            const oldOrigin = new URL(provider.baseUrl).origin;
            const newOrigin = new URL(body.baseUrl).origin;
            provider.baseUrl = body.baseUrl;
            value = { provider, revokedCredentialCount: oldOrigin === newOrigin ? 0 : 4 };
          }
        } else if (Object.keys(body).length === 1 && typeof body.enabled === "boolean") {
          provider.enabled = body.enabled;
          value = { provider };
        } else {
          status = 400;
          value = { error: "invalid_request" };
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

function setField(label, value, root = "document") {
  return `(() => { const group=[...${root}.querySelectorAll('.field')].find(x=>x.querySelector('label')?.textContent.trim()===${JSON.stringify(label)}); if(!group) throw Error('Missing field: '+${JSON.stringify(label)}); const input=group.querySelector('input'); input.value=${JSON.stringify(value)}; input.dispatchEvent(new Event('input',{bubbles:true})); input.dispatchEvent(new Event('change',{bubbles:true})); })()`;
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

  await evaluate("window.__confirmMessages=[];window.confirm=(message)=>{window.__confirmMessages.push(message);return true}");
  await evaluate("[...document.querySelectorAll('.panel')].find(panel=>panel.querySelector('h2')?.textContent==='My Provider').querySelector('button').click()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('Enable provider')"));
  assert.deepEqual(providerUpdates[0], { id: "my_provider", body: { enabled: false } });
  assert.equal(await evaluate("[...document.querySelectorAll('select')].filter(select=>[...select.options].some(option=>option.value==='my_provider')).length"), 0, "disabled provider should leave active key/model selectors");

  await evaluate("[...document.querySelectorAll('.panel')].find(panel=>panel.querySelector('h2')?.textContent==='My Provider').querySelector('button').click()");
  await until(() => evaluate("[...document.querySelectorAll('select')].filter(select=>[...select.options].some(option=>option.value==='my_provider')).length===2"));
  assert.deepEqual(providerUpdates[1], { id: "my_provider", body: { enabled: true } });

  const providerCard = "[...document.querySelectorAll('.panel')].find(panel=>panel.querySelector('h2')?.textContent==='My Provider')";
  assert.equal(await evaluate(`${providerCard}.querySelector('button[aria-expanded]')?.textContent`), "Edit Base URL", "custom provider editor should be available to system admins");
  assert.equal(await evaluate("[...document.querySelectorAll('.panel')].find(panel=>panel.querySelector('h2')?.textContent==='OpenAI')?.innerText.includes('Edit Base URL') ?? false"), false, "built-in endpoint should not be editable");

  const updateCountBeforeCancel = providerUpdates.length;
  await evaluate(`${providerCard}.querySelector('button[aria-expanded]').click()`);
  await until(() => evaluate(`${providerCard}.querySelector('.provider-base-url-editor input')?.value==='https://provider.example.org/v1/'`));
  assert.equal(await evaluate(`${providerCard}.querySelector('.provider-base-url-editor button[type=submit]').disabled || ${providerCard}.querySelector('.provider-base-url-editor button[type=button]').disabled`), false, "save and cancel controls should be enabled while idle");
  await evaluate(`${providerCard}.querySelector('.provider-base-url-editor button[type=button]').click()`);
  assert.equal(providerUpdates.length, updateCountBeforeCancel, "cancel should not send an endpoint update");

  await evaluate(`${providerCard}.querySelector('button[aria-expanded]').click()`);
  await evaluate(setField("Base URL", "https://provider.example.org/v1/compatible/", `${providerCard}.querySelector('.provider-base-url-editor')`));
  await evaluate(`${providerCard}.querySelector('.provider-base-url-editor button[type=submit]').click()`);
  await until(() => evaluate("document.querySelector('.content').innerText.includes('https://provider.example.org/v1/compatible/')"));
  assert.deepEqual(providerUpdates[2], {
    id: "my_provider",
    body: { baseUrl: "https://provider.example.org/v1/compatible/", expectedBaseUrl: "https://provider.example.org/v1/" },
  });
  const sameOriginConfirmation = await evaluate("window.__confirmMessages.at(-1)");
  assert.match(sameOriginConfirmation, /origin is unchanged.*credential envelopes will be retained/i, "same-origin update confirmation must explain credential retention");
  assert.ok(sameOriginConfirmation.includes("https://provider.example.org/v1/") && sameOriginConfirmation.includes("https://provider.example.org/v1/compatible/"), "same-origin confirmation should show both URLs");
  assert.equal(await evaluate("document.querySelector('#live-message').textContent.includes('credential envelopes were retained')"), true);
  assert.equal(await evaluate(`${providerCard}.querySelector('button[aria-expanded]').disabled`), false, "edit control should recover after save and refresh");

  const oldSameOriginUrl = "https://provider.example.org/v1/compatible/";
  await evaluate(`${providerCard}.querySelector('button[aria-expanded]').click()`);
  await evaluate(setField("Base URL", "https://provider-new.example.net/v1/", `${providerCard}.querySelector('.provider-base-url-editor')`));
  await evaluate(`${providerCard}.querySelector('.provider-base-url-editor button[type=submit]').click()`);
  await until(() => evaluate("document.querySelector('.content').innerText.includes('https://provider-new.example.net/v1/')"));
  assert.deepEqual(providerUpdates[3], {
    id: "my_provider",
    body: { baseUrl: "https://provider-new.example.net/v1/", expectedBaseUrl: oldSameOriginUrl },
  });
  const crossOriginConfirmation = await evaluate("window.__confirmMessages.at(-1)");
  assert.match(crossOriginConfirmation, /revoke all saved credentials.*globally.*enroll provider keys again/i, "cross-origin confirmation must explain global credential revocation");
  assert.ok(crossOriginConfirmation.includes(oldSameOriginUrl) && crossOriginConfirmation.includes("https://provider-new.example.net/v1/"), "cross-origin confirmation should show both URLs");
  assert.equal(await evaluate("document.querySelector('#live-message').textContent.includes('4 saved provider credentials were revoked')"), true);

  simulateProviderUpdateConflict = true;
  await evaluate(`${providerCard}.querySelector('button[aria-expanded]').click()`);
  await evaluate(setField("Base URL", "https://stale-update.example.org/v1/", `${providerCard}.querySelector('.provider-base-url-editor')`));
  const providerUpdateCountBeforeConflict = providerUpdates.length;
  await evaluate(`${providerCard}.querySelector('.provider-base-url-editor button[type=submit]').click()`);
  await until(() => evaluate("document.querySelector('#live-message').textContent.includes('review the current URL and retry')"));
  assert.equal(providerUpdates.length, providerUpdateCountBeforeConflict + 1, "a stale provider update should not be silently resubmitted");
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('https://concurrent-provider.example.net/v1/')"), true, "409 should refresh the provider card with the latest URL");

  const keyProviderExpression = "[...document.querySelectorAll('.field')].find(group=>group.querySelector('label')?.textContent.trim()==='LLM provider').querySelector('select')";
  await evaluate(`(() => {const select=${keyProviderExpression};select.value='my_provider';select.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  assert.equal(await evaluate("document.querySelector('[aria-live=polite].field-help')?.textContent.includes('https://concurrent-provider.example.net/v1/')"), true, "key form should identify the selected provider endpoint");
  await evaluate(setField("Provider API key", "mock-provider-key-not-a-real-secret"));
  await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Encrypt and save').click()");
  await until(() => evaluate("document.querySelector('#live-message').textContent.includes('key field cleared')"));
  assert.equal(credentialRequests[0].expectedBaseUrl, "https://concurrent-provider.example.net/v1/", "custom credential enrollment must bind to the selected canonical Base URL");
  assert.equal(await evaluate("[...document.querySelectorAll('.field')].find(group=>group.querySelector('label')?.textContent.trim()==='Provider API key').querySelector('input').value"), "", "a stale endpoint conflict must clear the raw key field");
  assert.equal(await evaluate(`${keyProviderExpression}.value`), "", "credential conflict must require the user to select the provider again");

  await evaluate(`(() => {const select=${keyProviderExpression};select.value='my_provider';select.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  assert.equal(await evaluate("document.querySelector('[aria-live=polite].field-help')?.textContent.includes('https://credential-raced.example.net/v1/')"), true, "credential conflict should refresh the endpoint for deliberate retry");
  await evaluate(setField("Provider API key", "mock-provider-key-after-reentry"));
  await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Encrypt and save').click()");
  await until(() => evaluate("document.querySelector('#live-message').textContent.includes('Provider key encrypted')"));
  assert.equal(credentialRequests[1].expectedBaseUrl, "https://credential-raced.example.net/v1/", "retry must submit the refreshed endpoint after the user re-enters the key");

  await evaluate(setField("Provider ID", "private_test"));
  await evaluate(setField("Display name", "Private Test"));
  await evaluate(setField("Base URL", "https://127.0.0.1/v1/"));
  await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Register provider').click()");
  await until(() => evaluate("document.querySelector('.content').innerText.includes('Private, local, or insecure endpoints are blocked.')"));
  assert.equal(registrations.length, 2, "private URL should be sent only to the mock API for its rejection response");
  assert.equal(await evaluate("[...document.querySelectorAll('button[type=submit]')].find(button=>button.textContent==='Register provider').disabled"), false, "register button should recover after an endpoint error");
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('private_test')"), false, "rejected provider should not appear in the provider list");

  sessionIsAdmin = false;
  await command("Page.navigate", { url: `http://127.0.0.1:${address.port}/ui` });
  await until(() => evaluate("document.querySelector('#app')?.getAttribute('aria-busy')==='false'"));
  await evaluate("[...document.querySelectorAll('.nav-item')].find(button=>button.textContent.includes('Providers')).click()");
  await until(() => evaluate("[...document.querySelectorAll('.panel')].some(panel=>panel.querySelector('h2')?.textContent==='My Provider')"));
  assert.equal(await evaluate("document.querySelector('.content').innerText.includes('Edit Base URL')"), false, "non-admins must not see endpoint editing controls");
  assert.equal(await evaluate("[...document.querySelectorAll('h2')].some(node=>node.textContent==='Add a custom provider')"), false, "non-admins must not see custom provider registration");
  assert.deepEqual(serverErrors, []);
  assert.deepEqual(browserExceptions, []);
  console.log("Chromium custom-provider UI passed: admin registration, same-origin URL reuse, cross-origin revocation, key enrollment CAS, role restrictions, provider dropdowns, and endpoint error recovery.");
} catch (error) {
  console.error({ browserExceptions, serverErrors, page: ws?.readyState === WebSocket.OPEN ? await evaluate("document.body.innerText") : "unavailable" });
  throw error;
} finally {
  ws?.close();
  browser.kill("SIGKILL");
  await new Promise((resolve) => server.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
