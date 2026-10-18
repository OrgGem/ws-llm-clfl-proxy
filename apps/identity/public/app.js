import { ApiError, createApiClient } from "./api.js";
import { safeBootstrapMetadata } from "./bootstrap.js";
import { isTimestampExpired, timestampMilliseconds } from "./dates.js";

const app = document.getElementById("app");
const state = {
  session: undefined,
  csrfToken: undefined,
  setupStatus: undefined,
  setupCsrfToken: undefined,
  setupConfig: undefined,
  setupError: undefined,
  setupSaved: false,
  setupAdminMode: false,
  projectId: undefined,
  oauthPort: "43128",
  oauthPairingPort: undefined,
  oauthControlPort: undefined,
  oauthPairingId: undefined,
  oauthPairingExpiresAt: undefined,
  oauthControlToken: undefined,
  oauthControlExpiresAt: undefined,
  oauthLoginStatus: undefined,
  oauthModels: [],
  oauthAlias: "",
  oauthBoundAliases: [],
  oauthError: undefined,
  oauthNotice: undefined,
  view: "overview",
  main: undefined,
  navButtons: new Map(),
  busy: false,
};

const api = createApiClient({ getCsrfToken: () => state.csrfToken ?? state.setupCsrfToken });

const VIEWS = {
  overview: {
    label: "Dashboard",
    icon: "◈",
    title: "Your Gateway, at a glance",
    description: "A clear view of the connections and credentials in this project.",
  },
  clients: {
    label: "Clients",
    icon: "⌘",
    title: "Clients and access",
    description: "Manage the applications and devices allowed to use this project.",
  },
  providers: {
    label: "Providers",
    icon: "↗",
    title: "Provider connections",
    description: "Add encrypted API credentials and control which models this project can use.",
  },
  connections: {
    label: "Connections",
    icon: "⤴",
    title: "Provider sign-in connections",
    description: "Connect an eligible provider account through your local adapter. Provider tokens stay on the adapter.",
  },
  sessions: {
    label: "Sessions",
    icon: "◷",
    title: "Active sessions",
    description: "Review connected devices and end sessions you no longer recognize.",
  },
  security: {
    label: "Security",
    icon: "⌑",
    title: "Identity and security",
    description: "Review sign-in identities, token key versions, approvals, and audit activity.",
  },
};

function h(tag, attributes = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (name === "className") element.className = value;
    else if (name === "htmlFor") element.htmlFor = value;
    else if (name === "checked" || name === "disabled" || name === "selected" || name === "multiple") element[name] = Boolean(value);
    else if (name === "value") element.value = value;
    else if (name.startsWith("on") && typeof value === "function") element.addEventListener(name.slice(2).toLowerCase(), value);
    else element.setAttribute(name, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function list(value) {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function display(value, fallback = "—") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function enabled(value) {
  return value === true || value === 1 || value === "active" || value === "enabled";
}

function dateLabel(value) {
  const milliseconds = timestampMilliseconds(value);
  const date = new Date(milliseconds);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function modelEntry(value) {
  if (!isRecord(value)) return undefined;
  const provider = typeof value.provider === "string" ? value.provider : "";
  const model = typeof value.model === "string" ? value.model : typeof value.alias === "string" ? value.alias : typeof value.id === "string" ? value.id : "";
  if (!provider || !model) return undefined;
  return { provider, model, label: display(value.displayName, display(value.alias, model)) };
}

function modelKey(model) {
  return `${model.provider}\u0000${model.model}`;
}

function modelsOf(values) {
  return list(values).map(modelEntry).filter(Boolean);
}

function button(label, onClick, variant = "secondary", options = {}) {
  return h("button", {
    type: "button",
    className: `button ${variant}${options.small ? " small" : ""}${options.wide ? " wide" : ""}`,
    disabled: options.disabled,
    title: options.title,
    onClick,
  }, label);
}

function iconButton(label, accessibleName, onClick) {
  return h("button", { type: "button", className: "icon-button", "aria-label": accessibleName, title: accessibleName, onClick }, label);
}

function badge(label, tone = "neutral") {
  return h("span", { className: `badge ${tone}` }, label);
}

function field(labelText, control, help, full = false) {
  const id = control.id || `field-${Math.random().toString(36).slice(2, 10)}`;
  control.id = id;
  return h("div", { className: `field${full ? " full" : ""}` },
    h("label", { htmlFor: id }, labelText),
    control,
    help ? h("p", { className: "field-help" }, help) : null,
  );
}

function fieldGroup(labelText, control, help, full = false) {
  return h("fieldset", { className: `field-group${full ? " full" : ""}` },
    h("legend", {}, labelText),
    control,
    help ? h("p", { className: "field-help" }, help) : null,
  );
}

function emptyState(title, description, glyph = "·") {
  return h("div", { className: "empty-state" },
    h("div", { className: "empty-glyph", "aria-hidden": "true" }, glyph),
    h("strong", {}, title),
    h("p", {}, description),
  );
}

function panel(title, description, content, actions) {
  return h("section", { className: "panel" },
    h("div", { className: "panel-header" },
      h("div", {}, h("h2", {}, title), description ? h("p", { className: "panel-description" }, description) : null),
      actions ?? null,
    ),
    content,
  );
}

function alertBox(message, tone = "danger", dismiss) {
  const alert = h("div", { className: `alert${tone === "info" ? " info" : ""}`, role: tone === "danger" ? "alert" : "status" },
    h("span", {}, message),
  );
  if (dismiss) alert.append(button("Dismiss", dismiss, "ghost", { small: true }));
  return alert;
}

function notice(message, tone = "info") {
  return h("div", { className: `notice${tone === "warning" ? " warning" : tone === "danger" ? " danger" : ""}`, role: "note" },
    h("span", { className: "notice-icon", "aria-hidden": "true" }, tone === "warning" ? "!" : "i"),
    h("span", {}, message),
  );
}

function setLiveMessage(message) {
  const live = document.getElementById("live-message");
  if (live) live.textContent = message;
}

function confirmAction(message) {
  return window.confirm(message);
}

function setBusy(value) {
  state.busy = value;
  app?.setAttribute("aria-busy", value ? "true" : "false");
  for (const control of app?.querySelectorAll("[data-busy-disabled]") ?? []) {
    control.disabled = value;
  }
}

async function runAction(action, successMessage) {
  if (state.busy) return;
  setBusy(true);
  try {
    await action();
    setLiveMessage(successMessage);
    await loadCurrentView();
  } catch (error) {
    showPageError(error);
  } finally {
    setBusy(false);
  }
}

function showPageError(error) {
  if (!state.main) return;
  if (error instanceof ApiError && error.status === 401) {
    state.csrfToken = undefined;
    initialize();
    return;
  }
  state.main.replaceChildren(
    alertBox(error instanceof Error ? error.message : "The request could not be completed."),
    emptyState("This view could not load", "Check your connection and try again. No provider secret or token is included in this message.", "↻"),
    button("Retry", () => loadCurrentView(), "secondary"),
  );
}

function showOneTimeValue({ title, description, label, value, warning, testAction }) {
  let secret = String(value ?? "");
  const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : undefined;
  const previousInert = app.inert;
  const textareaId = `one-time-value-${Math.random().toString(36).slice(2, 10)}`;
  const textarea = h("textarea", {
    className: "textarea",
    id: textareaId,
    readonly: "",
    spellcheck: "false",
    autocomplete: "off",
    autocapitalize: "off",
    "aria-label": label,
  });
  textarea.value = secret;
  const copyStatus = h("p", { className: "field-help", role: "status", "aria-live": "polite" }, "Copy this value now. It will be cleared when you close this window.");
  const backdrop = h("div", { className: "dialog-backdrop" });
  const close = () => {
    textarea.value = "";
    secret = "";
    backdrop.remove();
    document.removeEventListener("keydown", onKeydown);
    app.inert = previousInert;
    returnFocus?.focus();
  };
  const onKeydown = (event) => {
    if (event.key === "Escape") { close(); return; }
    if (event.key !== "Tab") return;
    const focusable = [...card.querySelectorAll("button:not([disabled]), textarea")];
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      secret = "";
      textarea.value = "";
      copyButton.disabled = true;
      copyButton.textContent = "Copied";
      copyStatus.textContent = "Copied. Paste it into your local adapter now; this view cleared its copy.";
    } catch {
      copyStatus.textContent = "Clipboard access is unavailable. Select the value above and copy it manually.";
      textarea.focus();
      textarea.select();
    }
  };
  const copyButton = button("Copy", copy, "secondary");
  const testButton = typeof testAction === "function" ? button("Test connection", async () => {
    testButton.disabled = true;
    copyStatus.textContent = "Checking the saved credential against the provider model-list endpoint…";
    try {
      const result = await testAction();
      if (result?.ok === true) {
        copyStatus.textContent = `Connection verified for ${display(result.provider, "provider")}${result.checkedAt ? ` at ${dateLabel(result.checkedAt)}` : ""}. No model request was sent.`;
      } else {
        copyStatus.textContent = "Identity did not confirm the provider connection. No model request was sent.";
      }
    } catch (error) {
      copyStatus.textContent = error instanceof ApiError && error.status === 404
        ? "Connection testing is not available on this Identity deployment yet. The credential remains saved."
        : error instanceof Error ? error.message : "Connection test failed. The credential remains saved.";
    } finally {
      testButton.disabled = false;
    }
  }, "secondary") : null;
  const card = h("section", { className: "dialog-card", role: "dialog", "aria-modal": "true", "aria-labelledby": "one-time-title" },
    h("div", { className: "dialog-header" },
      h("div", {}, h("p", { className: "eyebrow" }, "Shown once"), h("h2", { id: "one-time-title" }, title)),
      iconButton("×", "Close", close),
    ),
    h("p", { className: "dialog-description" }, description),
    warning ? notice(warning, "warning") : null,
    h("div", { className: "dialog-secret field" }, h("label", { htmlFor: textareaId }, label), textarea, copyStatus),
    h("div", { className: "dialog-footer" },
      testButton,
      copyButton,
      button("Done", close, "primary"),
    ),
  );
  backdrop.append(card);
  backdrop.addEventListener("click", (event) => { if (event.target === backdrop) close(); });
  document.addEventListener("keydown", onKeydown);
  document.body.append(backdrop);
  app.inert = true;
  textarea.focus();
  textarea.select();
}

function pageHeader(viewKey = state.view) {
  const view = VIEWS[viewKey] ?? VIEWS.overview;
  return h("header", { className: "page-heading" },
    h("div", {}, h("p", { className: "eyebrow" }, "Identity & Config"), h("h1", {}, view.title), h("p", { className: "page-description" }, view.description)),
  );
}

function renderLogin(session = {}, setupStatus = {}) {
  state.session = undefined;
  state.csrfToken = undefined;
  state.setupStatus = isRecord(setupStatus) ? setupStatus : undefined;
  state.setupCsrfToken = undefined;
  state.setupConfig = undefined;
  state.setupSaved = false;
  state.setupAdminMode = false;
  setBusy(false);
  const providers = list(session.loginProviders);
  const setupAvailable = setupStatus.bootstrapAvailable === true;
  const loginLinks = providers.map((provider) => {
    const id = typeof provider.id === "string" ? provider.id : "";
    const label = display(provider.label, "Sign in");
    const path = id ? `/auth/oidc/start?provider=${encodeURIComponent(id)}` : "/auth/login";
    return h("a", { className: "login-provider", href: path }, h("span", {}, label), h("span", { "aria-hidden": "true" }, "↗"));
  });
  const message = session.authSetupRequired
    ? setupAvailable
      ? "Organization sign-in is not configured yet. Use the temporary setup password to connect an OIDC provider."
      : "Sign-in has not been configured yet. Ask the service administrator to finish Identity setup."
    : providers.length
      ? "Sign in with your organization account to manage Gateway access."
      : "No sign-in provider is available. Ask the service administrator to configure OIDC.";
  const password = h("input", {
    className: "input",
    type: "password",
    name: "setup-password",
    autocomplete: "current-password",
    required: "",
    maxlength: 512,
    spellcheck: "false",
    autocapitalize: "off",
  });
  const setupLoginForm = setupAvailable ? h("form", {
    className: "setup-login-form",
    onSubmit: (event) => { event.preventDefault(); void submitSetupLogin(password); },
  },
    h("div", { className: "setup-section-heading" },
      h("h2", {}, "First-time OIDC setup"),
      h("p", { className: "field-help" }, "Use the temporary password delivered to the service owner. This access can only configure OIDC; it cannot manage clients, projects, or credentials."),
    ),
    state.setupError ? alertBox(state.setupError) : null,
    field("Temporary setup password", password, "The password expires after 24 hours and is disabled after the first successful OIDC admin sign-in."),
    h("div", { className: "form-actions" }, h("button", { type: "submit", className: "button primary", disabled: state.busy, "data-busy-disabled": "true" }, "Continue setup")),
  ) : null;
  const content = h("main", { className: "auth-screen" },
    h("section", { className: "login-card" },
      h("div", { className: "brand-mark", "aria-hidden": "true" }, "L"),
      h("p", { className: "eyebrow" }, "LLM Gateway control room"),
      h("h1", {}, "Manage access with confidence"),
      h("p", { className: "page-description" }, message),
      providers.length ? h("div", { className: "login-provider-list" }, ...loginLinks) : notice(message, setupAvailable ? "info" : "warning"),
      h("p", { className: "field-help login-note" }, "Your sign-in identity is separate from the provider API keys managed inside this console."),
      setupLoginForm,
    ),
  );
  app.replaceChildren(content);
  app.setAttribute("aria-busy", "false");
}

function setupIssuerList(config = state.setupConfig) {
  const values = Array.isArray(config?.allowedIssuers) ? config.allowedIssuers : state.setupStatus?.allowedIssuers;
  return Array.isArray(values) ? values.filter((value) => typeof value === "string" && value.startsWith("https://")) : [];
}

function isGoogleIssuer(value) {
  try {
    const url = new URL(value);
    return url.origin === "https://accounts.google.com" && url.pathname === "/" && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function providerDefaults(config = state.setupConfig) {
  const existing = list(config?.providers);
  const issuers = setupIssuerList(config);
  const provider = existing[0];
  const issuer = typeof provider?.issuer === "string"
    ? provider.issuer
    : issuers.find(isGoogleIssuer) ?? issuers[0] ?? "https://accounts.google.com";
  let host = "google";
  try { host = new URL(issuer).hostname.replace(/^www\./, ""); } catch { /* use the safe fallback */ }
  const isGoogle = isGoogleIssuer(issuer);
  return {
    id: display(provider?.id, isGoogle ? "google" : host.toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 32)),
    label: display(provider?.label, isGoogle ? "Google" : host),
    issuer,
    clientId: typeof provider?.clientId === "string" ? provider.clientId : "",
    hasClientSecret: provider?.hasClientSecret === true,
  };
}

function renderSetupPage() {
  const config = isRecord(state.setupConfig) ? state.setupConfig : {};
  const adminMode = state.setupAdminMode === true;
  const defaults = providerDefaults(config);
  const issuers = setupIssuerList(config);
  const issuerOptions = [...new Set([...issuers, defaults.issuer])];
  const providerId = h("input", { className: "input", value: defaults.id, required: "", maxlength: 32, pattern: "[a-z][a-z0-9_-]{0,31}", autocomplete: "off", spellcheck: "false" });
  const label = h("input", { className: "input", value: defaults.label, required: "", maxlength: 80, autocomplete: "off" });
  const issuer = h("select", { className: "select", required: "", value: defaults.issuer }, ...issuerOptions.map((value) => h("option", { value, selected: value === defaults.issuer }, value)));
  const clientId = h("input", { className: "input", value: defaults.clientId, required: "", maxlength: 512, autocomplete: "off", spellcheck: "false" });
  const clientSecret = h("input", { className: "input", type: "password", required: defaults.hasClientSecret ? undefined : "", maxlength: 2048, autocomplete: "new-password", spellcheck: "false" });
  const adminEmails = h("textarea", {
    className: "textarea",
    required: "",
    maxlength: 8192,
    autocomplete: "off",
    placeholder: "admin@example.com",
    value: Array.isArray(config.bootstrapAdminEmails) ? config.bootstrapAdminEmails.join("\n") : "",
  });
  issuer.addEventListener("change", () => {
    let host = "provider";
    try { host = new URL(issuer.value).hostname.replace(/^www\./, ""); } catch { /* keep fallback */ }
    const isGoogle = isGoogleIssuer(issuer.value);
    if (providerId.value === "google" || providerId.value === "") {
      providerId.value = isGoogle ? "google" : host.toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 32);
    }
    if (label.value === "Google" || label.value === "") label.value = isGoogle ? "Google" : host;
  });
  const callback = typeof config.redirectUri === "string"
    ? config.redirectUri
    : typeof state.setupStatus?.redirectUri === "string"
      ? state.setupStatus.redirectUri
      : "Unavailable";
  const signInLinks = list(config.providers).map((provider) => {
    const id = typeof provider.id === "string" ? provider.id : "";
    if (!id) return null;
    return h("a", { className: "login-provider", href: `/auth/oidc/start?provider=${encodeURIComponent(id)}` },
      h("span", {}, `Sign in with ${display(provider.label, id)}`), h("span", { "aria-hidden": "true" }, "↗"));
  }).filter(Boolean);
  const form = h("form", {
    className: "setup-config-form",
    onSubmit: (event) => {
      event.preventDefault();
      void saveSetupOidc({ providerId, label, issuer, clientId, clientSecret, adminEmails });
    },
  },
    h("div", { className: "form-grid" },
      field("Provider ID", providerId, "Used in the sign-in URL. Use lowercase letters, numbers, underscores, or hyphens."),
      field("Display name", label),
      field("OIDC issuer", issuer, "Use one of the issuer URLs allowed by the service owner."),
      field("OAuth client ID", clientId, "Create a web application client in your identity provider."),
      field("OAuth client secret", clientSecret, defaults.hasClientSecret ? "A secret is already saved. Leave this blank to keep it, or enter a replacement." : "Enter the client secret from your identity provider.", true),
      field("Bootstrap admin email addresses", adminEmails, "One email address per line. The first matching verified account receives initial admin access; other accounts need approval in Security.", true),
    ),
    h("div", { className: "notice setup-callback" },
      h("span", { className: "notice-icon", "aria-hidden": "true" }, "i"),
      h("span", {}, "Register this exact callback URL in your identity provider: ", h("code", { className: "monospace setup-callback-url" }, callback || "Unavailable")),
    ),
    h("p", { className: "field-help setup-instructions" }, "For Google, add a Web application OAuth client in Google Cloud Console, register the callback above, then save and sign in. The setup password stays available until the first successful OIDC administrator sign-in."),
    state.setupError ? alertBox(state.setupError) : null,
    state.setupSaved ? notice("OIDC settings saved. Sign in with the configured provider to finish setup.") : null,
    h("div", { className: "form-actions" },
      h("button", { type: "submit", className: "button primary", disabled: state.busy, "data-busy-disabled": "true" }, "Save OIDC settings"),
      h("button", { type: "button", className: "button secondary", disabled: state.busy, "data-busy-disabled": "true", onClick: adminMode ? exitAdminOidcSettings : signOutSetup }, adminMode ? "Back to Security" : "Sign out of setup"),
    ),
  );
  const content = h("main", { className: "auth-screen setup-screen" },
    h("section", { className: "login-card setup-card" },
      h("div", { className: "brand-mark", "aria-hidden": "true" }, "L"),
      h("p", { className: "eyebrow" }, "LLM Gateway control room"),
      h("h1", {}, adminMode ? "Manage organization sign-in" : "Connect organization sign-in"),
      h("p", { className: "page-description" }, adminMode
        ? "Update the OIDC providers used for Identity sign-in. Provider client secrets are write-only and are never shown here."
        : "This temporary setup access can configure OIDC only. It cannot manage projects, clients, or provider credentials."),
      signInLinks.length ? h("div", { className: "login-provider-list setup-existing-providers" }, ...signInLinks) : null,
      form,
    ),
  );
  app.replaceChildren(content);
  app.setAttribute("aria-busy", state.busy ? "true" : "false");
}

async function submitSetupLogin(password) {
  if (state.busy) return;
  const value = password.value;
  password.value = "";
  state.setupError = undefined;
  setBusy(true);
  try {
    const login = await api.postSetupLogin({ password: value });
    state.setupCsrfToken = typeof login?.csrfToken === "string" ? login.csrfToken : undefined;
    const status = await api.get("/api/setup/status");
    if (!isRecord(status) || status.authenticated !== true) throw new ApiError(401, "Setup access expired. Sign in again.");
    state.setupStatus = status;
    state.setupCsrfToken = typeof status.csrfToken === "string" ? status.csrfToken : state.setupCsrfToken;
    if (!state.setupCsrfToken) throw new ApiError(403, "Setup access expired. Sign in again.");
    state.setupConfig = await api.get("/api/setup/oidc");
    state.setupSaved = false;
    renderSetupPage();
  } catch (error) {
    state.setupError = error instanceof ApiError && error.status === 429
      ? "Too many setup login attempts. Wait a moment and try again."
      : error instanceof ApiError && error.status === 401
        ? "The setup password is invalid or has expired. Check the service owner’s instructions and try again."
        : error instanceof Error ? error.message : "Setup could not be opened. Try again.";
    state.setupCsrfToken = undefined;
    let status = state.setupStatus;
    try { status = await api.get("/api/setup/status"); } catch { /* retain the last public status */ }
    renderLogin({}, isRecord(status) ? status : {});
  } finally {
    setBusy(false);
  }
}

function parseAdminEmails(value) {
  const emails = value.split(/[\n,;]/).map((item) => item.trim()).filter(Boolean);
  const valid = emails.length > 0 && emails.every((email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
  return valid ? [...new Set(emails)] : undefined;
}

async function saveSetupOidc(fields) {
  if (state.busy) return;
  const secret = fields.clientSecret.value;
  fields.clientSecret.value = "";
  state.setupError = undefined;
  state.setupSaved = false;
  const emails = parseAdminEmails(fields.adminEmails.value);
  if (!emails) {
    state.setupError = "Enter at least one valid administrator email address.";
    renderSetupPage();
    return;
  }
  const id = fields.providerId.value.trim();
  const label = fields.label.value.trim();
  const issuer = fields.issuer.value;
  const clientId = fields.clientId.value.trim();
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(id) || !label || label.length > 80 || !setupIssuerList().includes(issuer) || !clientId) {
    state.setupError = "Check the provider ID, display name, allowed issuer, and client ID.";
    renderSetupPage();
    return;
  }
  const existing = list(state.setupConfig?.providers);
  const sameProvider = existing.find((provider) => provider.id === id && provider.issuer === issuer && provider.clientId === clientId);
  if (!secret && sameProvider?.hasClientSecret !== true) {
    state.setupError = "Enter the OAuth client secret for this provider.";
    renderSetupPage();
    return;
  }
  const providers = existing.filter((provider) => provider.id !== id).map((provider) => ({
    id: provider.id,
    label: provider.label,
    issuer: provider.issuer,
    clientId: provider.clientId,
  }));
  const selected = { id, label, issuer, clientId };
  if (secret) selected.clientSecret = secret;
  providers.push(selected);
  setBusy(true);
  try {
    state.setupConfig = await api.put("/api/setup/oidc", { providers, bootstrapAdminEmails: emails });
    state.setupSaved = true;
    renderSetupPage();
  } catch (error) {
    state.setupError = error instanceof Error ? error.message : "OIDC settings could not be saved.";
    renderSetupPage();
  } finally {
    setBusy(false);
  }
}

async function signOutSetup() {
  if (state.busy) return;
  setBusy(true);
  try {
    await api.post("/api/setup/logout", {});
    state.setupCsrfToken = undefined;
    state.setupStatus = undefined;
    state.setupConfig = undefined;
    state.setupError = undefined;
    await initialize();
  } catch (error) {
    state.setupError = error instanceof Error ? error.message : "Setup sign-out failed.";
    renderSetupPage();
  } finally {
    setBusy(false);
  }
}

async function editAdminOidcSettings() {
  if (state.busy) return;
  setBusy(true);
  try {
    state.setupConfig = await api.get("/api/setup/oidc");
    state.setupAdminMode = true;
    state.setupError = undefined;
    state.setupSaved = false;
    renderSetupPage();
  } catch (error) {
    showPageError(error);
  } finally {
    setBusy(false);
  }
}

async function exitAdminOidcSettings() {
  state.setupAdminMode = false;
  state.setupConfig = undefined;
  state.setupError = undefined;
  await initialize();
}

function projectIdOf(project) {
  return typeof project.id === "string" ? project.id : typeof project.projectId === "string" ? project.projectId : "";
}

function currentProject() {
  return list(state.session?.projects).find((project) => projectIdOf(project) === state.projectId);
}

function canWriteCurrentProject() {
  const role = currentProject()?.role;
  return role === "owner" || role === "admin";
}

function renderShell() {
  const user = isRecord(state.session?.user) ? state.session.user : {};
  const projects = list(state.session?.projects);
  const activeProject = projects.find((project) => projectIdOf(project) === state.projectId);
  const initials = display(user.displayName, display(user.name, display(user.email, "U"))).trim().slice(0, 1).toUpperCase();
  const projectSelect = h("select", {
    className: "project-select",
    "aria-label": "Current project",
    disabled: projects.length === 0,
    onChange: (event) => {
      if (state.projectId !== event.target.value) clearOAuthConnectionState();
      state.projectId = event.target.value;
      navigate(state.view);
    },
  }, ...projects.map((project) => {
    const id = projectIdOf(project);
    return h("option", { value: id, selected: id === state.projectId }, display(project.name, display(project.displayName, id)));
  }));

  const brand = h("div", { className: "brand-row" },
    h("div", { className: "brand-mark", "aria-hidden": "true" }, "L"),
    h("div", {}, h("p", { className: "brand-title" }, "LLM Gateway"), h("p", { className: "brand-subtitle" }, "Control room")),
  );
  const nav = h("nav", { className: "side-nav", "aria-label": "Primary" });
  state.navButtons = new Map();
  for (const [key, view] of Object.entries(VIEWS)) {
    if (key === "security" && state.session?.user?.isAdmin !== true) continue;
    const navButton = h("button", {
      type: "button",
      className: "nav-item",
      "aria-current": key === state.view ? "page" : undefined,
      onClick: () => navigate(key),
    }, h("span", { className: "nav-icon", "aria-hidden": "true" }, view.icon), h("span", {}, view.label));
    state.navButtons.set(key, navButton);
    nav.append(navButton);
  }
  const sidebar = h("aside", { className: "sidebar" },
    brand,
    h("p", { className: "nav-label" }, "Workspace"),
    nav,
    h("div", { className: "sidebar-spacer" }),
    h("div", { className: "side-note" }, h("strong", {}, "Keys stay private"), "Provider credentials are encrypted before the adapter receives them. This console never shows the raw key again."),
    h("div", { className: "user-chip" },
      h("div", { className: "avatar", "aria-hidden": "true" }, initials),
      h("div", { className: "user-chip-meta" }, h("div", { className: "user-name" }, display(user.displayName, display(user.name, "Signed-in user"))), h("div", { className: "user-email" }, display(user.email, ""))),
    ),
  );
  const main = h("main", { className: "content", id: "main-content", tabindex: "-1" });
  const workspace = h("div", { className: "workspace" },
    h("header", { className: "topbar" },
      h("div", { className: "topbar-left" },
        h("span", { className: "topbar-label" }, "Project"),
        projectSelect,
        button("New project", createProject, "secondary", { small: true }),
      ),
      h("div", { className: "topbar-right" },
        h("span", { className: "connection-pill" }, h("span", { className: "connection-dot", "aria-hidden": "true" }), "Identity connected"),
        button("Sign out", signOut, "ghost", { small: true }),
      ),
    ),
    h("div", { id: "live-message", className: "sr-only", role: "status", "aria-live": "polite" }),
    main,
  );
  app.replaceChildren(h("div", { className: "app-shell" }, sidebar, workspace));
  state.main = main;
  app.setAttribute("aria-busy", "false");
  if (projects.length === 0) {
    state.main.append(pageHeader(), notice("No project is assigned to this account yet. Ask an administrator to add you to a project.", "warning"));
  }
}

async function createProject() {
  const rawName = window.prompt("Name this project");
  if (rawName === null) return;
  const name = rawName.trim();
  if (!name || name.length > 80) {
    showPageError(new Error("Project names must contain 1 to 80 characters."));
    return;
  }
  if (state.busy) return;
  setBusy(true);
  try {
    const created = await api.post("/api/projects", { name });
    const project = isRecord(created?.project) ? created.project : created;
    const createdId = projectIdOf(isRecord(project) ? project : {});
    const session = await api.get("/api/session");
    if (!isRecord(session) || session.authenticated !== true) throw new ApiError(401, "Your session expired. Sign in again.");
    state.session = session;
    state.csrfToken = typeof session.csrfToken === "string" ? session.csrfToken : undefined;
    const projects = list(session.projects);
    state.projectId = projects.some((item) => projectIdOf(item) === createdId)
      ? createdId
      : projectIdOf(projects[0] ?? {});
    renderShell();
    await navigate(state.view);
    setLiveMessage(`Project ${name} created.`);
  } catch (error) {
    showPageError(error);
  } finally {
    setBusy(false);
  }
}

async function signOut() {
  if (state.busy) return;
  setBusy(true);
  try {
    await api.post("/api/logout", {});
    state.session = undefined;
    state.csrfToken = undefined;
    state.setupCsrfToken = undefined;
    clearOAuthConnectionState();
    await initialize();
  } catch (error) {
    showPageError(error);
  } finally {
    setBusy(false);
  }
}

async function initialize() {
  setBusy(true);
  try {
    const session = await api.get("/api/session");
    if (!isRecord(session) || session.authenticated !== true) {
      clearOAuthConnectionState();
      state.setupStatus = undefined;
      state.setupCsrfToken = undefined;
      state.setupConfig = undefined;
      state.setupError = undefined;
      let setupStatus = {};
      try {
        const status = await api.get("/api/setup/status");
        if (isRecord(status)) setupStatus = status;
      } catch { /* OIDC login must remain available if setup status is unavailable */ }
      if (setupStatus.authenticated === true) {
        state.setupStatus = setupStatus;
        state.setupCsrfToken = typeof setupStatus.csrfToken === "string" ? setupStatus.csrfToken : undefined;
        try {
          state.setupConfig = await api.get("/api/setup/oidc");
          renderSetupPage();
          return;
        } catch {
          state.setupCsrfToken = undefined;
          state.setupError = "Setup access expired. Sign in again to continue.";
          try {
            const refreshed = await api.get("/api/setup/status");
            if (isRecord(refreshed)) setupStatus = refreshed;
          } catch { /* render the ordinary login even if status cannot be refreshed */ }
        }
      }
      renderLogin(isRecord(session) ? session : {}, setupStatus);
      return;
    }
    state.setupCsrfToken = undefined;
    state.setupStatus = undefined;
    state.setupConfig = undefined;
    state.session = session;
    state.csrfToken = typeof session.csrfToken === "string" ? session.csrfToken : undefined;
    const projects = list(session.projects);
    const active = typeof session.activeProjectId === "string" ? session.activeProjectId : "";
    state.projectId = projects.some((project) => projectIdOf(project) === active) ? active : projectIdOf(projects[0] ?? {});
    renderShell();
    await navigate(state.view);
  } catch {
    renderRootError();
  } finally {
    setBusy(false);
  }
}

function renderRootError() {
  const content = h("main", { className: "auth-screen" },
    h("section", { className: "login-card" },
      h("div", { className: "brand-mark", "aria-hidden": "true" }, "L"),
      h("p", { className: "eyebrow" }, "LLM Gateway control room"),
      h("h1", {}, "We could not reach Identity"),
      h("p", { className: "page-description" }, "The account service did not respond. Try again in a moment."),
      button("Retry", initialize, "primary"),
    ),
  );
  app.replaceChildren(content);
  app.setAttribute("aria-busy", "false");
}

async function navigate(view) {
  if (!VIEWS[view] || !state.main) return;
  state.view = view;
  for (const [key, navButton] of state.navButtons) {
    if (key === view) navButton.setAttribute("aria-current", "page");
    else navButton.removeAttribute("aria-current");
  }
  await loadCurrentView();
}

async function loadCurrentView() {
  if (!state.main) return;
  const view = VIEWS[state.view] ?? VIEWS.overview;
  const main = state.main;
  main.replaceChildren(pageHeader());
  const loading = h("div", { className: "panel", "aria-label": `Loading ${view.label.toLowerCase()}` }, h("div", { className: "loading-bar" }));
  main.append(loading);
  try {
    const content = await renderView(state.view);
    if (main !== state.main || state.view !== Object.keys(VIEWS).find((key) => VIEWS[key] === view)) return;
    main.replaceChildren(pageHeader(), ...content);
  } catch (error) {
    showPageError(error);
  }
}

async function renderView(view) {
  if (!state.projectId && view !== "security" && view !== "sessions") return [notice("Choose a project before managing clients or provider access.", "warning")];
  if (view === "overview") return renderOverview();
  if (view === "clients") return renderClients();
  if (view === "providers") return renderProviders();
  if (view === "connections") return renderConnections();
  if (view === "sessions") return renderSessions();
  if (view === "security") return renderSecurity();
  return [emptyState("This view is unavailable", "Choose another section from the navigation.")];
}

function credentialIsActive(credential) {
  if (credential.revokedAt || credential.revoked_at || credential.revoked === true) return false;
  const expiry = credential.expiresAt ?? credential.expires_at;
  if (expiry !== undefined && expiry !== null) {
    const time = typeof expiry === "number" && expiry < 10_000_000_000 ? expiry * 1000 : new Date(expiry).getTime();
    if (Number.isFinite(time) && time <= Date.now()) return false;
  }
  return true;
}

function metric(label, value, note, glyph) {
  return h("article", { className: "metric-card" },
    h("div", { className: "metric-label" }, label),
    h("div", { className: "metric-value" }, value),
    h("p", { className: "metric-note" }, note),
    h("span", { className: "sr-only" }, glyph),
  );
}

async function renderOverview() {
  const data = await api.get("/api/dashboard", { projectId: state.projectId });
  const providers = list(data?.providers);
  const credentials = list(data?.credentials);
  const summary = isRecord(data?.summary) ? data.summary : {};
  const activeProviders = providers.filter((provider) => enabled(provider.enabled)).length;
  const activeCredentials = credentials.filter(credentialIsActive).length;
  const activeSessions = Number.isFinite(summary.activeSessions) ? summary.activeSessions : undefined;
  const activeClients = Number.isFinite(summary.activeClients) ? summary.activeClients : undefined;
  const metrics = [];
  if (activeClients !== undefined) metrics.push(metric("Active clients", activeClients, "Clients in the selected project", "clients"));
  metrics.push(metric("Enabled providers", activeProviders, "Provider routes available to this project", "providers"));
  metrics.push(metric("Active credentials", activeCredentials, "Encrypted keys that are not revoked or expired", "keys"));
  if (activeSessions !== undefined) metrics.push(metric("Active sessions", activeSessions, "Sessions reported by Identity", "sessions"));

  const providerRows = providers.map((provider) => h("div", { className: "list-row" },
    h("div", {}, h("div", { className: "row-title" }, display(provider.displayName, display(provider.provider))), h("div", { className: "row-meta" }, `${list(provider.models).length} model${list(provider.models).length === 1 ? "" : "s"} configured`)),
    badge(enabled(provider.enabled) ? "Enabled" : "Disabled", enabled(provider.enabled) ? "success" : "neutral"),
  ));
  const credentialRows = credentials.map((credential) => h("div", { className: "list-row" },
    h("div", {}, h("div", { className: "row-title" }, display(credential.displayName, display(credential.provider, "Provider credential"))), h("div", { className: "row-meta" }, `Expires ${dateLabel(credential.expiresAt ?? credential.expires_at)}`)),
    badge(credentialIsActive(credential) ? "Active" : "Revoked or expired", credentialIsActive(credential) ? "success" : "warning"),
  ));

  const metricContent = metrics.length
    ? h("div", { className: "metrics-grid" }, ...metrics)
    : emptyState("No summary metrics yet", "Identity has not reported project metrics for this view.");
  const providerContent = providerRows.length ? h("div", { className: "list" }, ...providerRows) : emptyState("No provider routes", "Provider routes will appear here when configured.", "↗");
  const credentialContent = credentialRows.length ? h("div", { className: "list" }, ...credentialRows) : emptyState("No encrypted keys", "Add a provider API key to make an authorized model available.", "⌑");
  return [
    metricContent,
    h("div", { className: "section-grid two" },
      panel("Provider routes", "Only server-configured endpoints can receive requests.", providerContent),
      panel("Credential health", "The raw provider key is never shown again after encryption.", credentialContent),
    ),
  ];
}

function modelCheckboxes(models, selected = []) {
  const available = modelsOf(models);
  const selectedKeys = new Set(modelsOf(selected).map(modelKey));
  if (!available.length) return emptyState("No models configured", "Add a model mapping in Providers before granting model access.");
  return h("div", { className: "checkbox-list" }, ...available.map((model) => {
    const checkbox = h("input", {
      type: "checkbox",
      value: model.model,
      checked: selectedKeys.has(modelKey(model)),
      "data-provider": model.provider,
      "data-model": model.model,
    });
    return h("label", { className: "checkbox-option" }, checkbox, h("span", {}, `${model.label} · ${model.provider}`));
  }));
}

function checkedModels(container) {
  return [...container.querySelectorAll('input[type="checkbox"][data-provider][data-model]:checked')].map((input) => ({
    provider: input.getAttribute("data-provider"),
    model: input.getAttribute("data-model"),
  }));
}

function clientIdOf(client) {
  return typeof client.id === "string" ? client.id : typeof client.clientId === "string" ? client.clientId : "";
}

function clientModelsOf(client) {
  return client.models ?? client.permissions ?? client.allowedModels ?? [];
}

async function downloadBootstrap(client) {
  const id = clientIdOf(client);
  if (!id) return;
  try {
    const response = await api.get(`/api/clients/${encodeURIComponent(id)}/bootstrap`);
    const bootstrap = safeBootstrapMetadata(response);
    const filenamePart = display(client.name, "client").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "client";
    const file = new Blob([`${JSON.stringify(bootstrap, null, 2)}\n`], { type: "application/json" });
    const objectUrl = URL.createObjectURL(file);
    const link = h("a", { href: objectUrl, download: `llm-gateway-${filenamePart}-setup.json`, className: "sr-only", "aria-label": "Download client setup metadata" });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
    setLiveMessage("Safe setup metadata downloaded. Pairing tokens, client secrets, and credential envelopes are not included.");
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      setLiveMessage("Client setup export is not available on this Identity deployment yet.");
      return;
    }
    showPageError(error);
  }
}

function clientStatus(client) {
  if (client.revokedAt || client.revoked_at) return { label: "Revoked", tone: "danger" };
  if (client.active === false || client.active === 0) return { label: "Disabled", tone: "neutral" };
  return { label: "Active", tone: "success" };
}

async function renderClients() {
  const data = await api.get("/api/clients", { projectId: state.projectId });
  const clients = list(data?.clients);
  const models = modelsOf(data?.models);
  const canWriteProject = canWriteCurrentProject();

  const nameInput = h("input", { className: "input", type: "text", maxlength: "80", required: "", autocomplete: "off", placeholder: "e.g. Local coding assistant" });
  const scopeOptions = modelCheckboxes(models);
  const createForm = h("form", { className: "panel", autocomplete: "off" },
    h("div", { className: "panel-header" }, h("div", {}, h("h2", {}, "Register a confidential client"), h("p", { className: "panel-description" }, "For local, browser, or mobile apps, use the pairing flow below. Public clients are created only after you approve a pairing request."))),
    h("div", { className: "form-grid" },
      field("Client name", nameInput, "Choose a recognizable name for this app or device."),
      fieldGroup("Allowed models", scopeOptions, "The client can use only the models selected here.", true),
    ),
    h("div", { className: "form-actions" }, h("button", { className: "button", type: "submit" }, "Create client")),
  );
  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!createForm.reportValidity()) return;
    const request = {
      projectId: state.projectId,
      name: nameInput.value.trim(),
      kind: "confidential",
      models: checkedModels(scopeOptions),
    };
    try {
      const result = await api.post("/api/clients", request);
      nameInput.value = "";
      if (typeof result?.clientSecret === "string" && result.clientSecret) {
        showOneTimeValue({
          title: "Save the client secret",
          description: "Identity will not show this secret again. Store it in the confidential runtime that owns this client.",
          label: "Client secret",
          value: result.clientSecret,
          warning: "This is a machine credential, separate from your OIDC sign-in and provider API keys.",
        });
      } else {
        setLiveMessage("Client created. A secret was not returned; rotate the client if it needs one.");
      }
      await loadCurrentView();
    } catch (error) {
      showInlineError(createForm, error);
    }
  });

  const clientRows = clients.map((client) => {
    const id = clientIdOf(client);
    const status = clientStatus(client);
    const canManage = client.canManage === true;
    const kind = client.kind === "confidential" ? "Confidential" : "Public";
    const modelSummary = modelsOf(clientModelsOf(client)).map((model) => `${model.label} · ${model.provider}`).join(", ") || "No model access";
    const editDetails = h("details", { className: "client-edit" },
      h("summary", { className: "button ghost small" }, "Edit model access"),
      h("form", { className: "client-model-form" },
        modelCheckboxes(models, clientModelsOf(client)),
        h("div", { className: "form-actions" }, h("button", { className: "button secondary small", type: "submit" }, "Save access")),
      ),
    );
    const modelForm = editDetails.querySelector("form");
    modelForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!id) return;
      try {
        await api.put(`/api/clients/${encodeURIComponent(id)}/models`, { models: checkedModels(modelForm) });
        setLiveMessage("Client model access updated.");
        await loadCurrentView();
      } catch (error) { showInlineError(modelForm, error); }
    });
    const actions = h("div", { className: "row-actions" },
      canManage ? editDetails : null,
      button("Download setup", () => downloadBootstrap(client), "secondary", { small: true, title: "Download secret-free client setup metadata" }),
      client.kind === "confidential" && canManage ? button("Rotate secret", async () => {
        if (!id || !confirmAction(`Rotate the secret for ${display(client.name, "this client")}? The old secret will stop working.`)) return;
        try {
          const result = await api.post(`/api/clients/${encodeURIComponent(id)}/rotate`, {});
          if (typeof result?.clientSecret === "string" && result.clientSecret) {
            showOneTimeValue({ title: "Save the new client secret", description: "The previous secret has been replaced. Identity will not display this value again.", label: "New client secret", value: result.clientSecret });
          }
          await loadCurrentView();
        } catch (error) { showPageError(error); }
      }, "secondary", { small: true }) : null,
      status.label === "Active" && canWriteProject ? button("Revoke", async () => {
        if (!id || !confirmAction(`Revoke ${display(client.name, "this client")}? Its active sessions will no longer be authorized.`)) return;
        await runAction(() => api.post(`/api/clients/${encodeURIComponent(id)}/revoke`, {}), "Client revoked.");
      }, "danger", { small: true }) : null,
    );
    return h("div", { className: "list-row" },
      h("div", {},
        h("div", { className: "row-title" }, display(client.name, display(client.clientIdentifier, "Unnamed client"))),
        h("div", { className: "row-meta" }, `${kind} · ${modelSummary}`),
        client.clientIdentifier ? h("div", { className: "row-meta monospace" }, client.clientIdentifier) : null,
      ),
      h("div", { className: "row-actions" }, badge(status.label, status.tone), actions),
    );
  });
  const clientList = clientRows.length ? h("div", { className: "list" }, ...clientRows) : emptyState("No clients registered", "Create a client when you are ready to connect an application.", "⌘");

  const pairCodeInput = h("input", { className: "input monospace", type: "text", maxlength: "24", autocapitalize: "characters", autocomplete: "off", spellcheck: "false", placeholder: "ABCD-EFGH", required: "" });
  const pairLookup = h("form", { className: "inline-form" }, field("Device code", pairCodeInput, "Enter the code shown by the local adapter."), h("button", { type: "submit", className: "button secondary" }, "Review device"));
  const pairResult = h("div", { className: "pair-result" });
  let pairingCode = "";
  pairLookup.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!pairLookup.reportValidity()) return;
    const code = pairCodeInput.value.trim();
    pairCodeInput.value = "";
    try {
      const result = await api.get("/api/pairing/lookup", { userCode: code });
      const pairing = isRecord(result?.pairing) ? result.pairing : result;
      if (!isRecord(pairing)) throw new Error("Identity returned an invalid pairing request.");
      pairingCode = code;
      pairResult.replaceChildren(renderPairApproval(pairing, models, () => pairingCode, () => { pairingCode = ""; pairResult.replaceChildren(); }));
    } catch (error) {
      pairingCode = "";
      pairResult.replaceChildren(alertBox(error instanceof Error ? error.message : "Could not look up the pairing request."));
    }
  });

  const membersPanel = await renderProjectMembers();
  const limitsPanel = await renderProjectLimits();
  return [
    canWriteProject ? createForm : panel("Register a client", "Only project owners and admins can create clients.", notice("Ask a project owner or admin to register a client or approve a pairing request.", "info")),
    h("div", { className: "section-grid two" },
      panel("Registered clients", "Each client has its own model permissions and revocation state.", clientList),
      canWriteProject ? panel("Pair a local adapter", "Approve a device only when you started the pairing and recognize its name.", h("div", {}, pairLookup, pairResult)) : panel("Pair a local adapter", "Only project owners and admins can approve pairing requests.", emptyState("Pairing approval unavailable", "Ask a project owner or admin to approve a device.")),
    ),
    h("div", { className: "section-grid two" }, membersPanel, limitsPanel),
  ];
}

async function renderProjectMembers() {
  const project = list(state.session?.projects).find((item) => projectIdOf(item) === state.projectId);
  if (!project) return notice("Select a project to review its members.", "warning");
  let data;
  try {
    data = await api.get(`/api/projects/${encodeURIComponent(state.projectId)}/members`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return panel("Project members", "Membership management is being enabled for this Identity deployment.", emptyState("Member list unavailable", "The project membership endpoint is not available yet."));
    }
    throw error;
  }
  const members = list(data?.members ?? data);
  const canManage = project.role === "owner" || project.role === "admin";
  const rows = members.map((member) => {
    const userId = typeof member.userId === "string" ? member.userId : "";
    const role = display(member.role, "member");
    const name = display(member.displayName, display(member.email, "Project member"));
    const canRemove = canManage && role !== "owner" && (project.role === "owner" || role !== "admin");
    return h("div", { className: "list-row" },
      h("div", {}, h("div", { className: "row-title" }, name), h("div", { className: "row-meta" }, display(member.email, "")), h("div", { className: "row-meta" }, `Added ${dateLabel(member.createdAt ?? member.created_at)}`)),
      h("div", { className: "row-actions" }, badge(role, role === "owner" ? "warning" : "neutral"), canRemove ? button("Remove", async () => {
        if (!userId || !confirmAction(`Remove ${name} from this project? Their project access will end.`)) return;
        await runAction(() => api.delete(`/api/projects/${encodeURIComponent(state.projectId)}/members/${encodeURIComponent(userId)}`), "Project member removed.");
      }, "danger", { small: true }) : null),
    );
  });
  const memberList = rows.length ? h("div", { className: "list" }, ...rows) : emptyState("No project members", "Invite an allowlisted identity to share this project.");
  if (!canManage) {
    return panel("Project members", "Access is limited to the members listed here.", memberList);
  }

  const issuerInput = h("input", { className: "input", type: "url", required: "", autocomplete: "off", placeholder: "https://login.example.com" });
  const subjectInput = h("input", { className: "input", type: "text", required: "", autocomplete: "off", placeholder: "Stable OIDC subject" });
  const roleSelect = h("select", { className: "select" }, h("option", { value: "member" }, "Member"), project.role === "owner" ? h("option", { value: "admin" }, "Project admin") : null);
  const form = h("form", { className: "project-member-form" },
    h("div", { className: "form-grid" },
      field("OIDC issuer", issuerInput, "Use the exact issuer from the person's verified login."),
      field("OIDC subject", subjectInput, "Email alone does not identify an account."),
      field("Project role", roleSelect),
    ),
    h("div", { className: "form-actions" }, h("button", { type: "submit", className: "button secondary" }, "Add member")),
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    try {
      await api.post(`/api/projects/${encodeURIComponent(state.projectId)}/members`, {
        issuer: issuerInput.value.trim(),
        subject: subjectInput.value.trim(),
        role: roleSelect.value,
      });
      await loadCurrentView();
      setLiveMessage("Project member added.");
    } catch (error) {
      showInlineError(form, error);
    }
  });
  return panel("Project members", "Only active allowlisted identities can be added. Owners cannot be removed here.", h("div", {}, memberList, form));
}

async function renderProjectLimits() {
  const project = list(state.session?.projects).find((item) => projectIdOf(item) === state.projectId);
  if (!project) return panel("Project limits", "Control request size, concurrency, and connection lifetime.", notice("Select a project to review limits.", "warning"));
  let response;
  try {
    response = await api.get(`/api/projects/${encodeURIComponent(state.projectId)}/limits`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return panel("Project limits", "Control request size, concurrency, and connection lifetime.", emptyState("Project limits unavailable", "Limit management is not available on this Identity deployment yet."));
    }
    if (error instanceof ApiError && error.status === 403) {
      return panel("Project limits", "Control request size, concurrency, and connection lifetime.", notice("Only project owners and admins can review these limits."));
    }
    throw error;
  }
  const limits = isRecord(response?.limits) ? response.limits : {};
  const maxPayloadBytes = h("input", { className: "input", type: "number", min: "1024", max: "1048576", step: "1", required: "", value: Number.isInteger(limits.maxPayloadBytes) ? String(limits.maxPayloadBytes) : "1048576" });
  const maxConcurrency = h("input", { className: "input", type: "number", min: "1", max: "8", step: "1", required: "", value: Number.isInteger(limits.maxConcurrency) ? String(limits.maxConcurrency) : "8" });
  const maxSessionSeconds = h("input", { className: "input", type: "number", min: "30", max: "300", step: "1", required: "", value: Number.isInteger(limits.maxSessionSeconds) ? String(limits.maxSessionSeconds) : "300" });
  const canManage = project.role === "owner" || project.role === "admin";
  for (const input of [maxPayloadBytes, maxConcurrency, maxSessionSeconds]) input.disabled = !canManage;
  const form = h("form", { className: "project-limits-form" },
    h("div", { className: "form-grid" },
      field("Maximum provider request body", maxPayloadBytes, "Serialized provider JSON bytes, including server-selected model and stream fields."),
      field("Concurrent requests", maxConcurrency, "Maximum active requests on each Gateway socket."),
      field("Maximum socket lifetime", maxSessionSeconds, "Gateway closes the socket at this limit, including active work."),
    ),
    canManage ? h("div", { className: "form-actions" }, h("button", { type: "submit", className: "button secondary" }, "Save limits")) : null,
  );
  if (canManage) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const updated = {
        maxPayloadBytes: Number(maxPayloadBytes.value),
        maxConcurrency: Number(maxConcurrency.value),
        maxSessionSeconds: Number(maxSessionSeconds.value),
      };
      try {
        await api.put(`/api/projects/${encodeURIComponent(state.projectId)}/limits`, updated);
        await loadCurrentView();
        setLiveMessage("Project limits saved.");
      } catch (error) {
        showInlineError(form, error);
      }
    });
  }
  return panel("Project limits", "Gateway applies these limits before sending a request to a provider.", h("div", {}, form));
}

function renderPairApproval(pairing, models, getCode, clear) {
  const name = display(pairing.clientName, display(pairing.deviceName, "Local adapter"));
  const detail = h("div", { className: "notice warning" },
    h("span", { className: "notice-icon", "aria-hidden": "true" }, "!"),
    h("span", {}, h("strong", {}, `Approve ${name}?`), h("br"), `This gives the device access to the selected project and models. Expires ${dateLabel(pairing.expiresAt)}.`),
  );
  const choices = modelCheckboxes(models);
  const actions = h("div", { className: "form-actions" },
    button("Deny", async () => {
      const userCode = getCode();
      if (!userCode) return;
      try { await api.post("/api/pairing/deny", { userCode }); clear(); setLiveMessage("Device pairing denied."); }
      catch (error) { showInlineError(actions, error); }
    }, "danger", { small: true }),
    button("Approve device", async () => {
      const userCode = getCode();
      if (!userCode) return;
      try {
        await api.post("/api/pairing/approve", { userCode, projectId: state.projectId, models: checkedModels(choices) });
        clear();
        setLiveMessage("Device pairing approved.");
      } catch (error) { showInlineError(actions, error); }
    }, "primary", { small: true }),
  );
  return h("div", { className: "pair-approval" }, detail, h("div", { className: "divider" }), fieldGroup("Allowed models", choices, "Choose only the models this device needs."), actions);
}

function providerIdOf(provider) {
  return typeof provider.provider === "string" ? provider.provider : "";
}

function credentialIdOf(credential) {
  return typeof credential.id === "string" ? credential.id : typeof credential.credentialId === "string" ? credential.credentialId : "";
}

function parsePublicProviderBaseUrl(value) {
  try {
    const endpoint = new URL(value);
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) return undefined;
    return endpoint;
  } catch {
    return undefined;
  }
}

function clearOAuthConnectionState() {
  state.oauthPairingId = undefined;
  state.oauthPairingExpiresAt = undefined;
  state.oauthPairingPort = undefined;
  state.oauthControlToken = undefined;
  state.oauthControlExpiresAt = undefined;
  state.oauthControlPort = undefined;
  state.oauthLoginStatus = undefined;
  state.oauthModels = [];
  state.oauthAlias = "";
  state.oauthBoundAliases = [];
  state.oauthAdapterReachable = undefined;
  state.oauthAuthorizationUrl = undefined;
  state.oauthProfileEmail = undefined;
  state.oauthError = undefined;
  state.oauthNotice = undefined;
}

function localOAuthEndpoint(path, portOverride) {
  const rawPort = portOverride === undefined ? state.oauthPort : String(portOverride);
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !/^\d{1,5}$/.test(String(rawPort).trim())) {
    throw new Error("Enter the local adapter port shown in its configuration.");
  }
  if (!path.startsWith("/local/oauth/") || path.includes("?") || path.includes("#")) {
    throw new Error("Local OAuth route is invalid.");
  }
  return `http://127.0.0.1:${port}${path}`;
}

async function localOAuthRequest(path, { method = "GET", body, controlToken } = {}) {
  const headers = new Headers({ Accept: "application/json" });
  if (body !== undefined) headers.set("Content-Type", "application/json");
  if (controlToken) headers.set("Authorization", `Bearer ${controlToken}`);
  const pinnedPort = controlToken
    ? state.oauthControlPort
    : path === "/local/oauth/pair/approve" || path === "/local/oauth/pair/start" ? state.oauthPairingPort : undefined;
  let response;
  try {
    response = await fetch(localOAuthEndpoint(path, pinnedPort), {
      method,
      mode: "cors",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
  } catch {
    state.oauthAdapterReachable = false;
    throw new Error("Could not reach the local adapter on this browser device. Start it and check the port. Hosted ChatGPT sessions may not be able to reach your computer; no port scan or remote fallback is used.");
  }
  let payload;
  try { payload = await response.json(); } catch { payload = undefined; }
  if (!response.ok) {
    const code = payload?.error?.code;
    const messages = {
      approval_rejected: "The local approval code did not match. Check the code printed by your adapter.",
      pairing_expired: "The local approval code expired. Start a new pairing request.",
      grant_unavailable: "The Identity pairing grant expired or was already used. Start a new pairing request.",
      login_pending: "Finish ChatGPT sign-in in the authorization tab before discovering models.",
      unauthorized: "The local OAuth control session expired. Start a new connection.",
      oauth_unavailable: "The local OAuth operation could not be completed. Try again from the local adapter.",
      rate_limited: "Too many pairing attempts. Wait briefly and try again.",
    };
    throw new Error(messages[code] ?? `The local adapter rejected the request (${response.status}).`);
  }
  return payload;
}

async function checkLocalOAuthAdapter() {
  state.oauthError = undefined;
  state.oauthNotice = undefined;
  try {
    const health = await localOAuthRequest("/local/oauth/health");
    if (health?.reachable !== true) throw new Error("The local adapter did not confirm its bridge is reachable.");
    state.oauthAdapterReachable = true;
    state.oauthNotice = health.oauthAvailable === true
      ? "The local adapter is reachable and has the OAuth bridge enabled."
      : "The adapter is reachable, but this adapter build has no ChatGPT OAuth connector enabled.";
  } catch (error) {
    state.oauthAdapterReachable = false;
    state.oauthError = error instanceof Error ? error.message : "The local adapter could not be reached.";
  }
  await loadCurrentView();
}

async function beginChatGptPairing() {
  if (state.busy || !state.projectId) return;
  state.oauthError = undefined;
  state.oauthNotice = undefined;
  setBusy(true);
  let pairingToken = "";
  try {
    const selectedPort = Number(state.oauthPort);
    localOAuthEndpoint("/local/oauth/health");
    state.oauthPairingPort = selectedPort;
    const health = await localOAuthRequest("/local/oauth/health");
    state.oauthAdapterReachable = health?.reachable === true;
    if (health?.oauthAvailable !== true) throw new Error("The local adapter is reachable but does not have ChatGPT OAuth enabled.");
    const grant = await api.post("/api/oauth/pairing", { projectId: state.projectId, connectorId: "chatgpt" });
    pairingToken = typeof grant?.pairingToken === "string" ? grant.pairingToken : "";
    if (!/^ogt_[A-Za-z0-9_-]{43}$/.test(pairingToken)) throw new Error("Identity returned an invalid one-time pairing grant.");
    const local = await localOAuthRequest("/local/oauth/pair/start", { method: "POST", body: { pairingToken } });
    pairingToken = "";
    if (typeof local?.pairingId !== "string" || !Number.isSafeInteger(local.expiresAt)) throw new Error("The local adapter returned an invalid pairing response.");
    state.oauthPairingId = local.pairingId;
    state.oauthPairingExpiresAt = local.expiresAt;
    state.oauthControlToken = undefined;
    state.oauthControlPort = undefined;
    state.oauthLoginStatus = undefined;
    state.oauthModels = [];
    state.oauthNotice = "A one-time code was printed in the local adapter terminal. Enter it here within two minutes to approve ChatGPT sign-in.";
  } catch (error) {
    pairingToken = "";
    state.oauthError = error instanceof Error ? error.message : "ChatGPT pairing could not be started.";
  } finally {
    setBusy(false);
    await loadCurrentView();
  }
}

async function approveLocalChatGptPairing(code) {
  if (state.busy || !state.oauthPairingId) return;
  state.oauthError = undefined;
  state.oauthNotice = undefined;
  setBusy(true);
  try {
    const result = await localOAuthRequest("/local/oauth/pair/approve", {
      method: "POST",
      body: { pairingId: state.oauthPairingId, approvalCode: code },
    });
    if (typeof result?.controlToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(result.controlToken)) {
      throw new Error("The local adapter returned an invalid control session.");
    }
    let authorizationUrl;
    try { authorizationUrl = new URL(result.authorizationUrl); } catch { throw new Error("The local adapter returned an invalid sign-in link."); }
    if (authorizationUrl.origin !== "https://auth.openai.com" || authorizationUrl.pathname !== "/api/accounts/authorize") {
      throw new Error("The local adapter returned an untrusted sign-in link.");
    }
    state.oauthControlToken = result.controlToken;
    state.oauthControlExpiresAt = result.expiresAt;
    state.oauthPairingId = undefined;
    state.oauthPairingExpiresAt = undefined;
    state.oauthControlPort = state.oauthPairingPort;
    state.oauthPairingPort = undefined;
    state.oauthAuthorizationUrl = authorizationUrl.toString();
    state.oauthLoginStatus = { status: "pending" };
    state.oauthModels = [];
    state.oauthNotice = "Local approval succeeded. Open the ChatGPT sign-in page, complete authorization, then check status here.";
  } catch (error) {
    state.oauthError = error instanceof Error ? error.message : "Local approval could not be completed.";
  } finally {
    setBusy(false);
    await loadCurrentView();
  }
}

async function checkChatGptOAuthStatus() {
  if (state.busy || !state.oauthControlToken) return;
  state.oauthError = undefined;
  state.oauthNotice = undefined;
  setBusy(true);
  try {
    const status = await localOAuthRequest("/local/oauth/status", { controlToken: state.oauthControlToken });
    if (status?.status === "connected") {
      state.oauthLoginStatus = { status: "connected", modelsAvailable: status.modelsAvailable };
      state.oauthProfileEmail = typeof status.email === "string" ? status.email : undefined;
      const discovery = await localOAuthRequest("/local/oauth/models", { controlToken: state.oauthControlToken });
      state.oauthModels = Array.isArray(discovery?.models) ? discovery.models.filter(isRecord).slice(0, 500) : [];
      state.oauthBoundAliases = Array.isArray(discovery?.boundAliases)
        ? [...new Set(discovery.boundAliases.filter((alias) => typeof alias === "string" && /^[^\u0000-\u0020]{1,128}$/.test(alias)))].slice(0, 256)
        : [];
      state.oauthNotice = "ChatGPT is connected on the local adapter. Discovered models are catalog metadata only; project and client model grants still apply.";
    } else if (status?.status === "pending") {
      state.oauthLoginStatus = { status: "pending" };
      state.oauthNotice = "ChatGPT sign-in is still waiting for approval in the browser tab opened from the local adapter.";
    } else if (status?.status === "failed") {
      state.oauthLoginStatus = { status: "failed", code: status.code };
      state.oauthNotice = "ChatGPT sign-in did not complete. Start a new local pairing request to try again.";
    } else {
      throw new Error("The local adapter returned an invalid OAuth status.");
    }
  } catch (error) {
    state.oauthError = error instanceof Error ? error.message : "ChatGPT status could not be checked.";
  } finally {
    setBusy(false);
    await loadCurrentView();
  }
}

async function bindLocalChatGptModelAlias(aliasValue) {
  const alias = aliasValue.trim();
  if (state.busy || !state.oauthControlToken) return;
  if (!/^[^\u0000-\u0020]{1,128}$/.test(alias)) {
    state.oauthError = "Enter an existing OpenAI model alias from this project.";
    await loadCurrentView();
    return;
  }
  if (!confirmAction(`Bind the local ChatGPT profile to project model alias “${alias}”? This replaces any local API-key or OAuth mapping for that alias. It does not grant project or client access.`)) return;
  state.oauthError = undefined;
  state.oauthNotice = undefined;
  setBusy(true);
  try {
    const result = await localOAuthRequest("/local/oauth/model", {
      method: "POST", body: { alias }, controlToken: state.oauthControlToken,
    });
    if (result?.bound !== true || result.alias !== alias) throw new Error("The local adapter returned an invalid model binding response.");
    state.oauthAlias = alias;
    state.oauthBoundAliases = [...new Set([...state.oauthBoundAliases, alias])].slice(0, 256);
    state.oauthNotice = `Local ChatGPT profile mapped to ${alias}. Identity still checks this user's active project and client model grants for each Responses request.`;
  } catch (error) {
    state.oauthError = error instanceof Error ? error.message : "The local model alias could not be mapped.";
  } finally {
    setBusy(false);
    await loadCurrentView();
  }
}

async function disconnectLocalChatGpt() {
  if (state.busy || !state.oauthControlToken) return;
  state.oauthError = undefined;
  setBusy(true);
  try {
    await localOAuthRequest("/local/oauth/disconnect", { method: "POST", body: {}, controlToken: state.oauthControlToken });
    clearOAuthConnectionState();
    state.oauthNotice = "ChatGPT was disconnected from the local adapter. This does not revoke any Identity credential already issued.";
  } catch (error) {
    state.oauthError = error instanceof Error ? error.message : "ChatGPT could not be disconnected.";
  } finally {
    setBusy(false);
    await loadCurrentView();
  }
}

async function renderConnections() {
  const data = await api.get("/api/oauth/connectors");
  const connectors = list(data?.connectors);
  const chatgpt = connectors.find((connector) => connector.id === "chatgpt");
  const claude = connectors.find((connector) => connector.id === "claude");
  const portInput = h("input", {
    className: "input monospace",
    type: "text",
    inputmode: "numeric",
    pattern: "[0-9]{1,5}",
    maxlength: "5",
    autocomplete: "off",
    value: state.oauthPort,
    "aria-label": "Local adapter port",
    onInput: (event) => { state.oauthPort = event.target.value; },
  });
  const portForm = h("form", { className: "inline-form", onSubmit: (event) => { event.preventDefault(); void checkLocalOAuthAdapter(); } },
    field("Local adapter port", portInput, "Enter the port shown by the adapter; the browser contacts only 127.0.0.1 and does not scan ports."),
    h("button", { type: "submit", className: "button secondary", disabled: state.busy, "data-busy-disabled": "true" }, "Check local adapter"),
  );
  const pairingForm = h("div", { className: "form-actions" },
    button("Connect ChatGPT", beginChatGptPairing, "primary", { disabled: state.busy || chatgpt?.localOAuth?.enabled !== true }),
  );
  let approvalForm;
  if (state.oauthPairingId) {
    const codeInput = h("input", {
      className: "input monospace",
      type: "text",
      inputmode: "numeric",
      pattern: "[0-9]{8}",
      minlength: "8",
      maxlength: "8",
      autocomplete: "one-time-code",
      required: "",
      placeholder: "00000000",
    });
    approvalForm = h("form", { className: "inline-form", onSubmit: (event) => {
      event.preventDefault();
      if (!approvalForm.reportValidity()) return;
      const code = codeInput.value;
      codeInput.value = "";
      void approveLocalChatGptPairing(code);
    } },
      field("Local approval code", codeInput, "Enter the eight-digit code printed by the adapter. It is never sent to Identity."),
      h("button", { type: "submit", className: "button primary", disabled: state.busy, "data-busy-disabled": "true" }, "Approve locally"),
    );
  }
  const authLink = state.oauthAuthorizationUrl
    ? h("a", { className: "button secondary", href: state.oauthAuthorizationUrl, target: "_blank", rel: "noopener noreferrer" }, "Open ChatGPT sign-in")
    : null;
  const statusActions = state.oauthControlToken ? h("div", { className: "form-actions" },
    button("Check sign-in status and models", checkChatGptOAuthStatus, "secondary", { disabled: state.busy, title: "Check only this paired local adapter." }),
    state.oauthLoginStatus?.status === "connected"
      ? button("Disconnect local profile", disconnectLocalChatGpt, "danger", { disabled: state.busy, small: true })
      : null,
  ) : null;
  const aliasInput = h("input", {
    className: "input monospace", type: "text", maxlength: "128", autocomplete: "off",
    value: state.oauthAlias, placeholder: "project-openai-alias", "aria-label": "Existing OpenAI project model alias",
    onInput: (event) => { state.oauthAlias = event.target.value; },
  });
  const aliasForm = state.oauthLoginStatus?.status === "connected"
    ? h("form", { className: "inline-form", onSubmit: (event) => {
      event.preventDefault();
      void bindLocalChatGptModelAlias(aliasInput.value);
    } },
      field("Existing OpenAI project model alias", aliasInput, "Use an alias already authorized for your project and client. The adapter will not create or expand grants."),
      h("button", { type: "submit", className: "button secondary", disabled: state.busy, "data-busy-disabled": "true" }, "Bind local profile"),
    )
    : null;
  const boundAliases = state.oauthBoundAliases.length
    ? h("div", { className: "list" }, ...state.oauthBoundAliases.map((alias) => h("div", { className: "list-row" },
      h("div", { className: "row-title monospace" }, alias), badge("Local mapping", "neutral"),
    )))
    : null;
  const modelRows = state.oauthModels.map((model) => h("div", { className: "list-row" },
    h("div", {},
      h("div", { className: "row-title" }, display(model.displayName, display(model.id))),
      h("div", { className: "row-meta monospace" }, model.id),
      h("div", { className: "row-meta" }, [
        Number.isSafeInteger(model.contextWindow) ? `${model.contextWindow.toLocaleString()} token context` : null,
        Array.isArray(model.inputModalities) && model.inputModalities.length ? `Input: ${model.inputModalities.join(", ")}` : null,
        Array.isArray(model.reasoningEfforts) && model.reasoningEfforts.length ? `Reasoning: ${model.reasoningEfforts.join(", ")}` : null,
      ].filter(Boolean).join(" · ")),
    ),
    badge("Catalog only", "neutral"),
  ));
  const modelContent = modelRows.length
    ? h("div", { className: "list" }, ...modelRows)
    : emptyState("No ChatGPT models discovered", "Connect a ChatGPT profile and check status to load its safe model catalog.", "↗");
  const remote = isRecord(chatgpt?.remoteInference) ? chatgpt.remoteInference : {};
  const remoteNotice = remote.enabled === true
    ? notice("The operator has enabled hosted ChatGPT Responses inference. Use the native /v1/responses API; OAuth credentials are not supported by Chat Completions.", "warning")
    : notice("Hosted ChatGPT inference is disabled while eligibility is pending. Local sign-in and model discovery do not enable Gateway inference.", "warning");
  const safeConnector = panel("ChatGPT", "Connect a ChatGPT account to the local adapter. Access and refresh tokens remain on the adapter host.",
    h("div", { className: "stack" },
      remoteNotice,
      notice("This browser bridge reaches only 127.0.0.1 on the port you enter. If you are using a hosted ChatGPT session, the adapter may be unreachable; run the adapter on this same device. A remote CLI or manual callback flow is not available yet.", "info"),
      portForm,
      state.oauthAdapterReachable === false ? alertBox("The local adapter is unreachable. Confirm it is running on this computer and the port is correct; no automatic port scanning was attempted.", "info") : null,
      state.oauthAdapterReachable === true ? notice("The local adapter responded to the exact-origin bridge health check.", "info") : null,
      state.oauthNotice ? notice(state.oauthNotice, "info") : null,
      state.oauthError ? alertBox(state.oauthError) : null,
      pairingForm,
      approvalForm ?? null,
      authLink,
      state.oauthLoginStatus?.status === "pending" ? badge("Sign-in pending", "warning") : null,
      state.oauthLoginStatus?.status === "connected" ? badge(`Connected${state.oauthProfileEmail ? ` · ${state.oauthProfileEmail}` : ""}`, "success") : null,
      state.oauthLoginStatus?.status === "failed" ? badge("Sign-in incomplete", "danger") : null,
      statusActions,
      aliasForm,
      boundAliases,
    ),
  );
  const modelPanel = panel("Discovered models", "Catalog IDs are upstream metadata. Bind an existing project alias above; Identity still enforces active project and client model grants. OAuth-mapped aliases use only /v1/responses.", modelContent);
  const claudePanel = panel("Claude subscription OAuth", "This connector is disabled because an authorized third-party subscription integration is unavailable.",
    h("div", { className: "stack" },
      badge("Unavailable", "neutral"),
      h("p", { className: "panel-description" }, display(claude?.localOAuth?.reasonCode, "subscription_oauth_unavailable") === "subscription_oauth_unavailable"
        ? "Use an Anthropic Console API credential from the Providers screen. Claude subscription sign-in is not connected to Gateway inference."
        : "This connector is disabled by Identity policy."),
    ),
  );
  return [safeConnector, modelPanel, claudePanel];
}

async function renderProviders() {
  const data = await api.get("/api/providers", { projectId: state.projectId });
  const providers = list(data?.providers);
  const credentials = list(data?.credentials);
  const enabledProviders = providers.filter((provider) => enabled(provider.enabled));
  const canWriteProject = canWriteCurrentProject();
  const isSystemAdmin = state.session?.user?.isAdmin === true;

  const customProviderId = h("input", { className: "input", required: "", maxlength: 32, pattern: "[a-z][a-z0-9_-]{0,31}", autocomplete: "off", placeholder: "my_provider" });
  const customProviderName = h("input", { className: "input", required: "", maxlength: 80, autocomplete: "off", placeholder: "My provider" });
  const customProviderBaseUrl = h("input", { className: "input", type: "url", required: "", maxlength: 2048, autocomplete: "off", placeholder: "https://api.example.com/v1" });
  const customProviderForm = isSystemAdmin ? h("form", { className: "panel", autocomplete: "off" },
    h("div", { className: "panel-header" }, h("div", {}, h("h2", {}, "Add a custom provider"), h("p", { className: "panel-description" }, "Register a public HTTPS endpoint that implements the OpenAI chat completions API."))),
    notice("Only a system administrator can register custom endpoints and change their Base URL. Same-origin path changes retain saved credentials; changing origin revokes every saved credential for that provider and requires reenrollment. Built-in provider endpoints and protocols remain fixed. API keys use the existing encrypted credential form below.", "info"),
    h("div", { className: "form-grid spaced-form-grid" },
      field("Provider ID", customProviderId, "Lowercase ID used for credential ownership and model grants."),
      field("Display name", customProviderName),
      field("Base URL", customProviderBaseUrl, "Include the API path prefix. The service appends /chat/completions. Private, local, and insecure endpoints are blocked.", true),
    ),
    h("p", { className: "field-help" }, "Protocol: OpenAI-compatible. The registered URL is server-controlled and never comes from a model request."),
    h("div", { className: "form-actions" }, h("button", { className: "button secondary", type: "submit", disabled: state.busy, "data-busy-disabled": "true" }, "Register provider")),
  ) : null;
  customProviderForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!customProviderForm.reportValidity()) return;
    const id = customProviderId.value.trim();
    const displayName = customProviderName.value.trim();
    const baseUrl = customProviderBaseUrl.value.trim();
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(id) || !displayName || !baseUrl) {
      showInlineError(customProviderForm, new Error("Check the provider ID, display name, and HTTPS base URL."));
      return;
    }
    if (providers.some((provider) => providerIdOf(provider) === id)) {
      showInlineError(customProviderForm, new Error("That provider ID is already registered. Choose a different provider ID."));
      return;
    }
    if (!parsePublicProviderBaseUrl(baseUrl)) {
      showInlineError(customProviderForm, new Error("Provider URLs must use HTTPS and cannot contain credentials, query strings, or fragments."));
      return;
    }
    setBusy(true);
    try {
      await api.post("/api/providers", { id, displayName, baseUrl, protocol: "openai" });
      setLiveMessage(`Custom provider ${displayName} registered.`);
      await loadCurrentView();
    } catch (error) {
      showInlineError(customProviderForm, error);
    } finally {
      setBusy(false);
    }
  });

  const keyProvider = h("select", { className: "select", required: "" },
    h("option", { value: "" }, "Choose a provider"),
    ...enabledProviders.map((provider) => h("option", { value: providerIdOf(provider) }, display(provider.displayName, providerIdOf(provider)))),
  );
  const keyProviderDestination = h("p", { className: "field-help", role: "status", "aria-live": "polite" }, "Choose a provider to review where this key will be sent.");
  const updateKeyProviderDestination = () => {
    const selected = enabledProviders.find((provider) => providerIdOf(provider) === keyProvider.value);
    keyProviderDestination.textContent = selected
      ? `This key will be sent to ${display(selected.baseUrl, "the configured provider endpoint")}. Review this endpoint before saving.`
      : "Choose a provider to review where this key will be sent.";
  };
  keyProvider.addEventListener("change", updateKeyProviderDestination);
  const apiKeyInput = h("input", { className: "input", type: "password", maxlength: "8192", autocomplete: "new-password", autocapitalize: "off", spellcheck: "false", placeholder: "Paste provider API key", required: "" });
  const keyForm = h("form", { className: "panel", autocomplete: "off" },
    h("div", { className: "panel-header" }, h("div", {}, h("h2", {}, "Add a provider key"), h("p", { className: "panel-description" }, "This key is encrypted by Identity and is not shown or exported again."))),
    notice("Your organization sign-in is separate from this provider API key. This field sends the key only to Identity over HTTPS; the adapter receives an encrypted envelope.", "info"),
    h("div", { className: "form-grid spaced-form-grid" },
      field("LLM provider", keyProvider, "Choose from the server-configured provider list."),
      field("Provider API key", apiKeyInput, "The raw key is never saved in browser storage or included in exports."),
    ),
    keyProviderDestination,
    h("div", { className: "form-actions" }, h("button", { className: "button", type: "submit" }, "Encrypt and save")),
  );
  keyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!keyForm.reportValidity()) return;
    let apiKey = apiKeyInput.value;
    apiKeyInput.value = "";
    if (!apiKey) return;
    if (new TextEncoder().encode(apiKey).byteLength > 8_192) {
      apiKey = "";
      showInlineError(keyForm, new Error("Provider keys must be 8 KiB or less."));
      return;
    }
    try {
      const selectedProvider = enabledProviders.find((provider) => providerIdOf(provider) === keyProvider.value);
      if (!selectedProvider) {
        apiKey = "";
        showInlineError(keyForm, new Error("Choose an enabled provider before saving this key."));
        return;
      }
      if (selectedProvider.custom === true && typeof selectedProvider.baseUrl !== "string") {
        apiKey = "";
        showInlineError(keyForm, new Error("The selected provider endpoint is unavailable. Reload the provider list before entering a key."));
        return;
      }
      const credentialRequest = { projectId: state.projectId, provider: keyProvider.value, apiKey };
      if (selectedProvider.custom === true) credentialRequest.expectedBaseUrl = selectedProvider.baseUrl;
      const result = await api.post("/api/credentials", credentialRequest);
      apiKey = "";
      const envelope = isRecord(result?.envelope) ? result.envelope : undefined;
      if (envelope) {
        showOneTimeValue({
          title: "Save the encrypted credential envelope",
          description: "The adapter needs this envelope with a short-lived Gateway token. Identity will not return it again; if you lose it, add the provider key again.",
          label: "Credential envelope JSON",
          value: JSON.stringify(envelope),
          warning: "Treat this envelope as sensitive. It does not contain the raw provider key, but it can be used with a valid account token until revoked or expired.",
          testAction: async () => {
            const credentialId = credentialIdOf(result.credential ?? {});
            if (!credentialId) throw new Error("Identity did not return a credential ID for testing.");
            return api.post(`/api/credentials/${encodeURIComponent(credentialId)}/test`, { envelope });
          },
        });
      } else {
        setLiveMessage("Provider key encrypted. Identity did not return an envelope to copy.");
      }
      await loadCurrentView();
    } catch (error) {
      apiKey = "";
      if (error instanceof ApiError && error.code === "provider_conflict") {
        try {
          await loadCurrentView();
          setLiveMessage("The provider URL changed while you were adding this key. The provider list was refreshed and the key field cleared; review the current endpoint and enter the key again.");
        } catch (refreshError) {
          showPageError(refreshError);
        }
      } else {
        showInlineError(keyForm, error);
      }
    }
  });

  const credentialRows = credentials.map((credential) => {
    const credentialId = credentialIdOf(credential);
    const active = credentialIsActive(credential);
    return h("div", { className: "list-row" },
      h("div", {},
        h("div", { className: "row-title" }, display(credential.displayName, display(credential.provider, "Provider credential"))),
        h("div", { className: "row-meta" }, `Added ${dateLabel(credential.createdAt ?? credential.created_at)} · Expires ${dateLabel(credential.expiresAt ?? credential.expires_at)}`),
      ),
      h("div", { className: "row-actions" }, badge(active ? "Active" : "Revoked or expired", active ? "success" : "warning"), active && canWriteProject ? button("Revoke", async () => {
        if (!credentialId || !confirmAction("Revoke this provider credential? Requests using it will be denied.")) return;
        await runAction(() => api.post(`/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {}), "Provider credential revoked.");
      }, "danger", { small: true }) : null),
    );
  });
  const credentialList = credentialRows.length ? h("div", { className: "list" }, ...credentialRows) : emptyState("No provider keys saved", "Add a provider API key to connect a model. The raw key cannot be recovered after encryption.", "⌑");

  const modelCards = providers.map((provider) => {
    const providerId = providerIdOf(provider);
    const providerIsEnabled = enabled(provider.enabled);
    const models = list(provider.models);
    const modelRows = models.map((model) => {
      const alias = display(model.alias, display(model.model, ""));
      const permitted = enabled(model.projectAllowed);
      const modelEnabled = enabled(model.enabled);
      const toggle = h("input", {
        type: "checkbox",
        checked: permitted,
        disabled: !providerIsEnabled || !modelEnabled || !canWriteProject,
        "aria-label": `Allow ${display(model.displayName, alias)} for this project`,
        onChange: async (event) => {
          const checkbox = event.currentTarget;
          checkbox.disabled = true;
          try {
            await api.post("/api/permissions", { projectId: state.projectId, provider: providerId, model: alias, allowed: checkbox.checked });
            setLiveMessage(`Model access updated for ${display(model.displayName, alias)}.`);
            await loadCurrentView();
          } catch (error) {
            checkbox.checked = !checkbox.checked;
            checkbox.disabled = !providerIsEnabled || !modelEnabled || !canWriteProject;
            showInlineError(card, error);
          }
        },
      });
      return h("div", { className: "list-row" },
        h("div", {}, h("div", { className: "row-title" }, display(model.displayName, alias)), h("div", { className: "row-meta" }, `${alias} → ${display(model.upstreamModel, alias)}`)),
        h("label", { className: "checkbox-option nowrap" }, toggle, h("span", {}, "Allowed")),
      );
    });
    const customRoute = provider.custom === true ? ` · OpenAI-compatible endpoint ${display(provider.baseUrl, "configured by administrator")}` : "";
    const providerActions = [];
    if (isSystemAdmin && providerId) {
      providerActions.push(h("button", {
        type: "button",
        className: `button ${providerIsEnabled ? "danger" : "secondary"} small`,
        disabled: state.busy,
        "data-busy-disabled": "true",
        onClick: async () => {
          const name = display(provider.displayName, providerId);
          const nextEnabled = !providerIsEnabled;
          if (!nextEnabled && !confirmAction(`Disable ${name}? Requests using this provider route will be denied. Existing keys and mappings will remain saved.`)) return;
          await runAction(
            () => api.put(`/api/providers/${encodeURIComponent(providerId)}`, { enabled: nextEnabled }),
            `${name} provider route ${nextEnabled ? "enabled" : "disabled"}.`,
          );
        },
      }, providerIsEnabled ? "Disable provider" : "Enable provider"));
    }
    const editBaseUrlButton = isSystemAdmin && provider.custom === true && providerId ? h("button", {
      type: "button",
      className: "button secondary small",
      disabled: state.busy,
      "data-busy-disabled": "true",
      "aria-expanded": "false",
      onClick: () => {
        if (state.busy) return;
        const existingEditor = card.querySelector(".provider-base-url-editor");
        if (existingEditor) {
          existingEditor.remove();
          editBaseUrlButton.setAttribute("aria-expanded", "false");
          editBaseUrlButton.focus();
          return;
        }

        const oldBaseUrl = display(provider.baseUrl, "");
        const newBaseUrl = h("input", { className: "input", type: "url", required: "", maxlength: 2048, autocomplete: "url", value: oldBaseUrl, "data-busy-disabled": "true" });
        const editor = h("form", { className: "provider-base-url-editor form-grid spaced-form-grid", autocomplete: "off", "aria-label": `Edit ${display(provider.displayName, providerId)} Base URL` },
          field("Base URL", newBaseUrl, "Use a public HTTPS URL. Path changes on the same origin retain saved credentials; changing the origin revokes all saved credentials for this provider.", true),
          h("div", { className: "form-actions full" },
            h("button", { className: "button primary", type: "submit", disabled: state.busy, "data-busy-disabled": "true" }, "Save Base URL"),
            h("button", { className: "button secondary", type: "button", disabled: state.busy, "data-busy-disabled": "true", onClick: () => { editor.remove(); editBaseUrlButton.setAttribute("aria-expanded", "false"); editBaseUrlButton.focus(); } }, "Cancel"),
          ),
        );
        editor.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (!editor.reportValidity()) return;
          const nextBaseUrl = newBaseUrl.value.trim();
          const previousUrl = parsePublicProviderBaseUrl(oldBaseUrl);
          const nextUrl = parsePublicProviderBaseUrl(nextBaseUrl);
          if (!nextUrl) {
            showInlineError(editor, new Error("Provider URLs must use HTTPS and cannot contain credentials, query strings, or fragments."));
            return;
          }
          if (!previousUrl) {
            showInlineError(editor, new Error("The saved provider URL is invalid. Reload the provider list before editing it."));
            return;
          }
          if (nextBaseUrl === oldBaseUrl) {
            editor.remove();
            editBaseUrlButton.setAttribute("aria-expanded", "false");
            setLiveMessage("No Base URL changes were made.");
            return;
          }

          const sameOrigin = nextUrl.origin === previousUrl.origin;
          const name = display(provider.displayName, providerId);
          const confirmation = sameOrigin
            ? `Update ${name} Base URL from ${oldBaseUrl} to ${nextBaseUrl}? The origin is unchanged, so saved credential envelopes will be retained.`
            : `Change ${name} Base URL from ${oldBaseUrl} to ${nextBaseUrl}? This changes the origin. Identity will revoke all saved credentials for this provider globally; users must enroll provider keys again before requests can succeed.`;
          if (!confirmAction(confirmation)) return;

          setBusy(true);
          try {
            const result = await api.put(`/api/providers/${encodeURIComponent(providerId)}`, { baseUrl: nextBaseUrl, expectedBaseUrl: oldBaseUrl });
            const revokedCount = Number.isSafeInteger(result?.revokedCredentialCount) && result.revokedCredentialCount >= 0 ? result.revokedCredentialCount : undefined;
            const successMessage = sameOrigin
              ? `${name} Base URL updated. Saved credential envelopes were retained.`
              : revokedCount === undefined
                ? `${name} Base URL updated. Saved credentials were revoked; enroll provider keys again before using this route.`
                : `${name} Base URL updated. ${revokedCount} saved provider credential${revokedCount === 1 ? " was" : "s were"} revoked; enroll provider keys again before using this route.`;
            await loadCurrentView();
            setLiveMessage(successMessage);
          } catch (error) {
            if (error instanceof ApiError && error.code === "provider_conflict") {
              try {
                await loadCurrentView();
                setLiveMessage("This provider URL changed in another administrator session. The provider list is refreshed; review the current URL and retry your change.");
              } catch (refreshError) {
                showPageError(refreshError);
              }
            } else {
              showInlineError(editor, error);
            }
          } finally {
            setBusy(false);
          }
        });
        card.append(editor);
        editBaseUrlButton.setAttribute("aria-expanded", "true");
        newBaseUrl.focus();
      },
    }, "Edit Base URL") : null;
    if (editBaseUrlButton) providerActions.push(editBaseUrlButton);
    const actions = providerActions.length ? h("div", { className: "row-actions" }, ...providerActions) : null;
    const card = panel(display(provider.displayName, providerId), `${modelEnabledText(provider)}${customRoute} · project model permissions`, modelRows.length ? h("div", { className: "list" }, ...modelRows) : emptyState("No models mapped", "Add an alias and upstream model below."), actions);
    return card;
  });

  const modelProvider = h("select", { className: "select", required: "" },
    h("option", { value: "" }, "Choose provider"),
    ...enabledProviders.map((provider) => h("option", { value: providerIdOf(provider) }, display(provider.displayName, providerIdOf(provider)))),
  );
  const alias = h("input", { className: "input", required: "", maxlength: "128", placeholder: "e.g. fast-chat", autocomplete: "off" });
  const upstreamModel = h("input", { className: "input", required: "", maxlength: "128", placeholder: "Provider model ID", autocomplete: "off" });
  const displayName = h("input", { className: "input", required: "", maxlength: "128", placeholder: "Friendly name", autocomplete: "off" });
  const modelForm = h("form", { className: "panel", autocomplete: "off" },
    h("div", { className: "panel-header" }, h("div", {}, h("h2", {}, "Add a model mapping"), h("p", { className: "panel-description" }, "Aliases and upstream model IDs are server-managed; clients never choose a URL."))),
    h("div", { className: "form-grid" },
      field("Provider", modelProvider),
      field("Model alias", alias, "The name project clients request."),
      field("Upstream model", upstreamModel, "The provider's upstream model ID may include /, for example org/model."),
      field("Display name", displayName),
    ),
    h("div", { className: "form-actions" }, h("button", { className: "button secondary", type: "submit" }, "Add mapping")),
  );
  modelForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!modelForm.reportValidity()) return;
    try {
      await api.post("/api/providers/models", { provider: modelProvider.value, alias: alias.value.trim(), upstreamModel: upstreamModel.value.trim(), displayName: displayName.value.trim() });
      await loadCurrentView();
      setLiveMessage("Model mapping added.");
    } catch (error) { showInlineError(modelForm, error); }
  });

  const providerContent = modelCards.length ? h("div", { className: "section-grid two" }, ...modelCards) : emptyState("No providers configured", "An administrator must configure provider routes before adding keys.", "↗");
  return [
    ...(customProviderForm ? [customProviderForm] : []),
    canWriteProject ? keyForm : panel("Add a provider key", "Only project owners and admins can change provider credentials.", notice("Ask a project owner or admin to add or revoke provider credentials.", "info")),
    panel("Saved credentials", "Only credential metadata is shown. Raw provider keys are not stored in this list.", credentialList),
    providerContent,
    isSystemAdmin ? modelForm : panel("Model mappings", "Only system administrators can add provider model mappings.", emptyState("Mapping changes restricted", "Use the configured model aliases available to this project.")),
  ];
}

function modelEnabledText(provider) {
  return enabled(provider.enabled) ? "Provider route enabled" : "Provider route disabled";
}

async function renderSessions() {
  const data = await api.get("/api/sessions");
  const sessions = list(data?.sessions ?? data);
  const rows = sessions.map((session) => {
    const id = typeof session.id === "string" ? session.id : typeof session.sessionId === "string" ? session.sessionId : "";
    const revoked = Boolean(session.revokedAt ?? session.revoked_at ?? session.revoked);
    const expired = isTimestampExpired(session.expiresAt ?? session.expires_at);
    const active = !revoked && !expired;
    const title = display(session.deviceName, display(session.clientName, display(session.kind, "Session")));
    return h("div", { className: "list-row" },
      h("div", {}, h("div", { className: "row-title" }, title), h("div", { className: "row-meta" }, `${display(session.kind, "Session")} · Last seen ${dateLabel(session.lastSeenAt ?? session.last_seen_at)} · Expires ${dateLabel(session.expiresAt ?? session.expires_at)}`), h("div", { className: "row-meta" }, `Started ${dateLabel(session.createdAt ?? session.created_at)}`)),
      h("div", { className: "row-actions" }, badge(active ? "Active" : revoked ? "Revoked" : "Expired", active ? "success" : "neutral"), active ? button("Revoke", async () => {
        if (!id || !confirmAction(`Revoke the ${title} session? It will need to sign in again.`)) return;
        await runAction(() => api.post(`/api/sessions/${encodeURIComponent(id)}/revoke`, {}), "Session revoked.");
      }, "danger", { small: true }) : null),
    );
  });
  const content = rows.length ? h("div", { className: "list" }, ...rows) : emptyState("No sessions found", "Connected clients will appear here when they sign in.", "◷");
  return [panel("Sessions", "Revoke a device if you no longer recognize it. Revocation blocks future Gateway requests.", content)];
}

async function renderSecurity() {
  let data;
  try {
    data = await api.get("/api/security");
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return [notice("The Security screen is available only to system administrators. Project membership does not grant Identity-wide admin access.", "warning")];
    }
    throw error;
  }
  const security = isRecord(data) ? data : {};
  const identity = isRecord(security.identity) ? security.identity : {};
  const keyVersions = list(security.keyVersions);
  const pending = list(security.pendingIdentities);
  const allowlisted = list(security.allowlistedUsers);
  const audit = list(security.audit);

  const oidcList = list(state.session?.loginProviders);
  const identityContent = h("div", { className: "section-grid two" },
    h("div", {}, h("div", { className: "field-label" }, "Gateway machine-token issuer"), h("div", { className: "row-meta monospace" }, display(identity.issuer, "Not reported")), h("p", { className: "field-help" }, "This issuer signs short-lived Gateway access tokens. It is separate from OIDC user sign-in.")),
    h("div", {}, h("div", { className: "field-label" }, "User sign-in providers"), oidcList.length ? h("div", { className: "list" }, ...oidcList.map((provider) => h("div", { className: "list-row" }, h("span", { className: "row-title" }, display(provider.label, provider.id)), badge("OIDC login", "neutral")))) : h("p", { className: "row-meta" }, "No login providers reported.")),
  );
  const keyList = keyVersions.length ? h("div", { className: "list" }, ...keyVersions.map((key) => {
    const keyId = display(key.kid, display(key.keyId, display(key.id, "Key version")));
    return h("div", { className: "list-row" }, h("div", {}, h("div", { className: "row-title monospace" }, keyId), h("div", { className: "row-meta" }, `Created ${dateLabel(key.createdAt ?? key.created_at)}${key.retireAt ? ` · Retire ${dateLabel(key.retireAt)}` : ""}`)), badge(enabled(key.active) ? "Signing" : "Verification only", enabled(key.active) ? "success" : "neutral"));
  })) : emptyState("No key versions reported", "Identity will report active and retiring signing key IDs here.");
  const pendingList = pending.length ? h("div", { className: "list" }, ...pending.map((person) => renderPendingIdentity(person))) : emptyState("No pending identities", "Unapproved sign-in identities will appear here after they request access.");
  const allowlistRows = allowlisted.map((person) => {
    const issuer = display(person.issuer, "");
    const subject = display(person.subject, "");
    const name = display(person.displayName, display(person.email, "Allowlisted user"));
    const revoked = Boolean(person.revokedAt ?? person.revoked_at ?? person.revoked);
    return h("div", { className: "list-row" },
      h("div", {}, h("div", { className: "row-title" }, name), h("div", { className: "row-meta" }, display(person.email, "")), h("div", { className: "row-meta monospace" }, `${issuer} · ${subject}`)),
      h("div", { className: "row-actions" }, badge(revoked ? "Revoked" : enabled(person.isAdmin) ? "Administrator" : "Allowed", revoked ? "danger" : enabled(person.isAdmin) ? "warning" : "success"), !revoked ? button("Revoke", async () => {
        if (!issuer || !subject || !confirmAction(`Remove access for ${name}? Their Identity sessions will need to be revoked.`)) return;
        await runAction(() => api.post("/api/security/revoke", { issuer, subject }), "Identity access revoked.");
      }, "danger", { small: true }) : null),
    );
  });
  const allowlistContent = allowlistRows.length ? h("div", { className: "list" }, ...allowlistRows) : emptyState("No users allowlisted", "Allowlist an identity after verifying the person and issuer.");
  const auditRows = audit.map((event) => h("div", { className: "list-row" },
    h("div", {}, h("div", { className: "row-title" }, display(event.action, "Security event")), h("div", { className: "row-meta" }, `${display(event.targetType, display(event.target_type, "Target"))} · ${display(event.actorEmail, display(event.actorUserId, display(event.actor_user_id, "System")))}`)),
    h("span", { className: "row-meta nowrap" }, dateLabel(event.createdAt ?? event.created_at)),
  ));
  const auditContent = auditRows.length ? h("div", { className: "list" }, ...auditRows) : emptyState("No audit activity", "Security events will appear here. Payloads and secrets are never shown.");

  return [
    notice("System login, Gateway access tokens, and LLM provider keys have separate roles. OIDC signs in a human; machine tokens authorize a client; provider API keys authorize upstream model calls.", "info"),
    panel("Identity boundaries", "Review the configured sign-in and token issuers separately.", identityContent, button("Edit OIDC settings", editAdminOidcSettings, "secondary")),
    h("div", { className: "section-grid two" }, panel("Token signing keys", "Key IDs only. Private signing material never appears in the browser.", keyList), panel("Pending identities", "Approve only identities you can verify.", pendingList)),
    h("div", { className: "section-grid two" }, panel("Allowlisted users", "Access is keyed by OIDC issuer and subject, not email alone.", allowlistContent), panel("Recent audit activity", "Metadata only. Prompts, responses, keys, and tokens are excluded.", auditContent)),
  ];
}

function renderPendingIdentity(person) {
  const issuer = display(person.issuer, "");
  const subject = display(person.subject, "");
  const name = display(person.displayName, display(person.email, "Pending identity"));
  const adminToggle = h("input", { type: "checkbox", "aria-label": `Grant administrator access to ${name}` });
  const actions = h("div", { className: "row-actions" },
    h("label", { className: "checkbox-option nowrap" }, adminToggle, h("span", {}, "Admin")),
    button("Approve", async () => {
      if (!issuer || !subject || !confirmAction(`Allow ${name} to access this service${adminToggle.checked ? " as an administrator" : ""}?`)) return;
      await runAction(() => api.post("/api/security/approve", { issuer, subject, isAdmin: adminToggle.checked }), "Identity approved.");
    }, "secondary", { small: true }),
  );
  return h("div", { className: "list-row" },
    h("div", {}, h("div", { className: "row-title" }, name), h("div", { className: "row-meta" }, display(person.email, "")), h("div", { className: "row-meta monospace" }, `${issuer} · ${subject}`), h("div", { className: "row-meta" }, `First seen ${dateLabel(person.firstSeenAt ?? person.first_seen_at)}`)),
    actions,
  );
}

function showInlineError(container, error) {
  const message = error instanceof Error ? error.message : "The request could not be completed.";
  const old = container.querySelector(".inline-error");
  old?.remove();
  container.prepend(h("div", { className: "alert inline-error", role: "alert" }, message));
}

initialize();
