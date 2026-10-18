import { readFile, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";
import { configureConfidentialClient, createDeviceLabel, pairPublicClient, readClientBootstrapFile } from "./auth.js";
import { ConfigError, ConfigStore, defaultConfigPath, validateConfig } from "./config.js";
import { createEnvironmentConfigStore, EnvironmentConfigStore, hasEnvironmentRuntimeSettings, loadPrivateEnvFile } from "./env-config.js";
import type { CredentialEnvelope, ProviderProtocol } from "./types.js";
import { startAdapter } from "./server.js";
import { ChatGptOAuthManager, OAuthConnectorError } from "./oauth.js";
import { RequestCommandError, runRequestCommand } from "./request.js";

const HELP = `OpenAI-compatible local adapter

Commands:
  pair --identity-url URL --gateway-url WSS_URL [--name DEVICE]
  configure-machine --identity-url URL --gateway-url WSS_URL --client-id ID
  configure-bootstrap FILE
  envelope add FILE
  model add --id ALIAS --provider PROVIDER_ID [--protocol openai|anthropic] --credential-id ID
  model list
  oauth status
  oauth login chatgpt [--profile PROFILE_ID] [--print-url]
  oauth models chatgpt --profile PROFILE_ID [--cached]
  oauth model add --id MODEL_ALIAS --profile PROFILE_ID
  oauth model remove --id MODEL_ALIAS
  oauth logout chatgpt --profile PROFILE_ID
  request --api chat.completions|responses|completions [--input FILE|-]
  token
  serve
  config-path

Set WS_PROXY_ADAPTER_CONFIG to choose a config file. Confidential setup reads
WS_PROXY_CLIENT_SECRET from the environment so it does not enter shell history.
Set WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS=1 for single-socket benchmark runs.

Use --config-env FILE to load a protected dotenv file before any command. Agent
runtime mode requires WS_PROXY_CONFIG_SOURCE=env and Identity/Gateway URLs,
confidential client credentials, local bearer token, protected envelope path,
one model alias, provider ID, and protocol in WS_PROXY_* environment variables.
Environment runtime state stays in memory and is not written to adapter.json.
request reads JSON from stdin by default or --input FILE, inserts the only
configured model alias when model is omitted, and writes only JSON or SSE to stdout.

ChatGPT subscription OAuth is a local loopback sign-in. The browser must reach
the adapter host at 127.0.0.1; Claude subscription OAuth is unavailable. Cloud
inference remains disabled until the operator verifies connector eligibility.
`;

export async function main(argv = process.argv.slice(2)): Promise<void> {
  try {
    const invocation = extractEnvFileOption(argv);
    if (invocation.envFile) await loadPrivateEnvFile(invocation.envFile);
    const [command, ...args] = invocation.args;
    const store = await createCliConfigStore();
    if (store instanceof EnvironmentConfigStore && !isEnvironmentCommand(command, args)) {
      throw new ConfigError("This command is not available in environment runtime mode");
    }
    switch (command) {
      case "pair": {
        const options = parseOptions(args);
        const identityUrl = requiredOption(options, "identity-url");
        const gatewayUrl = requiredOption(options, "gateway-url");
        const clientName = options.get("name") ?? createDeviceLabel();
        await pairPublicClient({
          identityUrl,
          gatewayUrl,
          clientName,
          configStore: store,
          onCode: (uri, code) => {
            process.stdout.write(`Approve this adapter in your authenticated browser:\n${uri}\nCode: ${code}\nWaiting for approval...\n`);
          },
        });
        process.stdout.write(`Pairing complete. Sensitive adapter state was saved with owner-only permissions at ${store.filePath}.\n`);
        process.stdout.write("Use `ws-llm-adapter token` to retrieve the local API bearer token for your client.\n");
        return;
      }
      case "configure-machine": {
        const options = parseOptions(args);
        const clientSecret = process.env.WS_PROXY_CLIENT_SECRET;
        if (!clientSecret) throw new ConfigError("Set WS_PROXY_CLIENT_SECRET in the environment before configuring a confidential client");
        await configureConfidentialClient({
          identityUrl: requiredOption(options, "identity-url"),
          gatewayUrl: requiredOption(options, "gateway-url"),
          clientId: requiredOption(options, "client-id"),
          clientSecret,
          configStore: store,
        });
        process.stdout.write(`Confidential client state saved with owner-only permissions at ${store.filePath}.\n`);
        process.stdout.write("Use `ws-llm-adapter token` to retrieve the local API bearer token for your client.\n");
        return;
      }
      case "configure-bootstrap": {
        if (args.length !== 1) throw new ConfigError("Usage: configure-bootstrap FILE");
        const bootstrap = await readClientBootstrapFile(path.resolve(args[0] as string));
        if (bootstrap.client.kind === "public") {
          await pairPublicClient({
            identityUrl: bootstrap.identityUrl,
            gatewayUrl: bootstrap.gatewayUrl,
            clientName: createDeviceLabel(),
            configStore: store,
            onCode: (uri, code) => {
              process.stdout.write(`Approve this new public adapter client in your authenticated browser:\n${uri}\nCode: ${code}\nWaiting for approval...\n`);
            },
          });
          process.stdout.write("Public bootstrap configured. Pairing created a new user-approved client; the bootstrap clientId was not reused.\n");
        } else {
          const clientSecret = process.env.WS_PROXY_CLIENT_SECRET;
          if (!clientSecret) throw new ConfigError("Set WS_PROXY_CLIENT_SECRET in the environment for this confidential bootstrap");
          await configureConfidentialClient({
            identityUrl: bootstrap.identityUrl,
            gatewayUrl: bootstrap.gatewayUrl,
            clientId: bootstrap.client.clientId,
            clientSecret,
            configStore: store,
          });
          process.stdout.write("Confidential bootstrap configured with owner-only local state.\n");
        }
        process.stdout.write(`Bootstrap project: ${bootstrap.projectId}\nAuthorized aliases: ${bootstrap.models.map((model) => `${model.id} (${model.provider}/${model.protocol})`).join(", ") || "none"}\n`);
        process.stdout.write("Import an encrypted envelope, then map an authorized alias with `model add`. Bootstrap data contains no credential secret or envelope.\n");
        return;
      }
      case "envelope": {
        if (args[0] !== "add" || !args[1] || args.length !== 2) throw new ConfigError("Usage: envelope add FILE");
        const inputPath = path.resolve(args[1]);
        const fileStat = await stat(inputPath);
        if (!fileStat.isFile() || fileStat.size > 32_768) throw new ConfigError("Envelope source file must be a regular file no larger than 32 KiB");
        if (process.platform !== "win32" && (fileStat.mode & 0o077) !== 0) {
          throw new ConfigError("Envelope source file permissions are too broad; restrict it to owner read/write (0600)");
        }
        let envelope: CredentialEnvelope;
        try {
          envelope = JSON.parse(await readFile(inputPath, "utf8")) as CredentialEnvelope;
        } catch {
          throw new ConfigError("Envelope source is unreadable or invalid JSON");
        }
        await store.update((current) => {
          const envelopes = [...current.envelopes.filter((item) => item.credentialId !== envelope.credentialId), envelope];
          return validateConfig({ ...current, envelopes });
        });
        process.stdout.write("Credential envelope saved in the owner-only adapter config.\n");
        return;
      }
      case "model": {
        if (args[0] === "list" && args.length === 1) {
          const config = await store.load();
          for (const model of config.models) process.stdout.write(`${model.id}\t${model.provider}\t${model.protocol}\n`);
          for (const model of config.oauthModels ?? []) process.stdout.write(`${model.alias}\topenai\tchatgpt-oauth\t${model.profileId}\n`);
          return;
        }
        if (args[0] !== "add") throw new ConfigError("Usage: model add --id ALIAS --provider openai|anthropic --credential-id ID");
        const options = parseOptions(args.slice(1));
        const provider = requiredOption(options, "provider");
        if (!/^[a-z][a-z0-9_-]{0,31}$/.test(provider)) throw new ConfigError("--provider must be a valid provider ID");
        const protocolOption = options.get("protocol");
        const protocol = protocolOption ?? (provider === "openai" || provider === "anthropic" ? provider : undefined);
        if (protocol !== "openai" && protocol !== "anthropic") {
          throw new ConfigError("Custom providers require --protocol openai or --protocol anthropic");
        }
        if ((provider === "openai" || provider === "anthropic") && protocol !== provider) {
          throw new ConfigError("The built-in provider protocol must match --provider");
        }
        const model = {
          id: requiredOption(options, "id"),
          provider,
          protocol: protocol as ProviderProtocol,
          credentialId: requiredOption(options, "credential-id"),
        };
        await store.update((current) => validateConfig({ ...current, models: [...current.models.filter((item) => item.id !== model.id), model] }));
        process.stdout.write("Model alias saved.\n");
        return;
      }
      case "oauth": {
        await runOAuthCommand(args, store);
        return;
      }
      case "request": {
        await runRequestCommand(args, store);
        return;
      }
      case "token": {
        const config = await store.load();
        process.stdout.write(`${config.localBearerToken}\n`);
        return;
      }
      case "serve": {
        if (args.length !== 0) throw new ConfigError("Usage: serve");
        const oauthManager = store instanceof EnvironmentConfigStore ? undefined : new ChatGptOAuthManager(store);
        let server;
        try {
          server = await startAdapter({ configStore: store, ...(oauthManager ? { oauthManager } : {}) });
        } catch (error) {
          await oauthManager?.close();
          throw error;
        }
        process.stdout.write(`Adapter listening on http://127.0.0.1:${server.port}\n`);
        const close = () => { void server.close().finally(() => oauthManager?.close()).finally(() => process.exit(0)); };
        process.once("SIGINT", close);
        process.once("SIGTERM", close);
        return;
      }
      case "config-path":
        process.stdout.write(`${store.filePath}\n`);
        return;
      case "help":
      case "--help":
      case "-h":
      case undefined:
        process.stdout.write(HELP);
        return;
      default:
        throw new ConfigError(`Unknown command: ${command}`);
    }
  } catch (error) {
    const message = error instanceof RequestCommandError
      ? error.message
      : error instanceof Error ? error.message : "Adapter command failed";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}

async function createCliConfigStore(): Promise<ConfigStore> {
  const source = process.env.WS_PROXY_CONFIG_SOURCE;
  if (source === "env") return createEnvironmentConfigStore();
  if (source !== undefined) throw new ConfigError("WS_PROXY_CONFIG_SOURCE must be env when set");
  if (hasEnvironmentRuntimeSettings()) {
    throw new ConfigError("Partial runtime environment settings are present; set WS_PROXY_CONFIG_SOURCE=env or clear them");
  }
  return new ConfigStore(defaultConfigPath());
}

function isEnvironmentCommand(command: string | undefined, args: string[]): boolean {
  if (command === "serve" && args.length === 0) return true;
  if (command === "request") return true;
  if (command === "help" || command === "--help" || command === "-h" || command === undefined) return true;
  return command === "model" && args.length === 1 && args[0] === "list";
}

function extractEnvFileOption(argv: string[]): { args: string[]; envFile?: string } {
  const args: string[] = [];
  let envFile: string | undefined;
  const valueOptions = new Set([
    "--api", "--input", "--identity-url", "--gateway-url", "--name", "--client-id", "--protocol",
    "--provider", "--credential-id", "--id", "--profile", "--port", "--identity", "--project",
  ]);
  const flags = new Set(["--print-url", "--cached"]);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--config-env") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new ConfigError("Missing value for --config-env");
      if (envFile) throw new ConfigError("Duplicate option --config-env");
      envFile = value;
      index += 1;
      continue;
    }
    if (token?.startsWith("--config-env=")) {
      const value = token.slice("--config-env=".length);
      if (!value) throw new ConfigError("Missing value for --config-env");
      if (envFile) throw new ConfigError("Duplicate option --config-env");
      envFile = value;
      continue;
    }
    args.push(token as string);
    if (valueOptions.has(token as string)) {
      const value = argv[index + 1];
      if (value !== undefined && !value.startsWith("--")) {
        args.push(value);
        index += 1;
      }
    } else if (token?.startsWith("--") && !flags.has(token)) {
      const value = argv[index + 1];
      if (value !== undefined && !value.startsWith("--")) {
        args.push(value);
        index += 1;
      }
    }
  }
  return { args, ...(envFile === undefined ? {} : { envFile }) };
}

async function runOAuthCommand(args: string[], store: ConfigStore): Promise<void> {
  const [action, connector, ...rest] = args;
  if (connector === "claude" && (action === "login" || action === "models" || action === "logout")) {
    throw new ConfigError("Claude subscription OAuth is unavailable. Use a Console API key or a supported cloud-provider credential.");
  }
  if (action === "status" && args.length === 1) {
    const manager = new ChatGptOAuthManager(store);
    try {
      const profiles = await manager.listProfiles();
      const bindings = await manager.listModelBindings();
      process.stdout.write("ChatGPT subscription OAuth: local sign-in available\n");
      process.stdout.write("Remote inference: operator eligibility gate; requests are blocked unless this deployment is explicitly verified\n");
      process.stdout.write("Claude subscription OAuth: unavailable\n");
      if (profiles.length === 0) process.stdout.write("Profiles: none\n");
      for (const profile of profiles) {
        process.stdout.write(`Profile ${profile.profileId}\t${profile.connected ? "connected" : "disconnected"}\t${profile.email ?? "email unavailable"}\n`);
      }
      for (const binding of bindings) process.stdout.write(`Model ${binding.alias}\tChatGPT profile ${binding.profileId}\n`);
    } finally { await manager.close(); }
    return;
  }
  if (action === "login" && connector === "chatgpt") {
    const options = parseOAuthLoginOptions(rest);
    const manager = new ChatGptOAuthManager(store);
    try {
      const login = await manager.startLogin(options.profileId ? { profileId: options.profileId } : {});
      if (options.printUrl) {
        process.stdout.write(`${login.authorizationUrl}\n`);
      } else {
        process.stdout.write("Opening ChatGPT sign-in in your browser. If no browser opens, use this URL on the adapter host:\n");
        process.stdout.write(`${login.authorizationUrl}\n`);
        openBrowser(login.authorizationUrl);
      }
      process.stdout.write("Waiting for the loopback callback. The browser must run on the adapter host.\n");
      const deadline = Date.now() + 10 * 60_000;
      while (Date.now() < deadline) {
        const status = manager.status(login.operationId);
        if (status.status === "connected") {
          process.stdout.write(`ChatGPT connected as profile ${status.profileId}${status.email ? ` (${status.email})` : ""}.\n`);
          process.stdout.write("Run `oauth models chatgpt --profile PROFILE_ID` to discover available models.\n");
          return;
        }
        if (status.status === "failed") {
          throw new OAuthConnectorError(status.code, status.code === "callback_timeout" ? "ChatGPT sign-in timed out." : "ChatGPT sign-in could not be completed.");
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      await manager.cancelLogin(login.operationId);
      throw new OAuthConnectorError("callback_timeout", "ChatGPT sign-in timed out.");
    } finally { await manager.close(); }
  }
  if (action === "models" && connector === "chatgpt") {
    const options = parseOAuthValueOptions(rest, new Set(["profile", "cached"]));
    const profileId = requiredOption(options.values, "profile");
    const manager = new ChatGptOAuthManager(store);
    try {
      const models = options.flags.has("cached")
        ? await manager.readCachedModels(profileId)
        : await manager.discoverModels(profileId);
      if (options.flags.has("cached")) process.stdout.write("Showing saved model metadata; it may be stale and does not grant model access.\n");
      for (const model of models) {
        const capabilities = [model.contextWindow ? `${model.contextWindow} context` : "", model.inputModalities.join("/")].filter(Boolean).join(" ");
        process.stdout.write(`${model.id}\t${model.displayName ?? ""}\t${capabilities}\t${model.reasoningEfforts.join(",")}\n`);
      }
      if (models.length === 0) process.stdout.write("No eligible models are available in the selected profile.\n");
    } finally { await manager.close(); }
    return;
  }
  if (action === "model" && connector === "add") {
    const options = parseOptions(rest);
    const manager = new ChatGptOAuthManager(store);
    try {
      await manager.bindModelProfile(requiredOption(options, "id"), requiredOption(options, "profile"));
      process.stdout.write("ChatGPT OAuth model alias saved. Gateway model grants remain authoritative.\n");
    } finally { await manager.close(); }
    return;
  }
  if (action === "model" && connector === "remove") {
    const options = parseOptions(rest);
    const manager = new ChatGptOAuthManager(store);
    try {
      await manager.removeModelBinding(requiredOption(options, "id"));
      process.stdout.write("ChatGPT OAuth model alias removed.\n");
    } finally { await manager.close(); }
    return;
  }
  if (action === "logout" && connector === "chatgpt") {
    const options = parseOptions(rest);
    const manager = new ChatGptOAuthManager(store);
    try {
      const result = await manager.disconnectWithStatus(requiredOption(options, "profile"));
      process.stdout.write(`Local ChatGPT tokens cleared; refresh-token revocation ${result.remoteRevoked ? "confirmed" : "not confirmed"}.\n`);
      process.stdout.write("Already issued cloud credential envelopes may remain usable until they expire or are centrally revoked.\n");
    } finally { await manager.close(); }
    return;
  }
  throw new ConfigError("Usage: oauth status | login chatgpt | models chatgpt --profile ID | model add|remove | logout chatgpt --profile ID");
}

function parseOAuthLoginOptions(args: string[]): { profileId?: string; printUrl: boolean } {
  const values = new Map<string, string>();
  let printUrl = false;
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === "--print-url") {
      if (printUrl) throw new ConfigError("Duplicate option --print-url");
      printUrl = true;
      continue;
    }
    if (current === "--profile") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new ConfigError("Missing value for --profile");
      if (values.has("profile")) throw new ConfigError("Duplicate option --profile");
      values.set("profile", value);
      index += 1;
      continue;
    }
    throw new ConfigError(`Unexpected OAuth login option: ${current ?? ""}`);
  }
  const profileId = values.get("profile");
  return { ...(profileId ? { profileId } : {}), printUrl };
}

function parseOAuthValueOptions(args: string[], allowed: Set<string>): { values: Map<string, string>; flags: Set<string> } {
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (!current?.startsWith("--")) throw new ConfigError(`Unexpected argument: ${current ?? ""}`);
    const key = current.slice(2);
    if (!allowed.has(key)) throw new ConfigError(`Unknown option --${key}`);
    if (key === "cached") {
      if (flags.has(key)) throw new ConfigError("Duplicate option --cached");
      flags.add(key);
      continue;
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new ConfigError(`Missing value for --${key}`);
    if (values.has(key)) throw new ConfigError(`Duplicate option --${key}`);
    values.set(key, value);
    index += 1;
  }
  return { values, flags };
}

function openBrowser(url: string): boolean {
  const executable = process.platform === "darwin" ? "open" : process.platform === "linux" ? "xdg-open" : undefined;
  if (!executable) return false;
  try {
    const child = spawn(executable, [url], { detached: true, stdio: "ignore" });
    child.once("error", () => undefined);
    child.unref();
    return true;
  } catch { return false; }
}

function parseOptions(args: string[]): Map<string, string> {
  const result = new Map<string, string>();
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token?.startsWith("--")) throw new ConfigError(`Unexpected argument: ${token ?? ""}`);
    const key = token.slice(2);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new ConfigError(`Missing value for --${key}`);
    if (result.has(key)) throw new ConfigError(`Duplicate option --${key}`);
    result.set(key, value);
    index += 1;
  }
  return result;
}

function requiredOption(options: Map<string, string>, name: string): string {
  const value = options.get(name);
  if (!value) throw new ConfigError(`Missing required option --${name}`);
  return value;
}
