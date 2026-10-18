import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { configureConfidentialClient, createDeviceLabel, pairPublicClient, readClientBootstrapFile } from "./auth.js";
import { ConfigError, ConfigStore, defaultConfigPath, validateConfig } from "./config.js";
import type { CredentialEnvelope, ProviderProtocol } from "./types.js";
import { startAdapter } from "./server.js";

const HELP = `OpenAI-compatible local adapter

Commands:
  pair --identity-url URL --gateway-url WSS_URL [--name DEVICE]
  configure-machine --identity-url URL --gateway-url WSS_URL --client-id ID
  configure-bootstrap FILE
  envelope add FILE
  model add --id ALIAS --provider PROVIDER_ID [--protocol openai|anthropic] --credential-id ID
  model list
  token
  serve
  config-path

Set WS_PROXY_ADAPTER_CONFIG to choose a config file. Confidential setup reads
WS_PROXY_CLIENT_SECRET from the environment so it does not enter shell history.
Set WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS=1 for single-socket benchmark runs.
`;

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const [command, ...args] = argv;
  const store = new ConfigStore(defaultConfigPath());
  try {
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
      case "token": {
        const config = await store.load();
        process.stdout.write(`${config.localBearerToken}\n`);
        return;
      }
      case "serve": {
        if (args.length !== 0) throw new ConfigError("Usage: serve");
        const server = await startAdapter({ configStore: store });
        process.stdout.write(`Adapter listening on http://127.0.0.1:${server.port}\n`);
        const close = () => { void server.close().finally(() => process.exit(0)); };
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
    const message = error instanceof Error ? error.message : "Adapter command failed";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
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
