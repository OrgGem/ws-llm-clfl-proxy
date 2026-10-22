# Agent client guide

The adapter CLI can run a bounded OpenAI-compatible request through the authenticated Gateway. The `request` command starts a short-lived loopback adapter inside that process, so a persistent `serve` daemon is not required. The copyable client is in [`templates/ws-llm-agent`](../templates/ws-llm-agent/README.md).

For the native Rust runner—which keeps the CLI, trimmed YoAgent runtime, and optional local Uteke memory together under [`agent/`](../agent/README.md) while using a direct WSS provider—see the [YoAgent integration guide](YOAGENT.md) and its [agent skill](../agent/.agents/skills/ws-agent/SKILL.md).

## Install

The adapter package is currently local to this repository. Build and pack it from a repository checkout:

```sh
npm ci
npm run build --workspace @ws-proxy/adapter
mkdir -p .local/agent-packages
npm pack --workspace @ws-proxy/adapter --pack-destination .local/agent-packages
```

Install the generated `ws-proxy-adapter-<version>.tgz` into the independent project that contains the copied template:

```sh
npm install /absolute/path/to/ws-llm-clfl-proxy/.local/agent-packages/ws-proxy-adapter-<version>.tgz
```

The package installs the `ws-llm-adapter` executable. The template launcher resolves the installed package and starts its CLI without a shell. To install the optional CLI skill in the independent project, copy it from this repository:

```sh
mkdir -p .agents/skills/ws-llm-cli
cp /absolute/path/to/ws-llm-clfl-proxy/.agents/skills/ws-llm-cli/SKILL.md .agents/skills/ws-llm-cli/SKILL.md
```

## Configure an agent runtime

Create a confidential client and explicit project/model grants in Identity. The environment values must come from that deployment and its administrator. Use `.env.example` as a field list, copy it to `.env`, restrict the file with `chmod 600`, and keep the envelope file owner-only. The template contains no envelope-shaped JSON sample; use only an envelope exported by Identity.

Create a separate high-entropy local bearer with a password manager or secret manager and place it in `WS_PROXY_LOCAL_BEARER_TOKEN`. It protects the adapter's loopback HTTP API and is not a provider credential; for an OpenAI SDK client, inject that same value as `OPENAI_API_KEY` through protected runtime configuration.

Environment configuration is opt-in with `WS_PROXY_CONFIG_SOURCE=env`. It supplies the Identity/Gateway URLs, client credentials, local bearer, encrypted envelope path, provider, protocol, and `WS_PROXY_MODEL_ALIAS`. An omitted request model uses the configured alias only when the environment configuration has exactly one alias. Inherited process environment takes precedence over values parsed from `--config-env`; the adapter does not execute the file as shell code. Runtime configuration remains in memory.

Environment mode is for a trusted runtime that can protect a client secret. Distributed public clients should continue to use the adapter's pairing workflow. The adapter obtains short-lived Gateway access tokens from Identity; the envelope does not replace that authentication. A running `serve` process loads its environment and envelope at startup, so restart it after replacing either file or rotating credentials.

Do not pass credentials or task content as command-line arguments. Avoid putting private data into prompts. The template ignores `.env`, credentials, local state, and package artifacts; review the destination project's ignore rules before adding files.

## Make a request

The template invokes the CLI as follows, with the JSON request sent over stdin:

```text
npm exec -- ws-llm-adapter --config-env .env request --api chat.completions
```

From the copied template project, send a plain task with:

```sh
node agent.mjs --config-env .env --task-file task.txt
```

With no `--task-file`, the wrapper reads the task from stdin. It adds a separate system message from `agent.system.md`, bounds task input to 32 KiB and encoded request JSON to 1 MiB, omits `model`, and leaves output on stdout. `Ctrl+C` cancels the child request. Nonzero status means the response was not completed; this includes a native Responses `response.incomplete` terminal. The command may write provider incomplete JSON before returning nonzero. The wrapper does not retry or join streams.

The wrapper and CLI use `--config-env`, avoiding Node's own `--env-file` runtime option so the adapter's protected parser validates the file directly.

For direct API calls, pass a request JSON file with the adapter's `--input` option:

```sh
npm exec -- ws-llm-adapter --config-env .env request --api chat.completions --input examples/chat.json
npm exec -- ws-llm-adapter --config-env .env request --api responses --input examples/responses.json
npm exec -- ws-llm-adapter --config-env .env request --api chat.completions --input examples/tool-calls.json
```

Examples intentionally omit a model name so the adapter selects the configured authorized alias. Use API names and fields supported by the installed adapter version. Tool calls are returned as structured data. The adapter and wrapper never execute tools, and an agent must not treat a suggested call as completed work.

## Limits and OAuth

Identity grants decide which project, provider, and model alias a client can use. An upstream model ID is not automatically a granted alias. Requests can fail due to authorization, limits, expiration, connection interruption, or provider errors; report fixed error messages without exposing secret values. Do not retry an interrupted generation automatically because the provider may have processed or billed the original request.

ChatGPT subscription OAuth is a local-host sign-in and currently supports only explicitly authorized native `/v1/responses` aliases when operator eligibility is verified. It does not support Chat Completions or grant access to arbitrary upstream models. The agent template uses Chat Completions and therefore expects a compatible API-key envelope. See [OAuth operations](OAUTH.md) and [the protocol](PROTOCOL.md).

## Serve the local OpenAI-compatible API

For an SDK that expects a local HTTP endpoint, run `npm exec -- ws-llm-adapter --config-env .env serve` or `npm run serve`. It binds only to `127.0.0.1:43128` by default and serves `/v1/models`, `/v1/chat/completions`, `/v1/responses`, and `/v1/completions` where supported. Configure the SDK's base URL as `http://127.0.0.1:43128/v1`, provide the local adapter bearer as `OPENAI_API_KEY` through protected runtime secret storage, and set the model to the granted local alias (for example, `OPENAI_MODEL_ALIAS` from nonsecret application configuration). Never place the bearer in a curl command, source literal, command argument, or log. OAuth-bound aliases work only through native Responses.
