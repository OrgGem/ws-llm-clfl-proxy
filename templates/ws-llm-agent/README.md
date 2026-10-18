# ws-llm agent client template

This template gives an agent a small, bounded way to request an LLM response through `ws-llm-adapter`. It does not provide tools or execute tool calls. The task text goes to the adapter on stdin, never in the child process arguments.

## Install the adapter

The adapter package is built from this repository and is currently distributed as a local package artifact. In a checkout of `ws-llm-clfl-proxy`, build and pack it:

```sh
npm ci
npm run build --workspace @ws-proxy/adapter
mkdir -p .local/agent-packages
npm pack --workspace @ws-proxy/adapter --pack-destination .local/agent-packages
```

Copy this template to a private client project, then install the generated `ws-proxy-adapter-<version>.tgz` file:

```sh
cp -R templates/ws-llm-agent /path/to/my-agent-client
cd /path/to/my-agent-client
npm install /absolute/path/to/ws-llm-clfl-proxy/.local/agent-packages/ws-proxy-adapter-<version>.tgz
```

The adapter package exposes the `ws-llm-adapter` CLI and its documented subcommands. `agent.mjs` resolves that installed CLI and launches it with `shell: false`; no global install is required.

## Configure credentials

Provision a confidential client, project membership, provider/model grants, and an encrypted credential envelope through the authenticated Identity workflow. The model alias in the environment must already be granted to that client and project. Do not assume a provider model name is authorized just because it exists upstream.

Create a separate high-entropy local bearer with your password manager or secret manager and store it in `WS_PROXY_LOCAL_BEARER_TOKEN`. It protects the adapter's loopback HTTP API and is not a provider credential. For an OpenAI SDK client of `serve`, inject this same local bearer as `OPENAI_API_KEY` through protected runtime configuration.

Copy `.env.example` to `.env`, fill in the assigned values, and restrict access:

```sh
cp .env.example .env
chmod 600 .env
mkdir -m 700 -p credentials
chmod 700 credentials
```

Edit `.env` with a trusted editor after restricting its permissions; do not put secret values in shell commands or process arguments. Place the Identity-issued encrypted envelope at the path configured by `WS_PROXY_ENVELOPE_FILE` and restrict it to the current owner (`chmod 600 credentials/credential-envelope.json`). The template intentionally contains no envelope-shaped JSON sample; never invent an envelope or use a placeholder as a credential.

The adapter parses the file provided by `--config-env` as data. Do not source it in a shell or commit it. Inherited environment variables take precedence over values in the file. Keep client secrets, the local bearer token, and envelope in protected storage; never put them in task text, command arguments, logs, or model messages. No raw provider API key is needed by the agent process.

The current environment mode uses these settings:

| Variable | Purpose |
| --- | --- |
| `WS_PROXY_CONFIG_SOURCE` | Set to `env` for memory-only environment configuration. |
| `WS_PROXY_IDENTITY_URL` | Identity HTTPS origin. |
| `WS_PROXY_GATEWAY_URL` | Gateway WSS socket URL. |
| `WS_PROXY_CLIENT_ID` / `WS_PROXY_CLIENT_SECRET` | Confidential machine client credentials. |
| `WS_PROXY_LOCAL_BEARER_TOKEN` | Local adapter bearer credential. |
| `WS_PROXY_ENVELOPE_FILE` | Protected file containing the encrypted envelope. |
| `WS_PROXY_MODEL_ALIAS` | One project-authorized alias selected by the adapter when a request omits `model`. |
| `WS_PROXY_PROVIDER` / `WS_PROXY_PROTOCOL` | Provider and upstream protocol for the envelope mapping. |

Use values issued for your deployment; the `.invalid` addresses and `replace-with-*` values are placeholders. `WS_PROXY_PROVIDER` must match the exact provider ID granted to this project and client. The sample `openai` value is only the built-in provider example.

## Send a task

Provide a bounded task in a file:

```sh
node agent.mjs --config-env .env --task-file task.txt
```

Or pipe a task through stdin:

```sh
printf '%s\n' 'Summarize the attached design notes.' | node agent.mjs --config-env .env
```

`agent.mjs` sends a Chat Completions JSON request with separate system and user messages. It leaves `model` out so the adapter uses the configured authorized alias. It allows at most 32 KiB of task text, 16 KiB of trusted system instructions, and 1 MiB of encoded request JSON. The adapter writes the response to stdout and returns a nonzero exit status for request, stream, or cancellation failures. The wrapper does not retry, execute tools, or claim an interrupted result is complete.

The wrapper uses `--config-env` so Node does not consume the option as its own `--env-file` runtime flag. The adapter validates and parses the file as data.

The CLI can also accept standalone OpenAI-compatible request JSON for the supported API surface. See `examples/chat.json`, `examples/responses.json`, and `examples/tool-calls.json`. For tool calls, the adapter returns structured model output; the caller must inspect it and obtain explicit authorization before executing anything.

From the copied project, a direct Responses request is:

```sh
npm exec -- ws-llm-adapter --config-env .env request --api responses --input examples/responses.json
```

The `request` command starts a short-lived loopback adapter inside the process and shuts it down after the request; a separate long-running `serve` process is optional.

## Expose the local OpenAI-compatible API

For an SDK or local client that expects an OpenAI API server, start the adapter in a separate terminal:

```sh
npm run serve
```

Or run the same command explicitly with `npm exec -- ws-llm-adapter --config-env .env serve`.

It binds only to `127.0.0.1:43128` by default. Configure a client with base URL `http://127.0.0.1:43128/v1`, its `OPENAI_API_KEY` loaded from protected secret storage as the local adapter bearer, and a model name equal to the granted local alias. The adapter provides `/models`, `/chat/completions`, `/responses`, and `/completions` with JSON and SSE responses where supported. OAuth-bound aliases are Responses-only.

For example, after installing the OpenAI SDK with `npm install openai`, an application can receive `OPENAI_API_KEY` from its existing protected runtime environment without putting the value in command arguments:

```js
import OpenAI from "openai";

if (!process.env.OPENAI_API_KEY) throw new Error("OPENAI_API_KEY must be supplied by protected runtime configuration");
if (!process.env.OPENAI_MODEL_ALIAS) throw new Error("OPENAI_MODEL_ALIAS must be supplied as a granted local model alias");
const client = new OpenAI({
  baseURL: process.env.OPENAI_BASE_URL ?? "http://127.0.0.1:43128/v1",
  apiKey: process.env.OPENAI_API_KEY,
});
const result = await client.chat.completions.create({
  model: process.env.OPENAI_MODEL_ALIAS,
  messages: [{ role: "user", content: "Summarize the current plan." }],
});
process.stdout.write(result.choices[0]?.message.content ?? "");
```

Set `OPENAI_API_KEY` to the local adapter bearer through the runtime's protected environment or secret manager. Do not copy a bearer token into a curl command, source-code literal, or log.

To add the repository's optional agent skill to this copied project, run this from the client project and replace the source path with your checkout path:

```sh
mkdir -p .agents/skills/ws-llm-cli
cp /absolute/path/to/ws-llm-clfl-proxy/.agents/skills/ws-llm-cli/SKILL.md .agents/skills/ws-llm-cli/SKILL.md
```

## OAuth boundary

ChatGPT subscription OAuth is a separate local flow and only supports authorized native Responses aliases when the deployment operator has enabled remote eligibility. It does not make Chat Completions or arbitrary aliases work. This template does not sign in, mint grants, or bypass Identity policy. See the source repository's [OAuth guide](https://github.com/OrgGem/ws-llm-clfl-proxy/blob/main/docs/OAUTH.md) and [agent-client guide](https://github.com/OrgGem/ws-llm-clfl-proxy/blob/main/docs/AGENT-CLIENT.md) for the current boundary.
