# Local OpenAI-compatible adapter

The adapter runs on the user's machine and exposes `GET /v1/models` and `POST /v1/chat/completions` on `127.0.0.1`. It obtains a machine access token from Identity over HTTPS and sends that token in the Gateway WSS `Authorization` header. Confidential client credentials use OAuth HTTP Basic authentication over HTTPS. Local auth state is stored in an owner-only config file. The adapter is not a hosted service.

Build the workspace and run the packaged CLI with Node 22.13 or newer:

```sh
npm ci
npm run build
node apps/adapter/dist/bin.js help
```

For public desktop pairing, run:

```sh
node apps/adapter/dist/bin.js pair \
  --identity-url https://identity.example \
  --gateway-url wss://gateway.example/v1/socket
```

Open the printed verification URL in a browser where you are signed in, approve the adapter, and wait for pairing to finish. The adapter receives a rotating refresh token through the device flow; it does not store or read the browser session cookie.

For an administrator-provisioned confidential client, set `WS_PROXY_CLIENT_SECRET` in the process environment and run:

```sh
node apps/adapter/dist/bin.js configure-machine \
  --identity-url https://identity.example \
  --gateway-url wss://gateway.example/v1/socket \
  --client-id CLIENT_ID
```

For an Identity bootstrap export, use `configure-bootstrap FILE`. The export contains service URLs, a public client ID and kind, project ID, model aliases with provider IDs and wire protocols, and bounded limits, but no client secret or credential envelope. A confidential client uses the exported client ID and reads `WS_PROXY_CLIENT_SECRET`; a public bootstrap starts a fresh pairing and creates a new user-approved client, ignoring the export's public client ID. After setup, add the encrypted envelope and map an allowed alias as below.

```sh
node apps/adapter/dist/bin.js configure-bootstrap client-bootstrap.json
```

Add an encrypted credential envelope exported for the signed-in user's project. The envelope file must be owner-only (`chmod 600 credential-envelope.json` on Unix-like systems):

```sh
node apps/adapter/dist/bin.js envelope add credential-envelope.json
node apps/adapter/dist/bin.js model add --id my-chat --provider openai --credential-id CREDENTIAL_ID
node apps/adapter/dist/bin.js model list
```

System administrators can register a custom public HTTPS provider in Identity's Providers screen. Its provider ID and endpoint are immutable; register another ID to use a different endpoint. Custom routes use the OpenAI chat-completions protocol, and their API keys use the same encrypted credential form. After registration, add an alias with the provider ID and explicit protocol:

```sh
node apps/adapter/dist/bin.js model add --id vendor-chat --provider my_provider --protocol openai --credential-id CREDENTIAL_ID
```

`my-chat` is the local alias sent to Gateway; Identity and Gateway authorize the alias and credential against the project. The adapter keeps the registry provider ID for Gateway authorization and uses the binding's protocol for request and stream conversion. Legacy built-in aliases may omit protocol because `openai` and `anthropic` map to their matching protocol; custom provider IDs require one. For Anthropic, `tool_choice: "none"` omits tool definitions, and `parallel_tool_calls: false` disables parallel tool use. Unsupported tool-choice shapes and non-boolean parallel settings return a request error rather than being silently dropped. Provider selection, endpoint, upstream model, and keys stay under server-side policy.

Start the local server with:

```sh
node apps/adapter/dist/bin.js serve
```

It binds only to `127.0.0.1`, defaults to port `43128`, and requires the local bearer token for every API request. Retrieve that token explicitly with `node apps/adapter/dist/bin.js token`; treat it like a password and pass it through your client configuration. The config path is `~/.config/ws-llm-clfl-proxy/adapter.json` by default. Set `WS_PROXY_ADAPTER_CONFIG` before setup to use another path. The config directory and file are created with `0700` and `0600` permissions on Unix-like systems.

Configure an OpenAI client with base URL `http://127.0.0.1:43128/v1`, API key from the explicit `token` command, and model `my-chat`. Browser requests must use a loopback Origin; non-loopback Host and Origin values are rejected. A local client disconnect cancels the Gateway request. An interrupted call is never silently replayed and may have been processed or billed upstream.

The executable in `dist/bin.js` is bundled with the shared protocol code. To create a local tarball for distribution alongside the client, run `npm pack --workspace @ws-proxy/adapter`. The package remains private to this repository and is not published by the build.

## Real Workers benchmark

`node scripts/benchmark-workers.mjs` sends actual streamed completions through the running local adapter and its configured remote Identity and Gateway URLs at concurrency 1, 5, and 10. It does not generate placeholder measurements. First configure a real model and envelope and build the adapter. Start one terminal with:

```sh
WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS=1 node apps/adapter/dist/bin.js serve
```

The benchmark verifies that one-socket limit through the local models response before it makes provider calls. Record the actual upstream model mapping in `BENCHMARK_UPSTREAM_MODEL`; the local alias does not reveal that server-side mapping. Then set:

```sh
BENCHMARK_MODEL_ALIAS=my-chat \
BENCHMARK_UPSTREAM_MODEL=provider-model-name \
BENCHMARK_PROMPT_FILE=/secure/path/benchmark-prompt.txt \
node scripts/benchmark-workers.mjs
```

The prompt file must be owner-only and at most 64 KiB. Its contents are sent to the configured provider, but only its byte length and SHA-256 are recorded. To save the report, set `BENCHMARK_OUTPUT_FILE` to a new path; the report is created with owner-only permissions and refuses to overwrite an existing file. Reports include the timestamp, commit when available, runtime/platform, target service origins, model alias, declared upstream model, concurrency outcomes, time to first byte/content, total time, and error codes. Worker plan is `unverified` unless `BENCHMARK_WORKERS_PLAN` is supplied; Worker CPU and memory are recorded as unavailable. The measurement is local end-to-end wall-clock time through adapter, Gateway, and provider, not isolated Worker CPU time. Each Gateway socket accepts the negotiated `maxInFlight` count (1–8). The ten-request scenario uses one socket and reports overload for requests above that limit (two at the default limit of 8); it neither opens extra sockets nor retries. This is a concurrency experiment, not a capacity guarantee. Reports exclude prompts, completion text, local bearer tokens, machine credentials, and envelopes.
