# YoAgent on the WebSocket Gateway

`agent/` contains the native Rust runner, the trimmed YoAgent runtime under `agent/runtime/`, and its optional Uteke memory integration. Its `GatewayProvider` sends OpenAI-compatible Chat Completions directly over the existing WSS Gateway; it does not run the TypeScript adapter or another HTTP service.

## Configure and run

Install a stable Rust toolchain. The manifests declare Rust 1.87 or newer; this integration was validated with Rust 1.99.1. Cargo dependencies are pinned in `Cargo.lock`.

Copy [`agent/.env.example`](../agent/.env.example) to `.env`, replace the placeholders with the confidential client settings and a currently authorized model alias, then set the file and exported credential envelope to owner-only permissions. Use the exact provider ID and model alias granted to the client in Identity. The model alias is the project authorization key; it is not an upstream model name.

From the repository root, provide task text over stdin or through a bounded UTF-8 file. The task body is never an argument:

```sh
cargo run --manifest-path agent/Cargo.toml --package ws-llm-agent -- --config-env .env --task-file private/task.txt
cat private/task.txt | cargo run --manifest-path agent/Cargo.toml --package ws-llm-agent -- --config-env .env
```

The runner reads no provider API key. It requests a short-lived Identity machine token and sends that token only in the WSS Authorization header; the encrypted envelope travels in the authenticated request frame. Neither value is printed. The base URL inside YoAgent's model metadata is inert: the custom provider handles the stream through Gateway.

Runs have a 32 KiB task input ceiling, 16 MiB output ceiling, a five-minute generation deadline plus bounded shutdown grace, a bounded turn/token budget, and YoAgent retries are disabled. A nonzero exit means the request or its cleanup failed; stdout may contain partial or complete model text, so do not present it as complete until the failure is understood. Do not automatically retry an interrupted request. A new run is a separate provider attempt and may incur another charge.

The default tool list is empty. Memory save/manage tools appear only when memory is explicitly configured; shell and filesystem tools are not registered by this runner. The internal runtime contains only the core and memory paths required by this CLI, rather than the upstream TUI, unrelated integrations, or additional tool systems.

## Optional local memory

Pass `--memory-config FILE` and compile with `--features memory` to enable the original Uteke integration. The checked-in [`agent/memory.example.json`](../agent/memory.example.json) is only a template; copy it to an owner-only file because the runner rejects group/world-readable or symlinked config files. It uses local Ollama embeddings and a per-project path below `.agent-state/`.

```sh
mkdir -p private
chmod 700 private
install -m 600 agent/memory.example.json private/memory.json
cargo run --manifest-path agent/Cargo.toml --package ws-llm-agent --features memory -- \
  --config-env .env \
  --memory-config private/memory.json \
  --task-file private/task.txt
```

The runner requires an explicit `ollama` or `openai` embedding backend and a dedicated memory database path. It does not compile YoAgent's ONNX memory feature. OpenAI embeddings require a separate key in the protected memory config or `UTEKE_EMBEDDING_API_KEY` from a secret manager; the runner refuses to borrow `OPENAI_API_KEY`. Embedding requests go directly to the explicitly selected local/external embedding backend, never through the LLM Gateway. Before exit, the runner drains pending `remember:`/`forget:` hook work for up to five seconds; a failed or timed-out memory operation returns nonzero. Do not reuse one memory database across projects or agents, and keep SQLite/index/cache state out of Git.

Persistent memory stays on the client. Recalled facts enter the model context sent through Gateway; an external embedding backend also receives text needed for embedding.

## Validate changes

```sh
cargo test --manifest-path agent/Cargo.toml --package ws-llm-agent --features memory
cargo clippy --manifest-path agent/Cargo.toml --package ws-llm-agent --all-targets --all-features -- -D warnings
npm run test:agent:native
```

The npm smoke requires `npm ci` and Cargo on PATH. It builds the binary and runs fixture Identity/WebSocket peers to check success, provider errors, disconnects, cancellation and no automatic retry. It makes no real LLM call. Existing Worker/adapter checks remain `npm run check`.

## Operational boundaries

- Protect `.env`, the credential envelope, and memory config with owner-only permissions. On Unix, the runner rejects group/world-readable and symlinked memory config files; the memory database directory is set to `0700` and its SQLite file to `0600` before use. On Windows, apply equivalent current-user-only ACLs to these files and the memory directory. The Gateway env parser rejects group/world-readable credential files on Unix.
- Do not put task text, secrets, or envelope data in shell history, argv, logs, or memory unless the user intended that content to be retained.
- A Gateway rejection, timeout, disconnect, cancelled run, or length stop returns a nonzero status. Preserve that status and report partial output as incomplete.
- The model receives no tools by default. Memory tools are scoped operationally by a private store dedicated to one project/agent; they do not grant server-side model permissions.
- No real provider generation or external embedding call is implied by local compilation or fixture tests. Check [implementation status](IMPLEMENTATION-STATUS.md) for live evidence and remaining gates.

For the compact runtime scope, see [ADR 0008](decisions/0008-compact-agent-directory.md). For the direct WSS design and credential boundary, see [ADR 0007](decisions/0007-agent-direct-ws.md), [WebSocket protocol](PROTOCOL.md), and [the threat model](THREAT-MODEL.md).
