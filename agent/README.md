# ws-llm-agent

Native Rust runner with a trimmed YoAgent runtime under `runtime/`. The `GatewayProvider` routes model calls directly over the authenticated WSS Gateway; it does not run a separate HTTP service.

This directory contains the Cargo workspace/lockfile, CLI and WS transport (`src/`), required loop/context/memory code (`runtime/`), environment and memory examples, fixture tests and the CLI skill (`.agents/skills/ws-yoagent/`). The runtime is an internal library, not another executable.

See [`docs/YOAGENT.md`](../docs/YOAGENT.md) for limits, memory boundaries, and protocol details. From the repository root, copy the environment template, replace its placeholders, and protect both it and the exported envelope:

```sh
cp agent/.env.example .env
chmod 600 .env
cargo run --manifest-path agent/Cargo.toml --package ws-llm-agent -- --config-env .env --task-file private/task.txt
```

Replace the sample values first, export the credential envelope to the configured path, then restrict that file to mode `0600` as well. The runner reads task text from stdin when `--task-file` is omitted. It never accepts task content on argv, has no shell/filesystem tools by default, and disables automatic retries. A nonzero exit means the response may be partial; preserve the status and do not retry automatically.

When working directly inside this directory, use `cargo run -- --config-env .env --task-file private/task.txt`; keep the env, task and envelope paths relative to that working directory. No parent Cargo workspace is required.

## Optional local memory

Memory remains disabled unless you explicitly pass a private config and compile with the feature. The checked-in `memory.example.json` is a template, so copy it to a regular owner-only file before use:

```sh
mkdir -p private
chmod 700 private
install -m 600 agent/memory.example.json private/memory.json
cargo run --manifest-path agent/Cargo.toml --package ws-llm-agent --features memory -- \
  --config-env .env --memory-config private/memory.json --task-file private/task.txt
```

The example uses local Ollama embeddings and a dedicated per-project path. Only explicit `ollama` and `openai` embedding backends are accepted; ONNX is not compiled in. OpenAI embeddings need a separate Uteke key in the protected memory config or `UTEKE_EMBEDDING_API_KEY` from a secret manager. The runner never borrows `OPENAI_API_KEY`, reuses the Gateway client secret, or sends embedding credentials through WSS. On Unix, its SQLite directory and database file are restricted before use; on Windows, apply equivalent current-user-only ACLs. Do not share a memory database across projects or agents.

Memory opt-in registers only YoAgent's memory save/manage tools. It does not add shell or filesystem tools. Persistent storage stays on the client; recalled facts enter the model context sent through Gateway.
