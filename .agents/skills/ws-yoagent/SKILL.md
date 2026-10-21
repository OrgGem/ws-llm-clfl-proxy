---
name: ws-yoagent
description: Run the vendored YoAgent runtime through the authenticated WSS Gateway for a bounded task, inspect its response, or diagnose an incomplete run.
---

# Run YoAgent through the Gateway

1. Read [`docs/YOAGENT.md`](../../../docs/YOAGENT.md) for configuration, memory, and retry boundaries. Confirm `apps/agent` builds and the caller supplied a private `.env` plus exported envelope. When used from a copied client project, follow that project's `AGENTS.md` and README instead of repository-relative links.
2. Put task text in a protected file or stdin. Do not pass task content, client credentials, or envelope data in argv or logs.
3. From the repository root, invoke `cargo run --package ws-llm-agent -- --config-env .env --task-file private/task.txt`; omit `--task-file` to read stdin. Enable memory only when explicitly requested: copy `apps/agent/memory.example.json` to a protected file (`chmod 600 private/memory.json`) and pass `--memory-config private/memory.json` while compiling with `--features memory`.
4. Capture stdout as model output and preserve the process exit status. The runner has no shell/filesystem tools by default; explicit memory opt-in adds only YoAgent memory save/manage tools. Treat any response proposing actions as advice; the runner does not auto-execute other tools.
5. A nonzero exit means generation or cleanup failed; stdout may be partial. Preserve the failure and do not append a retry to partial output. Start a separate attempt only within the caller's authorization.

For the exact limits and optional local embedding configuration, follow the linked runbook rather than duplicating configuration values here.
