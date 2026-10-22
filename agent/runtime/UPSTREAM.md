# YoAgent runtime provenance

- Upstream: https://github.com/trlongvn/yoagent
- Source commit: `fa42372e6cabf9ef2d2c4019693da8076e0ef3bb`
- Imported: 2026-10-21
- Upstream crate: `agent` 0.25.11, MIT; see [LICENSE](LICENSE).
- Local home: `agent/runtime/`, an internal runtime crate used by the native CLI in `agent/`.

This is a deliberately small source subset for the CLI and local-memory path, not a complete upstream checkout. It retains the Agent loop, context/session/types, retry and extension lifecycle; supporting APIs required by those paths, including `SharedState`, `ToolSource`, and model `CostConfig`; the minimal OpenAI-compatible Chat Completions request/stream and tool-argument conversion surface; and the Uteke memory backend and tools. It omits the upstream TUI and other binaries, non-OpenAI providers, MCP, sub-agents, decision/GASP/OpenAPI/skills systems, unrelated examples and tests, and personal memory databases, journals, indexes, or caches. The consolidation and scope are recorded in [ADR 0008](../../docs/decisions/0008-compact-agent-directory.md), which supersedes the broad source-retention scope of [ADR 0007](../../docs/decisions/0007-agent-direct-ws.md).

Local changes retained in this subset:

- A small Gateway-facing OpenAI-compatible payload/stream interface builds bounded Chat Completions requests and parses provider SSE without adding another provider transport. The native client owns authenticated WSS transport.
- The upstream merge's duplicate batch-size clamp in `agent_loop.rs` was removed; the original zero-size protection and batching behavior remain.
- Optional tracked memory-hook tasks and bounded draining let the one-shot CLI wait for final-turn `remember:`/`forget:` writes. Existing untracked hook APIs retain their behavior.

The memory implementation and policy remain the upstream Uteke design. Do not replace it with another engine or import any user's runtime memory data. Keep credentials out of examples and this source snapshot. Validate the retained runtime with the focused agent and memory tests; upstream-wide suites are outside this trimmed crate's scope.
