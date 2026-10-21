# Imported yoagent source

- Source: https://github.com/trlongvn/yoagent
- Commit: `fa42372e6cabf9ef2d2c4019693da8076e0ef3bb`
- Imported: 2026-10-21
- Crate: `agent` 0.25.11, MIT; retain [LICENSE](LICENSE).

This source snapshot preserves the owner's Agent runtime and optional Uteke memory implementation. Runtime databases, SQLite journals, vector indexes, embedding caches and other contents of the upstream `memory/` directory are deliberately excluded. Git metadata, upstream CI and unrelated integrations are not imported. Source, tests, examples and design documents are retained.

Local changes expose a small transport-independent OpenAI stream interface for the native Gateway client in `apps/agent`; the original HTTP providers remain available. See [ADR 0007](../../docs/decisions/0007-yoagent-direct-ws.md). Do not replace the imported memory module with a new implementation or copy personal memory databases into this snapshot when updating it.

The imported merge also repeated the batch-size clamp in `agent_loop.rs`, dereferencing an already-shadowed `usize` and preventing compilation. Remove only the duplicate clamp; the original zero-size protection and batching behavior remain intact.

Nonempty API-key example fields in two imported JSON configurations are cleared. Supply embedding credentials only through protected runtime configuration; example files must not carry credentials.

The memory module adds opt-in tracked hook tasks and a drain method so a one-shot executable can wait for final-turn `remember:`/`forget:` work before exiting. Existing untracked hook APIs keep their original behavior; the new client uses the tracked variant. The backend, recall/context design, write policy and memory tools remain the imported implementation.

The imported fork mixes `agent` and `yoagent` crate names in some integration tests. The package/library name is preserved; targeted core, Chat Completions and memory suites are validated. The entire upstream all-feature/all-integration suite is not a release claim. The workspace defaults to the new client; test the imported package with explicit targets.
