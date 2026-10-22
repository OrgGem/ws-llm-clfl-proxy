# Internal YoAgent runtime

This crate is the trimmed runtime used by the native CLI in [`agent/`](../README.md). It is not a standalone agent application or a general-purpose provider SDK. The upstream source, license, exact scope, and local changes are recorded in [`UPSTREAM.md`](UPSTREAM.md); the original MIT license is preserved in [`LICENSE`](LICENSE).

The retained code supports the CLI's Agent loop, context and session lifecycle, retry and extension hooks, model/configuration metadata, and the helper APIs those paths depend on, including `SharedState`, `ToolSource`, and `CostConfig`. Its provider surface is limited to the OpenAI-compatible Chat Completions request builder, strict incremental SSE/tool-argument parser, and a mock provider for offline tests. The optional `memory` feature keeps the upstream Uteke integration and tracked hook draining used to persist final-turn memory work.

The adjacent CLI crate owns Identity authentication, credential-envelope handling, and WSS transport. The runtime has no provider HTTP client path. The CLI installs no tools by default; it enables only the memory save/manage tools when memory is explicitly configured. TUI and command binaries, unrelated provider protocols and integrations, and shell/filesystem tool suites are not part of this retained runtime.

Run focused checks from the repository root:

```sh
cargo test --manifest-path agent/Cargo.toml --package agent --features memory
cargo clippy --manifest-path agent/Cargo.toml --package agent --all-targets --all-features -- -D warnings
```

The runner and fixture smoke are documented in [`agent/README.md`](../README.md) and [`docs/YOAGENT.md`](../../docs/YOAGENT.md). This trimmed crate does not claim to pass the original upstream all-target suite.
