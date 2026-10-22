# ADR 0008 — Consolidate the CLI and memory under agent/

2026-10-22. Accepted for the owner's request to remove the broad vendor import and keep only the agent CLI and memory in one directory.

Move the native application to `agent/` and retain its required runtime as a small internal crate at `agent/runtime/`. Both crates, their focused tests, environment/memory examples, Cargo workspace/lockfile and licensing live under that single directory. Remove the `apps/agent`, `vendor/yoagent` and root Cargo workspace files. Repository-root commands select `--manifest-path agent/Cargo.toml`.

Preserve the working direct WSS authentication, envelope, streaming, cancellation and no-retry behavior. Keep the existing Agent loop, context/session machinery and Uteke memory design, including tracked final-turn writes. Retain only supporting modules actually needed by those paths; remove upstream TUI/binaries, unused providers, optional integrations, broad examples/documentation and unrelated tests/dependencies. The previous source snapshot and exact provenance remain available in Git history.

This request supersedes the broad source-retention scope in ADR 0007. CLI and memory are the requested runtime surface; no new TUI is added. Do not replace memory with another engine or change provider access gates during this restructuring. Preserve MIT attribution and describe retained source and local changes in the agent's provenance note.

Validate retained runtime/memory and native-client tests, Clippy, direct-WS process fixtures, Cargo metadata/path resolution and the existing npm checks. Report current test counts after removing unrelated suites instead of comparing them as a test-coverage regression.
