# ADR 0007 — Preserve yoagent with a native Gateway provider

2026-10-21. Accepted for the owner's request to import their agent and memory design from `trlongvn/yoagent`.

Vendor the MIT-licensed source at commit `fa42372e6cabf9ef2d2c4019693da8076e0ef3bb`, retaining its Agent loop, session/context machinery and optional Uteke memory integration. Exclude source repository memory databases, vector indexes, caches and credentials. Record provenance and narrowly scoped local patches so the imported design remains identifiable and maintainable.

Add a native Rust client application under `apps/agent`. Its provider implements yoagent's StreamProvider and opens the existing Gateway WebSocket directly: no local HTTP intermediary and no additional cloud service. Reuse the existing OpenAI request/message conversion through a small vendored parser interface; preserve Gateway authentication, credential envelope, sequence and ACK contracts. Start with OpenAI-compatible Chat Completions and fail explicitly for unsupported protocols/APIs instead of silently rerouting them.

Confidential runtime configuration uses the existing WS_PROXY environment names and protected envelope file. The client obtains a short-lived machine access token from Identity and sends it only in the WebSocket Authorization header. Envelope credentials remain distinct from Gateway access tokens. No provider key is required locally, no credential goes in a URL, no arbitrary upstream URL is accepted, and no provider OAuth gate changes.

Disable yoagent's default retry policy in this runner: an interrupted or rejected attempt is returned explicitly. Bound socket frames, SSE parsing, generated content, task input and run length; propagate cancellation and enforce session/token expiry. Do not enable shell/filesystem tools by default. Preserve original memory hooks/tools behind explicit opt-in with a private store dedicated to one project/agent; memory and any separately configured embedding backend remain local-client responsibilities, not Gateway persistence. Never import pre-existing personal memory contents into Git.

Validate with fixture Identity and a real local WebSocket peer: authentication, tool-call reconstruction, sequence/terminal checks, error and disconnect paths, cancellation and no retry. Verify original agent/memory behavior separately with the imported tests. Real provider generation and external embedding calls require separately labelled evidence.
