# ADR 0006 — Agent CLI and environment configuration

2026-10-18. Accepted for the owner's agent-template request.

Reuse the local adapter and its GatewayClient for agent CLI generation and OpenAI-compatible loopback serving; do not add a third cloud service or a second wire protocol. A request command accepts bounded OpenAI JSON from stdin/file, supports Chat Completions, native Responses and legacy Completions, emits JSON or SSE to stdout, and returns nonzero on HTTP/stream/interruption failures. Attach cancellation to SIGINT and obey writable backpressure. Tool calls are returned as structured data and never automatically executed. No hidden retry or continuation across interrupted streams.

Environment mode is explicit and intended for confidential agent runtimes: Identity/Gateway URLs, client ID/secret and local API bearer come from environment, encrypted provider envelope from a protected file, and alias/provider/protocol from explicit configuration. No raw provider API key is required. Existing paired/public-client config remains available; do not silently treat a distributed application as a confidential client. Environment runtime state remains in memory; avoid persisting env secrets into another JSON file. Env-file loading must parse data rather than execute shell code and preserve inherited environment precedence. Reject unsupported/partial settings with fixed errors that never include secrets.

Agent templates and the CLI skill must point to tested commands and explain provider/model grants, structured tool calls, cancellation, retry ownership and the native Responses OAuth boundary. Template files contain placeholders, never a real envelope, prompt, token or secret. Tests cover env precedence/secret-free failures, actual HTTP→WS request/stream/tool paths, failure exit behavior and loopback binding.

Use `--config-env FILE` for the protected dotenv reader. Node may consume its reserved `--env-file` flag before application execution; that flag would bypass application file validation. Read bounded bytes from a checked file handle, parse with Node's dotenv grammar, and accept only documented runtime configuration keys.
