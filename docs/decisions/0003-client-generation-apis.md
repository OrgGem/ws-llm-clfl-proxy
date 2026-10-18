# ADR 0003 — Responses and completion generation APIs

Date: 2026-10-18. Status: accepted for implementation following the client's explicit Responses/streaming request.

## Decision

The loopback adapter exposes independent POST contracts for `/v1/responses`, `/v1/chat/completions` and legacy `/v1/completions`. Each supports streaming and buffered JSON generation. Responses is not renamed Chat Completions: OpenAI-protocol providers receive the native fixed `/responses` endpoint and retain typed Responses events, output items, function-call arguments, reasoning and usage. Legacy Completions uses the native fixed `/completions` endpoint. Anthropic remains supported through Chat Completions; Responses/legacy Completions on an Anthropic-protocol model are rejected explicitly instead of silently changing semantics.

An optional `api` discriminator on normal v1 `request.start` is the enum `chat.completions | responses | completions`; omission preserves the existing chat behavior. It selects only a server-built operation suffix inside the already authorized provider's immutable Base URL. It cannot select a protocol, host, arbitrary path or model. ACK frames are unchanged. The adapter forwards the discriminator, and Gateway rejects unsupported protocol/operation pairs before decryption/upstream dispatch. All existing per-request authorization, DNS, redirect, size, ACK, cancellation and lifetime controls remain.

Responses generation is stateless: `store` is forced false, background generation and remote conversation/previous-response handles are rejected. Callers submit prior input/output items explicitly. This avoids implementing an unscoped remote object store and preserves the default no-prompt/response-retention policy. Retrieval, deletion, listing, background cancellation and server-managed conversations are outside this POST-generation contract. Disconnect aborts the current upstream request; retries remain explicit new attempts.

Responses SSE uses named typed events and ends on `response.completed`, `response.incomplete` or a safe failure, without inventing a Chat Completions `[DONE]` sentinel. Successful terminals are withheld until Gateway `response.end`, so a transport error cannot appear as success. Buffered mode returns the terminal Response object. Provider errors are sanitized, and malformed/truncated streams never become successful JSON or a successful stream terminal. Output buffering/event sizes remain bounded. Chat/legacy SSE use `[DONE]` only after successful Gateway completion and preserve finish reasons, tool calls, logprobs where supported and provider-supplied usage.

## Validation boundaries

Continue testing the established public boundaries: loopback HTTP requests and SSE/JSON responses; the WebSocket wire contract; and Gateway private authorization plus fixed upstream HTTP routing. Include chunk fragmentation, text/tool/usage, incomplete/failed responses, disconnects, malformed data, cancellation, parameter validation and existing cross-tenant/credential checks. No real provider call or billed benchmark is implied by fixture-based tests.

## References

- https://developers.openai.com/api/reference/resources/responses/streaming-events
- https://developers.openai.com/api/reference/resources/responses/methods/create
- https://developers.openai.com/api/reference/resources/completions/methods/create
- https://developers.cloudflare.com/workers/best-practices/workers-best-practices/

Native provider capability is external: a custom OpenAI-compatible endpoint may implement Chat Completions without implementing Responses or legacy Completions. There is no silent fallback or retry to another API.

## Live provider diagnostics

A rejected upstream HTTP response exposes only its bounded numeric HTTP status in a fixed Gateway error message. Response bodies, error descriptions, headers and exception text remain excluded. This distinguishes credential/parameter/provider failures without reading the provider key or relaxing the allowlist; the Gateway still never retries. HTTP 429 retains its existing rate-limit classification.
