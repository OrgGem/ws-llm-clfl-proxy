# Threat model

## Purpose and scope

This model covers the MVP request path from an OIDC-authenticated administrator or user, through Identity and the local adapter, to the Gateway and a configured LLM provider. It focuses on tenant isolation, credential protection, billable request abuse, stream integrity, and Worker resource limits. It records intended controls; it is not evidence that the implementation or deployment has passed security testing.

## Assets and trust boundaries

| Asset | Exposure to limit |
| --- | --- |
| Provider API keys and decrypted key bytes | Never expose through logs, URLs, exports, browser responses, or D1 plaintext records |
| Credential envelopes | Treat as sensitive bearer material; bind to one credential owner, project, provider, key version, and expiry |
| Machine access and refresh tokens | Prevent theft/replay; keep access tokens short-lived and refresh tokens hashed/rotated |
| User, project, client, credential, and model permissions | Prevent cross-user/project use and honor revocation on new requests |
| Prompts, completions, and tool payloads | Keep transient by default; never include in application logs or default database records |
| Provider spend and Worker capacity | Limit abusive starts, unbounded buffering, long requests, and excess concurrency |

The main boundaries are: browser and external OIDC provider to Identity; local application to the loopback adapter; adapter over WSS to Gateway; Gateway over a private Service Binding to Identity; Identity to D1; and Gateway over HTTPS to configured provider endpoints. Provider APIs receive the provider key and request content by design.

## Assumptions

- HTTPS/WSS, Cloudflare Worker isolation, Worker Secrets, D1, and private Service Bindings operate as documented and are configured under a protected Cloudflare account.
- The configured external OIDC provider correctly authenticates its users. User allowlisting is keyed by `(issuer, subject)`, not mutable email text alone.
- A compromised Identity or Gateway Worker, Cloudflare account administrator, or provider can access data visible to that component. AES-GCM envelopes do not hide API keys from the backend that must decrypt them.
- The user-controlled local application can see its prompts and responses. Malware running as the same local user may read adapter state or call its loopback API.
- A provider may retain or process prompts according to its own product and privacy terms; this service cannot make a provider forget submitted data.

## Threats and controls

### OIDC login and administrative UI

An attacker may forge a login callback, inject a login CSRF, exploit a weak redirect URI, or access an account that is not approved for the service. Identity uses a maintained OAuth/OIDC client library for authorization-code/PKCE, state, nonce, issuer, audience, signature, and callback validation. It allowlists the stable `(issuer, subject)` pair before creating an application session. The configured bootstrap email can approve only the first administrator; any prior admin allowlist row permanently consumes bootstrap, including a revoked row. A different OIDC subject cannot inherit access by presenting the same email. Redirect URIs are exact configured values. State-changing UI actions use CSRF protection, secure `HttpOnly`/`SameSite` session cookies, output escaping, and a restrictive content security policy. The UI never renders provider keys or access/refresh tokens after issuance.

Residual risk: compromise of the external IdP account, its signing keys, or an allowlisted user's browser session can authorize actions as that user. Removing a user from the allowlist must revoke their application sessions.

### Initial OIDC setup password

Before an OIDC administrator exists, an operator can install a 192-bit random temporary setup password verifier and a 24-hour expiration through Worker Secrets. This is a setup principal, not an application user or administrator. Login requires the configured same origin, a bounded JSON body and per-source rate limiting; setup sessions are short-lived opaque HttpOnly/Secure/SameSite=Strict cookies with hashed server-side state. Configuration writes require CSRF verification. A setup session cannot call normal management, token, pairing-approval or provider credential APIs. There is no public reset or hardcoded shared password.

Setup may change only trusted allowlisted OIDC issuers, their client configuration and the initial administrator email. Redirect URIs are derived from the configured public origin. OIDC client secrets are encrypted at rest with separate configuration AAD and fresh AES-GCM nonces; read APIs return presence flags only. A present but undecryptable configuration fails closed. A missing configuration can use the existing operator-supplied static settings. First verified administrator login permanently closes bootstrap, and historical administrator allowlist records prevent later reactivation even after revocation.

Residual risk: stealing the temporary password or setup cookie before bootstrap closes can let an attacker replace OIDC configuration and claim initial administration. Protect the private password file, use HTTPS, complete setup promptly, then remove the bootstrap secrets. Restricting setup to initial configuration limits access but does not remove this trust. Recovery after bootstrap is an operator action, not an unauthenticated application flow.

### Confidential and public machine clients

A public client cannot safely keep an embedded shared secret. The MVP uses no client secret for local/browser/mobile/CLI clients. A local client presents a short-lived pairing code; an already authenticated allowlisted user sees the device/client identity and explicitly approves its project delegation. Device codes are cryptographically random, pairing is single-use, short-lived (no more than ten minutes), and polling/guessing is rate-limited. Public clients receive a short-lived machine access token and a rotating opaque refresh token, not an OIDC ID token. Backend runtimes that can protect secrets may use confidential client credentials, with separate client registration and rotation. Confidential client secret rotation and client-model grant changes are restricted to the user who created the client; project managers can revoke a project client but cannot take over the creator's machine-token principal.

Residual risk: a user can approve a malicious device or share a pairing code. The approval page must show the client/device and project clearly, and the adapter must protect its local refresh token. Pairing is an app-specific delegation flow, not an OAuth/OIDC issuer implementation.

### JWT theft, replay, and revocation

An attacker who steals a bearer access token could replay it before expiry. Identity signs and verifies ES256 tokens through `jose`, resolves the required `kid` only against its configured public JWKS, and pins issuer and audience. Gateway receives claims only through the private Identity Service Binding, checks the returned issuer, audience, claim shapes, and strict expiry, then allows the handshake. Identity verifies the token and active delegation again for every `request.start`. Tokens expire after five minutes; Identity allows at most five seconds of clock skew, while Gateway does not extend expiry. Refresh tokens have at least 256 bits of randomness, are stored only as a cryptographic hash, rotate after every use, and are revoked on logout, client revoke, or user disallow. Identity checks token-backed session/client/user/project state and current credential/provider/model permission in D1 through the private Identity Service Binding for every `request.start`.

Replay within a valid token lifetime remains possible: a stolen token plus a valid envelope can start new provider calls, and request IDs only prevent duplicates on one socket. Revocation blocks subsequent starts but does not recall a provider call that passed authorization already. The request ID is not a global idempotency key, and retrying can incur another charge. The adapter reports a disconnect before terminal output as an interrupted, possibly billed attempt.

### Cross-tenant access and confused deputy

A malicious or buggy client may combine its token with another user's credential envelope, project ID, provider, or model. Identity derives the principal from the verified JWT rather than caller-supplied user IDs, checks that the active client/session belongs to that user and project, and checks the credential row's owner/project/provider/revocation/expiry plus provider and model permissions before authorizing each request. Gateway compares the authenticated envelope metadata to that result before decrypting. Project ownership and permission checks are required even when JWT and envelope fields match each other; matching fields alone do not establish ownership.

Identity owns D1 and should expose only the needed authorization operation to Gateway over a private Service Binding. A Cloudflare D1 binding has no row-level or binding-level read-only permissions. If Gateway receives a D1 binding in a later deployment, treat it as privileged database access and constrain every query in code and deployment configuration; do not describe it as read-only.

### Credential envelope disclosure or tampering

An attacker may steal or alter a locally stored envelope, substitute a key version, change ownership metadata, or attempt to use a revoked credential. AES-256-GCM uses a fresh 96-bit nonce and authenticates the canonical AAD containing version, credential ID, user ID, project ID, provider, key ID, and expiry. The envelope is submitted only in `request.start` over WSS. D1 retains ownership/provider/key-version/expiry/revocation metadata; Identity checks it for each start. Gateway decrypts only after authorization and keeps the plaintext key only for the upstream operation. Encryption keys remain in Worker Secrets, key versions are retained only while valid envelopes need them, and the adapter must never log/export envelopes.

The backend can decrypt these envelopes; this is at-rest protection for the local copy, not end-to-end encryption. A stolen valid envelope by itself cannot authorize a call, but it remains reusable with a valid token until expiry or revocation. API-key plaintext is capped at 8 KiB. JavaScript cannot guarantee immediate zeroization of immutable string copies; implementations should minimize plaintext lifetime and avoid creating unnecessary copies.

### Local API abuse and DNS rebinding

A hostile web page may try to call the adapter through a browser, exploit DNS rebinding, or read data returned by local endpoints. The adapter binds only to `127.0.0.1` and/or `::1`, requires a local random bearer secret for API access, validates Host and Origin against loopback, disables credentialed cross-origin access, and does not authorize using browser cookies. The adapter's token/envelope state uses restrictive local file permissions. Cancellation and local client disconnects propagate through the WebSocket to the upstream fetch.

Residual risk: any process running as the same local user can usually read local state or make loopback calls. This adapter is part of the application deployment, including ChatGPT Cloud; it is not a separately trusted public service.

### SSRF and provider endpoint substitution

A compromised or malicious client could try to make Gateway contact an internal address or leak a provider key to an attacker endpoint. No WebSocket frame contains an upstream URL, hostname, path, redirect, or authentication header. Gateway resolves provider and model aliases from server-controlled registry data, restricts endpoints to exact configured HTTPS origins and paths, injects the authorized upstream model, and disables redirects. Provider headers are constructed by trusted provider-specific code. Custom endpoint support requires explicit administrator allowlisting, HTTPS/origin validation, and a new SSRF review.

The Gateway must not trust a model name merely because it came from an authorized client; authorization and alias-to-upstream-model mapping are checked for each request. Provider errors are sanitized so response bodies or request headers do not leak keys.

### Stream replay, cancellation, and partial output

WebSocket message delivery does not provide resumable provider execution. A duplicate request ID on one socket is rejected; a retry after a disconnect uses a new ID and is a separate billable attempt. Chunks carry monotonically increasing sequence numbers and one attempt has one terminal `response.end` or `response.error` while the connection remains available. Gateway's `response.end` signals HTTP body EOF only; the adapter parses the provider stream and requires the provider's success sentinel (such as OpenAI Chat Completions `[DONE]` or Anthropic Messages `message_stop`) before reporting successful local SSE completion. Missing sentinel, malformed final event, or terminal provider error is an interrupted/invalid response, never success or an implicit retry. `request.cancel`, local disconnect, Gateway timeout, and slow-client failure abort the upstream fetch and reader. A request already processed by the provider may still have incurred a charge.

### Slow clients and resource exhaustion

An attacker can open many sockets, send large starts, hold requests open, or stop reading output to consume Worker memory/subrequests and provider capacity. Limits include one MiB request frames and provider bodies, eight active requests per socket, eight unacknowledged chunks per request, a 32 KiB protocol chunk ceiling (Gateway currently emits at most 16 KiB), a 4 MiB tracked pending serialized chunk-frame budget, an 8 MiB cumulative serialized outbound-frame budget per socket lifetime (including control and terminal frames; never refunded by ACKs), 16 MiB response text per request, a 15-second ACK deadline, 60-second provider read-idle and no-active-request socket idle deadlines, a 300-second request deadline, a 30–300-second hard project socket lifetime, and 1,024 request IDs per socket. ACKs are bound to the request and cannot exceed the highest chunk sent, and remain accepted after a terminal event while earlier chunks are outstanding. However, ACKs are client assertions: a malicious authenticated direct WebSocket peer can falsely acknowledge unconsumed chunks and release the tracked 4 MiB pending budget. Gateway reserves room for policy draining when possible, then closes with 1013 and aborts active work when the 8 MiB lifetime cap is reached; the 16 MiB request source cap can therefore be interrupted sooner by the socket-wide cap. Workers has no dependable outbound drain signal, so these application counters do not prove a bound on the runtime internal send queue. The adapter is trusted to ACK only after local output is accepted. Gateway pauses upstream reads when the ACK window is full, then aborts and closes the socket with code 1013 on timeout; other requests sharing the socket may also be interrupted. At the hard project socket lifetime, Gateway closes with policy draining and cancels active requests, which may have already incurred provider charges. There is no claim that these per-socket limits enforce an exact account-wide quota; that requires an atomic coordinator and benchmark evidence. Deployment also needs request-rate and connection admission controls appropriate to the account.

Cloudflare Worker CPU, subrequest, socket, and buffering behavior must be measured under the target plan. Do not infer capacity from the local limits or from a ten-request experiment. Record benchmark configuration and failure conditions in the Phase 1 results.

### Logs, database, and exports

Raw provider credentials, decrypted keys, envelopes, access/refresh tokens, prompts, completions, tool payloads, and provider response bodies are excluded from application logs, default D1 rows, URLs, UI exports, and error responses. Audit events contain only necessary metadata such as actor ID, project ID, credential/client ID, action, outcome, and timestamp. Request and connection IDs may be logged for correlation but must not be used to retrieve prompt/response content. Provider URLs in logs must be static configured endpoints without credentials. Errors are sanitized and stacks stay in restricted diagnostics.

Database retention is limited to account, project, client, credential metadata, sessions, authorization state, minimal audit records, and optional non-content usage estimates. Migrations and D1 access permissions are controlled by Identity/CI deployment configuration. Export paths are reviewed to ensure they cannot include secrets or envelopes.

## Security verification gates

Before staging is called ready, focused negative-path tests must cover invalid/expired/wrong-audience tokens, revoked sessions and credentials, cross-user/project envelopes, tampered AAD/ciphertext, disallowed provider/model pairs, pairing brute force/reuse/expiry, local non-loopback and hostile-origin access, redirect/endpoint substitution, replayed/duplicate IDs, ACK jumps and timeout, cancel races, slow readers, an active stream crossing the hard project session cap, disconnect before terminal, upstream 429, missing provider success sentinels, and log/export redaction. Staging verification must confirm the actual Cloudflare binding layout and secret/key rotation procedure. A passing unit suite does not by itself satisfy this gate; implementation status and staging evidence must track any remaining coverage or deployment checks.
