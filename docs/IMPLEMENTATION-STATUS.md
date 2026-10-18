# Implementation and release evidence

Date: 2026-10-17. Implementation: five GPT-6 Luna agents at max reasoning, coordinated in the shared repository; independent review: GPT-6 Sol.

## Implemented

- Identity Worker: configured external OIDC client with PKCE/state/nonce and ID-token signature verification, stable principal allowlist, confidential client credentials, public pairing, rotating hashed refresh credentials, live session/client/user/project checks, project and client model permissions.
- AES-256-GCM envelopes with authenticated ownership/provider/expiry/key version; D1 stores metadata and revocation state only. Keys are Worker Secrets; local adapter stores the envelope privately.
- Private `IdentityInternal` WorkerEntrypoint Service Binding; public internal routes are denied. Gateway has no D1 or private signing-key binding in its deployment configuration.
- Gateway protocol v1 multiplexing, sequenced chunks, cancellation, token expiry, hard project/session limits, ACK credit, upstream read limits, and an absolute 8 MiB cumulative serialized output cap per socket. OpenAI and Anthropic endpoints are fixed, redirects rejected, Gateway never retries.
- Loopback HTTP adapter with local bearer authentication and Host/Origin checks; models/chat completions, text/tool calls/provider usage, interrupted-stream errors, SSE backpressure, explicit attempt boundaries, bootstrap/pairing CLI, and distributable bundled CLI.
- Five-screen admin UI, projects and members, limits, client creation/rotation/revoke, credential encryption/revoke/connection test, safe bootstrap download, sessions, stable allowlist approval and key-version/audit display.
- CI, repeatable local key setup, setup skill, migrations, and real-benchmark harness with a one-socket guard.

## Verification

Final clean `npm ci` passed. `npm run check` passed 114 tests: 75 root tests, 17 Identity unit tests, 8 Gateway runtime integration tests and 14 Identity runtime integration tests. It also passed workspace typechecks/builds, all public UI JavaScript syntax checks, and both staging Wrangler bundle dry runs. `npm audit` reported zero vulnerabilities after the proxy dependencies were installed. Worker module sizes: Identity 640,651 bytes; Gateway 502,232 bytes.

The adapter tarball was packed, installed with production dependencies outside the workspace, and its installed `ws-llm-adapter help` command ran successfully. HTTP and TLS WebSocket CONNECT proxy tests passed; auth/pairing requests reject redirects.

Staging deployed:

- Identity/UI: https://ws-llm-identity-staging.rpa-money.workers.dev — deployment `37f9f4d9d10e40c68caf9c1d497037e2`.
- Gateway: `wss://ws-llm-gateway-staging.rpa-money.workers.dev/v1/socket` — deployment `35d7ba9e9e8345c9846cca79adc4939f`.
- D1: `ws-llm-proxy-staging`, migration `0001_identity.sql` recorded in `d1_migrations`; foreign-key check returned no violations. Hourly Identity cleanup cron is configured.

Actual remote smoke used a temporary operator-seeded confidential client, then removed all its database rows and local client-secret file. It verified Identity health 200, public internal route 404, public JWKS with the matching public signer, client-credentials token issuance, authenticated WSS through the inherited environment proxy, negotiated project limits, and tampered-envelope rejection as nonretryable `credential_invalid` with `upstreamStarted:false`. The first smoke exposed a decrypt-error classification bug; the code was fixed, regression-tested, redeployed and the remote smoke passed. No provider was called. Post-cleanup database checks found zero users and zero credentials, with no foreign-key violations.

Deployed binding inspection confirmed Gateway has `IDENTITY` → `ws-llm-identity-staging#IdentityInternal` and an envelope secret, with no D1 or private signer. Identity signing/encryption/OIDC/bootstrap values are secret bindings; its public JWKS is a plain-text public binding. OIDC/bootstrap are intentionally empty until operator configuration. UI root, `dates.js`, and `bootstrap.js` return 200 with the Worker security headers. Focused and runtime suites use mock provider streams; these are functional/security tests, not provider performance measurements. The Gateway integration executes private Identity RPC and D1 on the Cloudflare test runtime, with the provider fetch boundary stubbed in the documented shared test isolate. The test worker has fixture-only signer/DB access; the production Gateway binding configuration must be inspected separately for isolation.

## External release gates and limitations

- No live OIDC application or provider API key was supplied in this session. Operator-seeded staging security smoke does not validate a real OIDC login, Google callback, actual LLM/tool-call behavior, or the OpenCode/browser user flow.
- No real Workers Free benchmark has run. Cloudflare subscription-read access returned authentication error 10000, so Workers Free eligibility is unverified. CPU/memory values must remain unavailable until obtained from platform evidence; adapter wall time is not Worker CPU.
- Dashboard shows actual configuration/client/session/credential counts. Aggregate usage/error telemetry is not implemented; provider usage is returned to the local API client when supplied by the provider. UI does not invent usage or error metrics.
- Provider OAuth is disabled pending official integration eligibility checks. The system is not an OIDC issuer.
- Limits are per socket/project policy, not exact global concurrency enforcement. That requires coordination beyond this MVP.
- No headless or manual browser visual flow has been completed. UI syntax, API helpers, bootstrap parser compatibility and timestamp behavior are tested.
- GitHub template metadata change was rejected with HTTP 403 by the integration; the template flag is not enabled.
- Production has not been deployed. Real staging login/provider/benchmark evidence remains required before production acceptance.

## Custom-domain deployment — 2026-10-18

User confirmed `llm.gemslab.id.vn`, since the connected Cloudflare account has the active `gemslab.id.vn` zone and no `.id.com` zone. Gateway deployed first (`d06bc1cdf29341d9a357481400ff33b4`), then Identity/UI (`61be05973867461fad492999bddfa4d3`), preserving existing secrets, private RPC bindings and staging D1. Identity custom domain and managed certificate were created; the exact `/v1/socket` zone route targets Gateway. The environment still uses the staging resources, not an independently provisioned production database.

Live HTTPS checks with a browser User-Agent: `/ui`, `/ui/`, UI modules/styles, `/api/session`, and public JWKS returned 200; the public internal path returned 404; ordinary HTTP to `/v1/socket` returned 426; a real TLS WebSocket handshake without credentials returned 401. `/api/session` explicitly reports `authSetupRequired:true`. The zone's existing edge policy rejects Python's default User-Agent with Cloudflare 1010; that policy was preserved. Authenticated provider streaming and real OIDC login were not re-tested and remain external gates.

Added a runtime integration test for `/ui`, prefixed modules/styles, root redirect and internal-route denial; all 15 Identity runtime integration tests passed. All 8 Gateway runtime integration tests passed during this change. Workspace typechecking, UI syntax checks and both Worker dry-run bundles passed. An initial test caught the static asset index canonical redirect loop; internal root asset lookup fixed it before deployment. Test OIDC public origin is now explicitly isolated from deployment configuration.

## Temporary OIDC setup password — 2026-10-18

Implemented a separate setup principal for first-run OIDC configuration, with a random 192-bit password, a SHA-256 verifier and a 24-hour expiry held in Worker Secrets. D1 stores hashed setup session/CSRF state, and AES-GCM encrypted OIDC settings with configuration-specific authenticated data. Setup cookies cannot authorize normal application management or machine access. Settings may later be managed by verified OIDC administrators. The exact issuer allowlist defaults to Google; callback is derived from `PUBLIC_ORIGIN`. The first administrator reservation closes bootstrap permanently, and completion revokes setup sessions. See ADR 0002 and Operations for the accepted fail-closed recovery and in-flight callback snapshot limits.

Migration `0002_bootstrap_setup.sql` applied and recorded on staging D1. Identity deployment `b860e84ddaad4f279abca47c6921390c` preserves signer/encryption secrets, custom-domain routing and private RPC exports. Bootstrap verifier/expiry secrets were configured without publishing the password. The private generated password file is ignored and is not part of this repository. Gateway was unchanged by this deployment.

Validation: workspace check passes 125 tests (75 root, 19 Identity unit, 8 Gateway runtime, 23 Identity runtime), typechecking, UI syntax checks, builds and Worker bundle dry runs. Eight setup runtime tests cover missing/expired credentials, hostile Origin, incorrect password, setup-only isolation, CSRF, issuer restrictions, encrypted storage and secret masking, corrupt-row fail-closed behavior, pending-transaction invalidation, closed/missing state and commit-time expiry. Sol review has no remaining setup blocker.

A real Chromium DOM test against a loopback mock API passed setup login, enabled controls after asynchronous requests, canonical Google defaults, settings save, secret input clearing, reload and logout. It found and resolved a disabled-button defect before deployment; the module graph now uses relative imports under `/ui`. `npm run test:ui:browser` reproduces this check with a local Chromium installation.

Live HTTPS smoke on `https://llm.gemslab.id.vn` passed temporary-password login, secure setup cookie attributes, safe settings read, invalid-password/hostile-Origin rejection, normal management API denial, missing-CSRF denial and logout revocation. The smoke did not save a dummy OIDC configuration or create application users. Google/OIDC credentials must still be supplied by the owner; no real OIDC authentication or LLM provider invocation was claimed.

## Google OIDC callback diagnosis — 2026-10-18

A real Google callback failed with the generic verification message. The first signed, offline Google-shaped RS256 test passed the original discovery/token/JWKS/nonce/issuer/audience pipeline, so a general signature-validation defect was not reproduced. Added bounded callback classifications: a fixed stage plus allowlisted OAuth reason and optional claim name, exposed through `X-OIDC-Error` and a safe reference in the failure page. Raw exception text, provider error descriptions, authorization codes, tokens, client secrets and claim values are excluded; browser-state/transaction checks still precede discovery.

Live diagnostic probe used a fresh app transaction and an intentionally invalid synthetic authorization code, never the user's supplied code. The deployed Basic authentication path returned `token_response:invalid_client`. After changing only token endpoint client authentication to advertised `client_secret_post`, the same probe returned `token_response:invalid_grant`, the expected rejection of its synthetic code. The encrypted OIDC settings revision and nonce were unchanged throughout this comparison. This isolates the observed client-authentication incompatibility without reading or changing the stored client secret. The final Identity deployment is `82dc560550e6459fa393df2d0b104ebb`; Gateway, database schema and user configuration were unchanged.

Client authentication now prefers POST only when the provider metadata advertises it, uses Basic for Basic-only or omitted method metadata, and rejects malformed/unsupported method lists. Tests cover signed Google-shaped POST success, Basic-only request behavior, unsupported/malformed metadata, safe diagnostic masking, and invalid browser-state rejection before discovery. Sol review found no remaining blocker. A fresh real-user Google login is still required to verify the complete live flow; a synthetic invalid-code probe is not proof of an authenticated user session. Callback URLs are one-use and must not be replayed after verification fails.

Final verification: `npm run check` passed 130 tests (75 root, 22 Identity unit, 8 Gateway runtime and 25 Identity runtime), workspace typechecks/builds and Worker dry runs. The final bundle also clamps the diagnostic class constructor to the same fixed enum sets.
