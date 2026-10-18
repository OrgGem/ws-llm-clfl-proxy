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
