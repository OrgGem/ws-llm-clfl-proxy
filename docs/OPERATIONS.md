# Operations and release gates

## Environment separation

Deploy staging before production. Use separate D1 databases, Worker names, OIDC redirect URIs, signing/encryption key material, and client registrations for each environment. Do not point a staging Gateway at production Identity or database bindings.

Cloudflare account discovered during initial implementation: `2e48918c469167b902558a1af0901c44`. Discovery is read-only and does not establish the account's Workers plan, deployment success, or benchmark eligibility. The account has workers.dev subdomain `rpa-money`. The subscription-read API returned authentication error 10000, so Workers Free eligibility remains unverified. Confirm the account and Workers Free plan before recording a Free benchmark.

## Local key setup

Run `node scripts/setup-local.mjs`. It generates an ES256 key pair and AES-256 key into ignored `.local/setup.json` with owner-only file permissions, then creates owner-only `apps/identity/.dev.vars` and `apps/gateway/.dev.vars`. Re-running preserves existing files and key material. It never prints secret values and does not contact Cloudflare. Existing `.dev.vars` files remain authoritative: if they predate the setup state, reconcile them privately rather than assuming they match.

The generated local issuer is `http://localhost:8787`. Configure a local OIDC application, its exact callback URL and bootstrap admin before login. A fresh setup has an empty OIDC provider array and bootstrap allowlist, so authentication remains unavailable until configured. Local key material is for development only; staging and production require separate keys.

## Run the local Workers

After installing and generating local keys, apply the local D1 migration:

```sh
npx wrangler d1 migrations apply DB --local --config apps/identity/wrangler.jsonc
```

Run Identity and Gateway in separate terminals so the local service-binding registry can connect them:

```sh
npx wrangler dev --config apps/identity/wrangler.jsonc --port 8787
npx wrangler dev --config apps/gateway/wrangler.jsonc --port 8788
```

Configure `OIDC_PROVIDERS` as a JSON array of objects with `id`, `label`, `issuer`, `clientId`, `clientSecret`, and `redirectUri` (exact `/auth/oidc/callback` URL). For Google use its official configured issuer; register the exact callback in the provider console first. Configure `BOOTSTRAP_ADMIN_EMAILS` for the initial trusted administrator. The verified first bootstrap identity is pinned to `(issuer, subject)`; later users require explicit approval. A system OIDC login is separate from provider API-key enrollment. Project `member` is a read-only management role; owner/admin can manage project settings and approve a client session. Client secret rotation and client model-grant updates remain creator-only so a project administrator cannot mint another user’s principal.

For adapter installation, pairing, bootstrap import, envelope import, and the real benchmark, read [the adapter guide](../apps/adapter/README.md). In managed cloud clients, preserve inherited `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, and CA trust settings. The adapter selects an environment proxy for Identity HTTP and Gateway WSS using maintained proxy libraries; it continues to bind its local API only to loopback.

## Secret handling

Enter operational secrets through `wrangler secret put` or a supported secret manager. Do not paste provider keys, private signing keys, refresh tokens, credential envelopes, or OIDC client secrets into issues, chat, committed configuration, or command-line arguments. For local development, use ignored `.dev.vars` or local configuration files with owner-only permissions. Public bootstrap exports may include service URLs, public client IDs, model aliases, and policy limits; keep credential envelopes in a separate sensitive local store.

Encryption key rotation requires keeping old key versions available until their envelopes expire or are reissued and any encrypted OIDC settings are re-saved under the current key. Revoke a compromised credential ID centrally and rotate the provider key if it may have escaped. Signing key rotation publishes old verification keys until issued tokens expire. Never reuse secret material between production and staging.

## Staging deployment commands

The checked-in staging D1 identifier belongs to the discovered account above. When cloning this project into another account, create a dedicated database and replace that binding identifier before migrating. Keep all environment bindings separate.

Configure `MACHINE_JWT_PUBLIC_JWKS` to the public keys corresponding to the staging signer, and keep the issuer/origin/Gateway URLs consistent across both Workers. Set the Identity secrets `MACHINE_JWT_PRIVATE_JWK`, `ENVELOPE_KEYS`, `OIDC_PROVIDERS`, and `BOOTSTRAP_ADMIN_EMAILS`, plus the same `ENVELOPE_KEYS` on Gateway, using `wrangler secret put NAME --env staging --config <worker-config>` (interactive input). Never use the local generator's signing/encryption keys on staging.

With authorized Wrangler authentication for the selected account:

```sh
npx wrangler d1 migrations apply DB --remote --env staging --config apps/identity/wrangler.jsonc
npx wrangler deploy --env staging --config apps/identity/wrangler.jsonc
npx wrangler deploy --env staging --config apps/gateway/wrangler.jsonc
```

Identity exports the private `IdentityInternal` RPC entrypoint. The Gateway staging service binding must target `ws-llm-identity-staging` with that entrypoint. Gateway has no D1 binding. A deployed `/health` response is a code health check, not proof of an end-to-end OIDC/provider flow. Provider OAuth remains disabled.

## Deployment gates

Before staging: install from the committed lockfile; run typechecking, focused security/stream tests, the full suite, and both Worker bundle dry runs. Apply migrations against staging only. Configure exact HTTPS origins and OIDC callback URLs. Verify that public Worker HTTP routes cannot invoke internal Identity authorization methods.

Before production: Sol review findings must be resolved or explicitly recorded as limitations; verify OIDC callback/allowlist, client issuance/rotation/revocation, cross-user and cross-project denial, envelope tampering/revocation, token expiry, cancellation/disconnect, slow clients, upstream errors, and stream/tool-call compatibility with an actual client on staging. Record actual commands and outcomes in the release evidence. Do not describe unavailable end-to-end checks as passing.

## Benchmark evidence

The benchmark uses real Workers and a real provider API key entered through authenticated credential enrollment. Run independent trials with 1, 5, and 10 concurrent requests on one socket, with fixed model and input, recording date, commit, environment, configuration, sample counts, successful/failed requests, time to first data and total elapsed time. Keep prompts/responses and credentials out of benchmark output.

Confirm Workers Free for the measured environment. Record CPU using platform telemetry only where accessible; do not equate wall time with CPU time. Worker memory cannot be inferred from a Node adapter's RSS; record unavailable memory measurements as unavailable. Record per-trial failures and any observer limitations. The protocol currently caps one socket at eight active requests. A synchronized ten-request trial therefore measures at most eight accepted requests and two `overloaded` outcomes (unless earlier requests complete before later starts); it is not a ten-success throughput claim. Force one Gateway session using `WS_PROXY_ADAPTER_MAX_GATEWAY_SESSIONS=1` on the adapter process, as required by the benchmark script. Ten concurrent requests are a measured experiment, not a capacity guarantee. Two Workers share the account quota.

## External configuration required

Live OIDC requires an externally registered OAuth/OIDC application and callback URL. Real LLM calls require an authorized provider API key. These values are not supplied by the repository. OAuth with an LLM subscription remains disabled until official hosted-proxy eligibility is verified independently; system login does not grant provider subscription access.

## Local adapter behind an environment proxy

The local adapter honors standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables for Identity HTTP requests and Gateway WebSocket connections. It supports HTTP and HTTPS proxies; for proxy selection, `wss://` Gateway URLs use the HTTPS rules and `ws://` URLs use the HTTP rules. Loopback targets stay direct. Keep proxy credentials in the environment and do not print proxy URLs. The adapter uses Node's normal TLS verification and trust settings; do not disable certificate checks to work around proxy configuration.

## GitHub template setting

The repository can be pushed through the current integration. Updating repository metadata to `is_template=true` returned HTTP 403 (`Resource not accessible by integration`) during bootstrap implementation. The GitHub account owner can enable **Settings → General → Template repository**, or provide an integration permission that allows repository administration. Until that setting is verified, use the repository by clone/fork; do not describe its GitHub template flag as enabled.

## Custom domain (2026-10-18)

The user confirmed `llm.gemslab.id.vn` (the connected zone), replacing the initially requested `.id.com` spelling. The existing staging Workers and D1 remain the deployment environment; this domain mapping is not a completed production acceptance.

- Identity custom domain: `llm.gemslab.id.vn` → `ws-llm-identity-staging`.
- UI: `https://llm.gemslab.id.vn/ui`; `/ui/` also works. `/` redirects to `/ui`. UI modules/styles are served under `/ui/`; authentication and management API paths remain at `/auth`, `/oauth`, `/pairing`, `/api` and `/.well-known/jwks.json`.
- Exact zone route `llm.gemslab.id.vn/v1/socket` → `ws-llm-gateway-staging` overrides the Identity custom-domain origin. Socket URL: `wss://llm.gemslab.id.vn/v1/socket`.
- Both Workers use `https://llm.gemslab.id.vn` as issuer; Identity uses that public origin and exports the custom-domain Gateway URL. Previously issued tokens using the workers.dev issuer must be replaced. Existing signing/encryption secrets and database are preserved.
- Register `https://llm.gemslab.id.vn/auth/oidc/callback` in the external OIDC application and set its exact `redirectUri` before enabling login. OIDC remains unconfigured; the UI reports setup required.

Cloudflare manages the custom-domain DNS and TLS certificate. Gateway route and Identity custom domain are recorded in the staging Wrangler environment for repeatable deployments. Deploy Gateway before Identity when applying this mapping. Never overwrite other zone routes.

## First-run password and OIDC settings

A fresh installation can enable a temporary **setup-only** password. It does not create a local administrator, a user principal, a machine token, or access to client/provider data. Use the initial setup option on `/ui` to configure the external OIDC application and the initial administrator email. The callback is `https://llm.gemslab.id.vn/auth/oidc/callback` on the current deployment. Register it as an exact authorized redirect URI in Google Cloud Console before trying sign-in.

Run `node scripts/create-bootstrap-password.mjs` from the repository root. It creates a random 192-bit password in ignored owner-only `.local/bootstrap/password.txt` and a separate owner-only `.local/bootstrap/secrets.json` containing its SHA-256 verifier and a 24-hour expiry. It refuses to overwrite existing files. Upload `BOOTSTRAP_PASSWORD_HASH` and `BOOTSTRAP_PASSWORD_EXPIRES_AT` from that private secrets file into Identity Worker Secrets; never commit either file. There is no shared, hardcoded default password. SHA-256 is used only for this machine-generated high-entropy credential, not for user-chosen passwords.

Setup cookies are opaque, hashed server-side, HttpOnly, Secure and SameSite=Strict, with a lifetime of at most 30 minutes. Login is rate-limited and requires the configured same origin; writes require a separate CSRF token. Setup can configure OIDC only. Google (`https://accounts.google.com`) is allowed by default. An operator may expand exact trusted issuers through the `OIDC_ISSUER_ALLOWLIST` JSON array; never allow arbitrary request-supplied issuers. UI settings are encrypted in D1 with a fresh AES-GCM nonce, versioned Worker encryption key and configuration-specific authenticated context. GET settings report only that a client secret exists, never its value. OIDC settings may also be edited by a signed-in OIDC administrator with CSRF protection.

Saving settings keeps setup access available so a mistaken client ID or secret can be corrected. Saving invalidates unconsumed OIDC transactions; a callback already consumed and exchanging its code can finish using its earlier configuration snapshot. Complete or abandon active sign-in attempts before changing bootstrap configuration. The first successful verified and approved OIDC administrator login permanently closes password bootstrap and revokes setup sessions. Existing administrator history also prevents password bootstrap from being enabled later. The first verified administrator reservation is durable before browser-session provisioning; if subsequent provisioning fails, setup fails closed and an operator must repair the OIDC account/session state. It does not automatically reopen password access. Once signed in through OIDC, delete the local password files and remove the bootstrap secrets from the Worker. If the temporary password expires before setup, an account operator must generate and install a new temporary verifier; application users cannot reset it publicly.

For the setup UI browser regression, run `npm run test:ui:browser` with Chromium installed (`CHROMIUM_BIN` may select another executable). It exercises the real DOM against a loopback-only mock API; it does not prove a real OIDC login.
