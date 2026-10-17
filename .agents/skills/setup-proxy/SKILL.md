---
name: setup-proxy
description: Set up this repository's local adapter and two Cloudflare Workers, configure OIDC and credential enrollment, or diagnose deployment configuration. Use when installing, configuring, deploying staging, or rotating system keys.
---

# Setup the LLM proxy

1. Read root `AGENTS.md`, `docs/OPERATIONS.md`, and the relevant `docs/decisions/` entry. Inspect current package scripts and Wrangler configs for actual commands and binding names. Identify local, staging, or production before changing resources.
2. Run `npm ci` and `node scripts/setup-local.mjs` for local development. Completion: generated state and `.dev.vars` are ignored, owner-only, and consistent; existing files are preserved. Keep local key material separate from deployed secrets.
3. Configure one external OIDC application with the exact Identity callback URI. Keep client secrets in Worker Secrets or ignored local config. Completion: provider configuration validates; an allowlisted `(issuer, subject)` can sign in, an unapproved principal is denied, and the active bootstrap invitation is pinned to a stable principal. Never invent OAuth client IDs or claim live login passed without a callback test.
4. Run `npm run check`. Inspect all failures and resolve them before deployment. Completion: typecheck, tests, application builds, and Worker dry runs pass; record exact commands and any unavailable checks.
5. For staging, inspect the actual connected Cloudflare account and resource names, reuse the dedicated D1 database, apply migrations, and configure separate signing/encryption secrets and public JWKS. Deploy Identity first and Gateway with its private Identity entrypoint binding. Completion: public internal paths are inaccessible, authenticated authorization works over the service binding, and no local issuer or placeholder key/config is deployed as operational configuration.
6. Register the client for its security boundary: confidential runtime uses client credentials; distributed clients use authenticated browser pairing without a shared embedded secret. Enroll a provider API key through the authenticated UI; store its envelope in the adapter's owner-only local configuration. Completion: loopback OpenAI-compatible API returns valid stream/tool calls and denial cases pass. Keep retries as new attempts, never splice interrupted streams.
7. Measure the 1/5/10-request benchmark only with real staging/provider access and verified Workers Free eligibility. Completion: evidence records model/configuration/commit/date, results and observation limits, or clearly identifies missing prerequisites. A mock stream is not a provider benchmark. Production remains gated on staging checks and review.

Use `docs/PROTOCOL.md` for wire behavior and `docs/THREAT-MODEL.md` for security checks. When access is unavailable, retain a concrete local result and report the missing capability; never output secret values or invent a successful deployment.
