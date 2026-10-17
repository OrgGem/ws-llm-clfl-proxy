# Agent instructions

## Scope
Build two Cloudflare Workers (Identity & Config; LLM Socket Gateway), D1, a static admin UI served by Identity, and a local adapter packaged with the client. API keys are the MVP; provider OAuth is conditional future work.

## Before changing behavior
Read [docs/PLAN.md](docs/PLAN.md) for architecture, implementation order, acceptance criteria, and unresolved contracts. For auth, credential, WebSocket, or provider changes, resolve the relevant Phase 1 decisions there and record rationale in `docs/decisions/` before implementation. Keep unverified choices explicitly pending.

## Hard boundaries
- Preserve the distinction between user OIDC login and OAuth machine authentication. Confidential clients use client credentials; public clients use PKCE or pairing without a shared embedded secret. Use maintained protocol libraries.
- Enforce user/project ownership and provider/model permissions for each request, including credential revocation checks. An envelope alone never grants access.
- Keep encryption keys in Worker Secrets. Use AES-GCM with fresh nonces and authenticated ownership/version/expiry metadata. Raw provider keys exist only transiently in processing memory.
- Exclude raw credentials, access/refresh tokens, prompts, and responses from logs, URLs, exports, and default database records. Treat envelopes as sensitive.
- Route upstream calls only through configured provider/endpoint allowlists. Gateway never retries LLM calls. Client retries must remain distinguishable from interrupted streams.
- Bound payloads, buffers, concurrency, and session lifetime. Cancel upstream on disconnect, cancellation, or slow-client overflow according to the agreed contract.
- Bind the adapter to loopback, including in ChatGPT Cloud. It is not a third cloud service.
- Keep provider OAuth disabled until eligibility and hosted-proxy support are verified with current official sources.

## Delivery
Implement in the plan's phase order. Validate changed behavior with focused tests; security and stream behavior require negative-path coverage. Report actual commands and outcomes, and label unrun checks. Keep benchmark measurements separate from assumptions; ten requests per socket is an experiment, not a capacity promise. Deploy staging and verify before production. Use repeatable setup and migrations; keep secrets and generated local state outside Git.

## Current state
Documentation bootstrap only. No application, package manager, test runner, Cloudflare resources, or deployment exists yet. Select tooling during Phase 1; document real commands when available instead of inventing them.
