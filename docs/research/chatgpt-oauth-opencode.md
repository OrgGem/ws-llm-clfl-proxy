# ChatGPT OAuth reference: OpenCode

Investigated 2026-10-18. This is source-backed research, not an implemented connector or a live OAuth test.

## Primary sources

OpenCode snapshot: `60a5a6ca7ce176b04cd2321ffd1819b1ea8e6006`.

- [Current ChatGPT token-sharing plugin](https://github.com/anomalyco/opencode/blob/60a5a6ca7ce176b04cd2321ffd1819b1ea8e6006/packages/core/src/plugin/provider/chatgpt.ts)
- [Legacy Codex OAuth plugin](https://github.com/anomalyco/opencode/blob/60a5a6ca7ce176b04cd2321ffd1819b1ea8e6006/packages/core/src/plugin/provider/openai.ts)
- [Official ChatGPT plan usage overview](https://developers.openai.com/siwc/token-sharing-open-source)

## What the source actually does

The new ChatGPT plugin registers a user-owned OAuth client using `dynamic_agent_client` on first sign-in and persists the returned client ID for later sign-ins. It persists an opaque host identifier separately, binds its HTTP callback to 127.0.0.1 on an ephemeral port, and generates fresh state, nonce and S256 PKCE. Authorization uses `/api/accounts/authorize`; code exchange and refresh use `/api/accounts/oauth/token`, with resource `https://api.openai.com/v1`. Scopes include `openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`. Code exchange uses the issued client ID and verifier, not a shared embedded client secret. These are observations from the ChatGPT plugin, not a proposal to reuse OpenCode's identity.

Before accepting credentials, the plugin checks the returned token-sharing scope and validates the ID token. Local credentials include access token, refresh token, expiry and client/scopes metadata; refresh returns updated credentials. Models can be fetched with the bearer token and filtered to visible models supported in the API. Provider requests use the API resource URL, session-affinity headers and a Responses-capable provider. Native response compaction is explicitly unsupported in this plugin. The official overview independently confirms eligible Responses API use with store:false and stream:true, not arbitrary subscription-backed Chat Completions.

The separate legacy OpenAI plugin uses a fixed client ID, browser/headless methods, the Codex backend URL `https://chatgpt.com/backend-api/codex`, and chatgpt-account-id. This older route must not be conflated with the current token-sharing Responses integration, nor should its client ID be adopted as this project's registered identity.

## Mapping to this repository

The user's requested split is compatible with the OAuth responsibilities shown in the source: the adapter owns browser login, callback/state/nonce/PKCE, ID-token and scope validation, credential storage, expiry checks, single-flight refresh and rotation. Refresh tokens stay local. The cloud side would receive only short-lived provider access-token envelopes, separately authorized by this system's Gateway token. A provider-specific connector must use eligible Responses operations and actual model entitlements; existing Chat/Responses implementations are not evidence that one can substitute OAuth tokens into any provider endpoint.

Use this project's own agent identity, persist host/client IDs across restarts, and do not reuse OpenCode/Codex client registrations or spoof their User-Agent. A new short-lived OAuth envelope needs provider credential type and expiry handling rather than the existing long-lived API-key TTL. Gateway would keep an explicit endpoint allowlist, avoid provider refresh, and preserve token expiry, revocation, ownership and stream terminal checks. These are design implications; they are not implemented yet.

## Remaining deployment distinction

The official overview explicitly covers open-source and locally hosted apps, including self-hosted VM hosts, and directs paid or remotely hosted apps to an interest form. Therefore the existence of OpenCode's local integration establishes the OAuth mechanism and available Responses path, but does not independently establish the documented status of a shared Cloudflare-hosted token-decrypting inference proxy. Client-side login alone does not eliminate that distinction. This is a targeted integration question about the remote inference hop, not a claim that third-party ChatGPT OAuth is unavailable.

No login was attempted, no user OAuth tokens were collected, and no deployment or live provider configuration was changed during this research.

## Claude subscription connector check

Checked 2026-10-18 against Anthropic's official Help Center. Anthropic describes Claude paid plans and the Claude Console as separate products: paid subscriptions provide Claude on web/desktop/mobile, while the Console provides API keys and API access; API usage is billed separately. The article notes that Max and Team plans may include monthly API credits, which does not itself define an OAuth token-sharing flow or authorize a third-party subscription connector.

- [Why Claude API usage is billed separately from paid Claude plans](https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-is-claude-api-usage-billed-separately-from-my-paid-claude-plan)
- [How to access the Claude API](https://support.claude.com/en/articles/8114521-how-can-i-access-the-claude-api)

The checked official material explains Console API access and billing; it does not establish a public third-party OAuth flow for using a consumer Claude subscription through this proxy. This is a limit on what was verified, not a claim that every form of Claude Code subscription sign-in is unavailable. Per ADR 0005, keep the Claude subscription OAuth connector disabled with `subscription_oauth_unavailable` until an authorized third-party integration is verified. Continue to support separately configured Console/API credentials.
