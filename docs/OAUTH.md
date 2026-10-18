# Provider OAuth

This guide covers ChatGPT plan OAuth for the local adapter. It is separate from the OIDC sign-in used to access the Identity admin UI and from the machine token the adapter uses to reach Gateway.

## Availability

| Connector | Local OAuth | Inference through this cloud Gateway | State |
| --- | --- | --- | --- |
| ChatGPT | Supported by the connector design; interactive, live OAuth has not been verified for this deployment. | Disabled by default. | `GET /api/oauth/connectors` reports `eligibility_pending` until an operator has verified hosted inference eligibility. |
| Claude subscription | Disabled. | Disabled. | `subscription_oauth_unavailable`; use a separately configured Claude Console/API credential. |

The default Identity configuration keeps `CHATGPT_OAUTH_REMOTE_ELIGIBILITY` set to `pending`. OpenAI's current Sign in with ChatGPT plan-usage docs cover open-source and locally hosted apps and direct paid or remotely hosted apps to an interest form. A successful local OAuth login does not establish eligibility for this Cloudflare-hosted inference proxy. Keep the remote connector disabled until that question is verified with OpenAI and the operator records the evidence. The Identity setting is an explicit operator attestation; changing it to `verified` is not an eligibility check.

No real ChatGPT OAuth session or live OAuth-backed inference has been completed for this deployment. Automated contract tests are not vendor approval or live-provider verification.

## How the credentials move

Three credentials have different jobs:

1. The user signs in to Identity with the configured system OIDC provider. That session authorizes a project and the browser-to-adapter pairing.
2. ChatGPT OAuth authorizes eligible OpenAI plan usage. Its refresh token stays on the adapter host. The adapter refreshes it locally and keeps access tokens in process memory.
3. The adapter's short-lived machine token authorizes its requests to Identity and Gateway. It does not grant ChatGPT plan access.

When remote inference is enabled, the adapter sends the current short-lived ChatGPT access token and its expiry to Identity over HTTPS. Identity checks the machine principal, project/client/model grants, caps credential lifetime to the token expiry and one hour, and returns an AES-GCM credential envelope. The browser never receives the access or refresh token. Gateway receives the envelope in the authenticated WebSocket request, checks its ownership, grant and expiry, and decrypts it only to make the provider request. Gateway does not refresh the ChatGPT token. After a local refresh, the adapter must obtain a new envelope.

The envelope is not a grant by itself. Identity still checks the active user, client, project, credential revocation, and model permissions for each request. A model appearing in OpenAI's catalog does not create an Identity provider model, project permission, or client grant.

## Browser pairing and local OAuth

Use a browser signed in to the Identity UI and select the project that should own the local adapter. The UI checks connector availability and creates a short-lived pairing grant bound to that signed-in user and project. Identity stores only a hash of the random grant; it expires after two minutes, can be redeemed once, and redemption requires the adapter's authenticated machine principal to match the same user and project. The local adapter prints a separate eight-digit approval code to its own terminal; enter that code only in the Identity page that started pairing. The code expires after two minutes and allows at most five attempts. Do not copy either code into chat, issue trackers, URLs, or logs.

The local adapter must be running on the same machine as the browser used for OAuth. It listens for the authorization callback on an ephemeral `127.0.0.1` port at `/auth/callback`. The OAuth authorization uses OpenAI's dynamic registration for open-source clients, PKCE, state, nonce, and the `api.openai.com/v1` resource. The adapter validates the returned identity and scopes, saves the issued client ID for that profile, and reuses a stable host ID on later sign-ins. Do not reuse an OpenCode or Codex client ID.

The OAuth browser path is not an ambient route from the cloud UI into arbitrary local services. The local bridge accepts only the configured Identity origin and loopback Host, and uses the explicit, expiring pairing grant. Its health and pairing routes do not use the adapter's normal API bearer token; after pairing, the browser receives a random, short-lived local control token for status/model operations. Keep that token in browser memory and do not send it to Identity. If the browser reports that the adapter is unreachable, first confirm the adapter is running and that this browser can reach the adapter's loopback address on the same host. Do not weaken the adapter's Host, Origin, or control-token checks.

The local bridge routes are:

| Route | Use |
| --- | --- |
| `GET /local/oauth/health` | Identity-origin browser checks whether the local OAuth bridge is reachable and configured. |
| `POST /local/oauth/pair/start` | Identity UI sends the two-minute pairing token; the adapter prints its local approval code and returns a pairing ID. |
| `POST /local/oauth/pair/approve` | Identity UI sends the pairing ID and local approval code; the adapter redeems the grant and starts OAuth. The response includes the authorization URL and a temporary local control token. |
| `GET /local/oauth/status` | Polls login status with `Authorization: Bearer <local-control-token>`. A successful profile is bound to the paired project. |
| `GET /local/oauth/models` | Discovers models for that profile with the same local control token. |
| `POST /local/oauth/model` | Explicitly maps a local alias to the paired profile after confirmation; does not create cloud model grants. |
| `POST /local/oauth/disconnect` | Disconnects the local profile with the same local control token. This does not revoke an Identity credential already issued for the project. |

The browser control token is held in page memory only and expires after ten minutes. Reloading the Identity page loses that token; approving a new pairing starts a new ChatGPT OAuth login. The adapter's local profiles and model-alias bindings persist in its protected OAuth profile file. After a page reload, use `oauth status` or `oauth logout chatgpt --profile PROFILE_ID` to inspect or disconnect a saved profile from the adapter host. To manage it through the UI again, start a new pairing and complete a new login; if that login creates a different profile ID, map the alias to that profile again. There is no persistent cloud session for managing saved local OAuth profiles.

The adapter CLI supports local sign-in and model discovery:

```sh
ws-llm-adapter oauth status
ws-llm-adapter oauth login chatgpt [--profile PROFILE_ID] [--print-url]
ws-llm-adapter oauth models chatgpt --profile PROFILE_ID [--cached]
ws-llm-adapter oauth model add --id MODEL_ALIAS --profile PROFILE_ID
ws-llm-adapter oauth model remove --id MODEL_ALIAS
ws-llm-adapter oauth logout chatgpt --profile PROFILE_ID
```

`oauth login` opens the system browser where possible. Use `--print-url` when the CLI cannot open one; it prints only the short-lived authorization URL and leaves the exact `127.0.0.1` callback listener running in that CLI process. There is no manual code-paste flow. The browser must be able to reach the adapter host's loopback address, so a browser on another machine cannot complete this login unless it runs in an environment that shares that loopback host. `oauth models` fetches fresh metadata; `--cached` explicitly labels saved results as potentially stale. `oauth model add` and `remove` only map or remove a local alias. `oauth login claude` reports that subscription OAuth is unavailable.

CLI login does not redeem the Identity browser-pairing grant and does not bind the profile to a project. A locally signed-in, discovered, and aliased profile therefore cannot by itself obtain an Identity envelope or use WebSocket inference. To make an OAuth profile usable by this proxy, pair and approve it through the authenticated Identity UI while the local adapter bridge is running. The CLI URL option is a local sign-in fallback, not a way for a remote browser to bypass that same-host loopback requirement.

## Model discovery and inference limits

ChatGPT model discovery uses the selected profile's access token against the fixed OpenAI models endpoint. It is a catalog for the signed-in account, not an authorization grant. Any returned modality or capability fields describe provider metadata; they do not promise that this adapter implements those inputs or outputs. This integration makes no audio or video handling promise; rely only on formats explicitly documented and supported by the adapter. The current local bridge returns an error if fresh discovery fails rather than presenting its saved metadata as current. An administrator must still configure the provider/model and allow it for the project and client. The adapter must not infer entitlement from a model's presence or invent unavailable capability metadata.

ChatGPT subscription credentials are allowed only for native OpenAI Responses requests through the built-in OpenAI provider route. Use the adapter's `/v1/responses` endpoint. The Gateway sends the request to OpenAI's native `/v1/responses` endpoint and requires stateless generation (`store: false`, streaming enabled); prior context must be supplied in the request. The integration does not promise stored conversations, server-side context retention, or automatic context compaction. Chat Completions, legacy Completions, custom OpenAI-compatible endpoints, Anthropic routes, and automatic format conversion are not supported for this OAuth credential. There is no fallback to an API-key path or another endpoint.

This follows OpenAI's documented ChatGPT plan-usage contract: `POST https://api.openai.com/v1/responses`, bearer access token, `store: false`, and `stream: true`. Do not substitute ChatGPT's legacy `backend-api` routes.

## Identity connector endpoints

These routes are called by the UI and local adapter; they are not a way to import tokens from a browser or arbitrary client:

| Route | Caller and purpose |
| --- | --- |
| `GET /api/oauth/connectors` | Signed-in browser session; returns local OAuth capability and remote-inference eligibility for each connector. |
| `POST /api/oauth/pairing` | Signed-in browser session with CSRF protection; body is `{ "projectId": "…", "connectorId": "chatgpt" }`; creates a two-minute one-use bridge grant. |
| `POST /api/oauth/pairing/redeem` | Adapter with machine Bearer token; body is `{ "pairingToken": "…" }`; consumes the grant only when machine user/project match. |
| `POST /api/oauth/token-envelope` | Adapter with machine Bearer token; body is `{ "connectorId": "chatgpt", "model": "…", "accessToken": "…", "expiresAt": 0 }`; only available when remote eligibility is verified and the active client/project has the model grant. Returns an encrypted envelope and its short expiry. |

The browser pairing request uses the current Identity CSRF token and same-origin checks. The token-envelope route rejects extra fields, including refresh tokens. Do not call it from browser JavaScript.

## Logout and revocation

The adapter owns refresh-token rotation and local profile storage. Local logout or deletion clears local OAuth state and attempts to revoke the provider refresh token; it cannot by itself revoke an Identity credential row or invalidate an envelope already issued to the adapter. The current browser bridge reports local disconnect only, not whether OpenAI accepted the revocation request. An issued envelope may remain usable until its short expiry unless an administrator revokes that credential in Identity. Use the Providers screen's credential-revoke action for immediate Gateway-side denial. Provider-side OAuth revocation and Identity credential revocation are separate events; report provider revocation as confirmed only when the adapter explicitly confirms success.

Do not send tokens in URLs or logs, include them in bootstrap downloads, or paste them into support requests. Keep the adapter's private OAuth profile file protected with owner-only permissions. If the local machine is lost or its profile file is exposed, revoke the Identity credential in the admin UI and remove the ChatGPT app authorization in ChatGPT settings.

## Claude subscription OAuth

The `claude` connector remains disabled with the fixed reason `subscription_oauth_unavailable`. Anthropic describes Claude paid plans and Claude Console as separate products: the Console provides API keys and API access, and API usage is billed separately; some Max and Team plans may include API credits, but that does not establish a third-party subscription OAuth flow for this Gateway. Use a Claude Console/API credential where eligible. Do not imitate Claude Code's first-party sign-in or embed a first-party client identity.

Sources: [Anthropic: why Claude API usage is billed separately](https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-is-claude-api-usage-billed-separately-from-my-paid-claude-plan) and [how to access the Claude API](https://support.claude.com/en/articles/8114521-how-can-i-access-the-claude-api).

## Operator verification gate

Before enabling ChatGPT remote inference, verify the currently applicable OpenAI SIWC eligibility for this hosted proxy with OpenAI. Record the written outcome and date with the deployment evidence. Then set `CHATGPT_OAUTH_REMOTE_ELIGIBILITY=verified` only in the intended Identity environment and deploy that configuration. Confirm `GET /api/oauth/connectors` reports remote inference enabled. Do not change the flag just to make a request pass.

The live acceptance check must use a real user's interactive browser and an eligible account; it is separate from mocked OAuth tests. Verify a new dynamic client registration, callback/state/nonce/PKCE and granted scopes, local refresh and rotation, model discovery, a project/client model grant, envelope expiry and revocation, and one successful native Responses stream ending in its provider success event. Confirm tokens do not appear in browser responses, logs, URLs, exports, or diagnostics. Do not report the feature live until this check and the remote eligibility gate both pass.

## References

- [ADR 0005 — Client-owned provider OAuth](decisions/0005-client-oauth-connectors.md)
- [ChatGPT OAuth source review: OpenCode](research/chatgpt-oauth-opencode.md)
- [OpenAI Sign in with ChatGPT plan-usage overview](https://developers.openai.com/siwc/token-sharing-open-source)
- [OpenAI sign-in and registration flow](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [OpenAI account sessions and token refresh](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
- [OpenAI token reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference)
- [OpenAI model discovery and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- [OpenAI self-hosted VM guidance](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms)
