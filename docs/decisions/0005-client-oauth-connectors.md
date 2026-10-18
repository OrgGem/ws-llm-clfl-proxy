# ADR 0005 — Client-owned provider OAuth

2026-10-18. Accepted scope: the owner chose cloud UI controlling a local adapter; refresh tokens remain local. OAuth provider eligibility remains connector-specific per PLAN.

ChatGPT uses official SIWC dynamic client registration, loopback callback, PKCE/state/nonce and validated issuer/audience/nonce/scopes. Persist issued client ID and stable host ID per local profile. Client owns refresh/rotation with single-flight and atomic protected storage. Do not reuse OpenCode/Codex client IDs. Provider OAuth login is separate from our machine/browser login.

Cloud UI must not gain arbitrary loopback access: use an explicit local pairing handshake, exact configured Identity origin and short-lived random single-use pairing authorization; no wildcard CORS, no ambient unauthenticated login/logout/token import. Never return refresh/access tokens to the browser UI, logs or URLs. A browser without a reachable adapter reports that fact.

Short-lived OAuth access tokens may be submitted through an authenticated HTTPS endpoint to Identity for encryption. Bind envelope to authenticated user/project/provider and cap expiry at declared provider expiry plus system maximum; expired tokens fail. Gateway still checks our auth, ownership, revocation and envelope expiry. Never accept upstream URLs from an OAuth login/model request. Cloud cannot refresh provider tokens. Client renews envelope after refresh. OAuth scope/ID validation belongs in client; Identity does not claim opaque token validation beyond configured connector policy.

Model discovery is provider-specific, authenticated, bounded, redacted and restricted to allowlisted model URLs. Return normalized model IDs and available capabilities/context/reasoning metadata when supplied; never invent entitlements. Discovery does not grant model permissions: effective availability intersects project/client grants. Existing /v1/models remains OpenAI-compatible.

ChatGPT token-sharing inference uses eligible native Responses with store:false/stream:true and the api.openai.com/v1 resource. Do not substitute legacy Codex backend endpoints. Remotely hosted inference eligibility is pending; expose status explicitly and keep actual proxy inference disabled until connector eligibility is configured/verified. Local OAuth/discovery may be developed/tested independently. Claude subscription OAuth is unavailable until an authorized third-party integration is verified; expose a disabled connector with a reason and retain API-key support. Do not fake OAuth or use a first-party application's client identity.

Tests must cover local pairing/origin/replay, state/nonce/PKCE/token validation, single-flight rotation, expiry/revoke/cross-user envelope checks, discovery bounds/redaction, and disabled unsupported connectors. Real OAuth completion requires the user's interactive browser and is a separate verification gate.
