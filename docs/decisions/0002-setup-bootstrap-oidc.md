# ADR 0002: Temporary setup authentication and encrypted OIDC settings

- Status: accepted for implementation
- Date: 2026-10-18
- Scope: initial Identity configuration before an allowlisted OIDC administrator can sign in

## Context

The administrative UI needs a way to configure its first external OIDC client before a user can authenticate through OIDC. That setup path must not create an application user, project membership, or ordinary browser session, and it must not remain usable after an administrator has successfully logged in.

## Decisions

- Setup uses a temporary password supplied only as a Worker Secret hash: `BOOTSTRAP_PASSWORD_HASH` is SHA-256 encoded as unpadded base64url, and `BOOTSTRAP_PASSWORD_EXPIRES_AT` is its Unix-seconds expiration. The password is a randomly generated 24-byte URL-safe value with a 24-hour maximum lifetime. Login is a bounded JSON POST, same-origin checked, and rate-limited by source address.
- Successful setup login creates a separate 30-minute session. D1 stores only hashes of its opaque session token and CSRF token. The session cookie is `__Host-setup`, HttpOnly, Secure, and SameSite=Strict; a separate Secure, SameSite=Strict CSRF cookie supports double-submit checks. Setup principals are accepted only by `/api/setup/*`; they cannot use project, client, credential, or user-management routes.
- Setup OIDC settings are stored as AES-256-GCM ciphertext in the `identity_settings` D1 row named `oidc`, keyed by the current `ENVELOPE_KEYS` version. The authenticated data is `identity-oidc-config-v1\n${keyId}`. Reads return provider metadata but never client secrets. An omitted secret on an unchanged provider preserves the encrypted existing secret.
- Issuers must match an exact HTTPS URL in `OIDC_ISSUER_ALLOWLIST`, encoded as a JSON string array. If that optional secret is absent, the only permitted issuer is Google (`https://accounts.google.com`). Configuration rejects loopback, private/reserved IPs, and local hostnames even when an issuer is allowlisted. Callback URIs are always derived from `PUBLIC_ORIGIN` as `/auth/oidc/callback`; clients cannot supply a redirect URI.
- OIDC provider data and bootstrap administrator emails are loaded from encrypted D1 settings for login, callback, and session UI responses once an administrator saves settings. Before the first encrypted settings row exists, the legacy `OIDC_PROVIDERS` and `BOOTSTRAP_ADMIN_EMAILS` bindings remain a compatibility fallback. If an encrypted row exists but cannot be decrypted or validated, reads fail closed and never fall back to environment settings.
- OIDC token endpoint client authentication follows discovery metadata: use `client_secret_post` when advertised, otherwise use `client_secret_basic` when advertised or when the metadata omits the method list (the OAuth default). Fail closed when the advertised methods are malformed or contain no supported method.
- Saving OIDC settings invalidates all outstanding OIDC transactions in the same D1 batch. An omitted client secret is preserved only when provider ID, issuer, and client ID all remain unchanged.
- Failed OIDC callbacks keep a generic sign-in message and may include a stable `X-OIDC-Error` header and matching reference composed only from a fixed processing stage, an allowlisted OAuth error or oauth4webapi error code, and (for claim comparisons) an allowlisted claim name. These categories help operators identify configuration failures without exposing callback URLs, authorization codes, token or provider response bodies, error descriptions, secret values, claim values, or exception text. Identity does not log callback failure details.
- A historical administrator allowlist row permanently closes password setup, even if revoked or missing a completion marker. The first verified bootstrap identity reserves its administrator allowlist row before user/session provisioning; that row also closes setup immediately. If later provisioning fails, setup remains closed and requires operator recovery. On successful administrator login, the same D1 batch that creates the ordinary web session marks setup disabled and revokes all temporary setup sessions. Member logins and denied callbacks do not create this reservation. Once disabled, ordinary OIDC administrators may still manage OIDC settings with their normal session and CSRF token.

## Consequences

Bootstrap access is limited to provider setup and cannot be confused with user or machine authentication. The default deployment supports Google unless an operator explicitly supplies a broader issuer allowlist. Loss of all usable OIDC administrators after bootstrap, or failure after reserving the first admin row but before session provisioning, requires operator recovery through a controlled Worker secret and database operation; the setup password is not a permanent back door.

The temporary password, provider client secret, encryption key, and database contents are deployment-sensitive. Setup endpoints must never log request bodies, password hashes, provider secrets, session tokens, CSRF tokens, or decrypted settings.
