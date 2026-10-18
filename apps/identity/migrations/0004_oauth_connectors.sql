ALTER TABLE credentials
  ADD COLUMN credential_kind TEXT NOT NULL DEFAULT 'api_key'
  CHECK (credential_kind IN ('api_key', 'oauth_access_token'));

CREATE INDEX credentials_kind_expiry_idx
  ON credentials(credential_kind, provider, revoked_at, expires_at);

CREATE TABLE oauth_bridge_grants (
  token_hash TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  browser_session_id TEXT NOT NULL REFERENCES sessions(id),
  connector_id TEXT NOT NULL CHECK (connector_id = 'chatgpt'),
  provider TEXT NOT NULL REFERENCES providers(provider),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  redeemed_at INTEGER
);
CREATE INDEX oauth_bridge_grants_expiry_idx ON oauth_bridge_grants(expires_at);
CREATE INDEX oauth_bridge_grants_owner_idx ON oauth_bridge_grants(user_id, project_id, expires_at);
