PRAGMA foreign_keys = ON;

CREATE TABLE user_allowlist (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
  approved_at INTEGER NOT NULL,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY (issuer, subject)
);
CREATE INDEX user_allowlist_email_idx ON user_allowlist(email);

CREATE TABLE pending_identities (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL,
  display_name TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, subject)
);

CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL,
  display_name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (issuer, subject)
);
CREATE INDEX users_email_idx ON users(email);

CREATE TABLE projects (
  id TEXT PRIMARY KEY NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX projects_owner_name_idx ON projects(owner_user_id, name);

CREATE TABLE project_members (
  project_id TEXT NOT NULL REFERENCES projects(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE clients (
  id TEXT PRIMARY KEY NOT NULL,
  client_identifier TEXT NOT NULL UNIQUE,
  project_id TEXT NOT NULL REFERENCES projects(id),
  created_by TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('confidential', 'public')),
  secret_hash TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at INTEGER NOT NULL,
  rotated_at INTEGER,
  CHECK ((kind = 'confidential' AND secret_hash IS NOT NULL) OR
         (kind = 'public' AND secret_hash IS NULL))
);
CREATE INDEX clients_project_idx ON clients(project_id, active);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  client_id TEXT REFERENCES clients(id),
  kind TEXT NOT NULL CHECK (kind IN ('web', 'refresh', 'client_credentials')),
  browser_token_hash TEXT UNIQUE,
  refresh_token_hash TEXT UNIQUE,
  csrf_token_hash TEXT,
  device_name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK ((kind = 'web' AND browser_token_hash IS NOT NULL) OR
         (kind != 'web' AND browser_token_hash IS NULL)),
  CHECK ((kind = 'refresh' AND refresh_token_hash IS NOT NULL AND client_id IS NOT NULL) OR
         (kind != 'refresh' AND refresh_token_hash IS NULL)),
  CHECK ((kind = 'web' AND csrf_token_hash IS NOT NULL) OR
         (kind != 'web' AND csrf_token_hash IS NULL))
);
CREATE INDEX sessions_user_idx ON sessions(user_id, revoked_at, expires_at);
CREATE INDEX sessions_client_idx ON sessions(client_id, revoked_at, expires_at);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE providers (
  provider TEXT PRIMARY KEY NOT NULL,
  display_name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
);

CREATE TABLE provider_models (
  provider TEXT NOT NULL REFERENCES providers(provider),
  alias TEXT NOT NULL,
  upstream_model TEXT NOT NULL,
  display_name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (provider, alias)
);

CREATE TABLE project_permissions (
  project_id TEXT NOT NULL REFERENCES projects(id),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, provider, model),
  FOREIGN KEY (provider, model) REFERENCES provider_models(provider, alias)
);

CREATE TABLE project_limits (
  project_id TEXT PRIMARY KEY NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  max_payload_bytes INTEGER NOT NULL DEFAULT 1048576 CHECK (max_payload_bytes BETWEEN 1024 AND 1048576),
  max_concurrency INTEGER NOT NULL DEFAULT 8 CHECK (max_concurrency BETWEEN 1 AND 8),
  max_session_seconds INTEGER NOT NULL DEFAULT 300 CHECK (max_session_seconds BETWEEN 30 AND 300),
  updated_by TEXT REFERENCES users(id),
  updated_at INTEGER NOT NULL
);

CREATE TABLE client_permissions (
  client_id TEXT NOT NULL REFERENCES clients(id),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, provider, model),
  FOREIGN KEY (provider, model) REFERENCES provider_models(provider, alias)
);

CREATE TABLE credentials (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  project_id TEXT NOT NULL REFERENCES projects(id),
  provider TEXT NOT NULL REFERENCES providers(provider),
  key_version TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX credentials_owner_idx ON credentials(user_id, project_id, provider, revoked_at, expires_at);

CREATE TABLE oidc_transactions (
  state_hash TEXT PRIMARY KEY NOT NULL,
  provider_key TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  return_to TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX oidc_transactions_expiry_idx ON oidc_transactions(expires_at);

CREATE TABLE pairing_requests (
  id TEXT PRIMARY KEY NOT NULL,
  device_code_hash TEXT NOT NULL,
  user_code_hash TEXT NOT NULL,
  client_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'delivered', 'expired')),
  user_id TEXT REFERENCES users(id),
  project_id TEXT REFERENCES projects(id),
  client_id TEXT REFERENCES clients(id),
  session_id TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER
);
CREATE INDEX pairing_code_idx ON pairing_requests(user_code_hash, status, expires_at);
CREATE INDEX pairing_device_idx ON pairing_requests(id, device_code_hash, status, expires_at);
CREATE INDEX pairing_expiry_idx ON pairing_requests(expires_at);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY NOT NULL,
  actor_user_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_events_created_idx ON audit_events(created_at DESC);

CREATE TABLE rate_limits (
  rate_key TEXT PRIMARY KEY NOT NULL,
  window_start INTEGER NOT NULL,
  hits INTEGER NOT NULL
);
CREATE INDEX rate_limits_window_idx ON rate_limits(window_start);

INSERT INTO providers(provider, display_name, enabled) VALUES
  ('openai', 'OpenAI', 1),
  ('anthropic', 'Anthropic', 1);
