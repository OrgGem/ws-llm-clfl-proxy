CREATE TABLE bootstrap_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  disabled_at INTEGER
);
INSERT OR IGNORE INTO bootstrap_state(singleton, disabled_at) VALUES (1, NULL);

CREATE TABLE setup_sessions (
  id TEXT PRIMARY KEY NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX setup_sessions_expiry_idx ON setup_sessions(expires_at);
CREATE INDEX setup_sessions_token_idx ON setup_sessions(token_hash, revoked_at, expires_at);

CREATE TABLE identity_settings (
  name TEXT PRIMARY KEY NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
