-- nodescale control-plane schema.
--
-- Nothing in this database grants access to a server or to a provider API:
--   * provider API tokens live only inside `vaults.blob`, encrypted in the
--     browser with keys derived from the user's passkey (WebAuthn PRF) or
--     recovery key, which never reach the server;
--   * server agents trust passkey public keys stored on the servers
--     themselves, not anything in this database.

CREATE TABLE users (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE credentials (
  id            TEXT PRIMARY KEY,               -- base64url WebAuthn credential ID
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key    TEXT NOT NULL,                  -- base64url SPKI
  alg           INTEGER NOT NULL,               -- COSE algorithm
  label         TEXT NOT NULL,
  transports    TEXT,
  prf           INTEGER NOT NULL DEFAULT 0,
  sign_count    INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);
CREATE INDEX credentials_user ON credentials(user_id);

CREATE TABLE challenges (
  id          TEXT PRIMARY KEY,
  challenge   TEXT NOT NULL,
  purpose     TEXT NOT NULL,
  user_id     TEXT,
  data        TEXT,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE sessions (
  id             TEXT PRIMARY KEY,              -- SHA-256 of the cookie token
  user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id  TEXT,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  user_agent     TEXT,
  ip             TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE vaults (
  user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  version     INTEGER NOT NULL,
  blob        TEXT NOT NULL,                    -- opaque ciphertext envelope
  updated_at  INTEGER NOT NULL
);

CREATE TABLE workspaces (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE memberships (
  workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role          TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX memberships_user ON memberships(user_id);

CREATE TABLE invites (
  id            TEXT PRIMARY KEY,               -- SHA-256 of the invite code
  workspace_id  TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  role          TEXT NOT NULL CHECK (role IN ('admin', 'member')),
  created_by    TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  used_by       TEXT,
  used_at       INTEGER
);

CREATE TABLE servers (
  id                   TEXT PRIMARY KEY,
  workspace_id         TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name                 TEXT NOT NULL,
  provider             TEXT,
  notes                TEXT,
  tailnet_ip           TEXT,
  tailnet_name         TEXT,
  tailscale_device_id  TEXT,
  agent_id             TEXT,
  agent_public_key     TEXT,
  status               TEXT NOT NULL DEFAULT 'pending',
  last_seen_at         INTEGER,
  created_by           TEXT,
  created_at           INTEGER NOT NULL,
  UNIQUE (workspace_id, name)
);

CREATE TABLE audit_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id  TEXT NOT NULL,
  user_id       TEXT,
  server_id     TEXT,
  action        TEXT NOT NULL,
  request_hash  TEXT,
  ok            INTEGER NOT NULL,
  detail        TEXT,
  ip            TEXT,
  created_at    INTEGER NOT NULL
);
CREATE INDEX audit_workspace_time ON audit_events(workspace_id, created_at DESC);
