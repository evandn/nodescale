-- Stack definitions (compose YAML). Secrets are never stored here: compose
-- files reference them as ${NAME}; values live in each user's encrypted vault
-- and are sealed to the target server in the browser at deploy time.
CREATE TABLE stacks (
  server_id     TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  workspace_id  TEXT NOT NULL,
  name          TEXT NOT NULL,
  compose       TEXT NOT NULL,
  updated_by    TEXT,
  updated_at    INTEGER NOT NULL,
  deployed_at   INTEGER,
  PRIMARY KEY (server_id, name)
);

-- The Cloudflare Tunnel a server's cloudflared runs, for routing hostnames.
ALTER TABLE servers ADD COLUMN tunnel_id TEXT;
