-- Credential IDs are never reused: once a passkey is removed, its ID cannot be
-- registered again (by anyone), so a removed passkey that still exists on an
-- authenticator can never sign in to someone else's account.
CREATE TABLE retired_credentials (
  id          TEXT PRIMARY KEY,
  retired_at  INTEGER NOT NULL
);
