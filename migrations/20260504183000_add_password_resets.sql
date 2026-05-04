-- +goose Up
CREATE TABLE password_resets (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'client')),
  actor_id TEXT NOT NULL,
  email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_password_resets_actor ON password_resets(actor_type, actor_id);
CREATE INDEX idx_password_resets_email ON password_resets(email);
CREATE INDEX idx_password_resets_expires_at ON password_resets(expires_at);

-- +goose Down
DROP TABLE IF EXISTS password_resets;
