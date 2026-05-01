-- +goose Up
PRAGMA foreign_keys = ON;

CREATE UNIQUE INDEX idx_shares_file_target_unique
  ON shares(file_id, target_type, target_id);

CREATE INDEX idx_shares_target_created_at
  ON shares(target_type, target_id, created_at);

CREATE INDEX idx_magic_links_active_lookup
  ON magic_links(client_id, consumed_at, expires_at);

CREATE INDEX idx_sessions_active_actor
  ON sessions(actor_type, actor_id, revoked_at, expires_at);

CREATE INDEX idx_email_events_recipient_created_at
  ON email_events(recipient_email, created_at);

-- +goose Down
DROP INDEX IF EXISTS idx_email_events_recipient_created_at;
DROP INDEX IF EXISTS idx_sessions_active_actor;
DROP INDEX IF EXISTS idx_magic_links_active_lookup;
DROP INDEX IF EXISTS idx_shares_target_created_at;
DROP INDEX IF EXISTS idx_shares_file_target_unique;
