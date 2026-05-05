-- +goose Up
PRAGMA foreign_keys = ON;

CREATE TABLE share_downloads (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  first_downloaded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_downloaded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  download_count INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (share_id, client_id),
  FOREIGN KEY (share_id) REFERENCES shares(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE INDEX idx_share_downloads_client_last_downloaded
  ON share_downloads(client_id, last_downloaded_at);

-- +goose Down
DROP INDEX IF EXISTS idx_share_downloads_client_last_downloaded;
DROP TABLE IF EXISTS share_downloads;
