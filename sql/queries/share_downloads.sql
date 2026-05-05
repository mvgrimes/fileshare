-- name: RecordShareDownload :exec
INSERT INTO share_downloads (id, share_id, client_id)
VALUES (?, ?, ?)
ON CONFLICT(share_id, client_id) DO UPDATE SET
  last_downloaded_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
  download_count = share_downloads.download_count + 1,
  updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now');

-- name: FileHasAnyClientDownload :one
SELECT EXISTS (
  SELECT 1
  FROM shares s
  JOIN share_downloads sd ON sd.share_id = s.id
  WHERE s.file_id = ?
);
