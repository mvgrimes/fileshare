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

-- name: ListFileViewHistory :many
SELECT
  c.display_name AS viewer_name,
  sd.last_downloaded_at AS viewed_at,
  sd.download_count
FROM share_downloads sd
JOIN shares s ON s.id = sd.share_id
JOIN clients c ON c.id = sd.client_id
WHERE s.file_id = ?
ORDER BY sd.last_downloaded_at DESC;
