-- name: CreateFile :exec
INSERT INTO files (id, uploader_type, uploader_id, original_filename, storage_key, content_type, size_bytes, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetFileByID :one
SELECT id, uploader_type, uploader_id, original_filename, storage_key, content_type, size_bytes, expires_at, created_at
FROM files
WHERE id = ?;

-- name: ListFilesByUploader :many
SELECT id, uploader_type, uploader_id, original_filename, storage_key, content_type, size_bytes, expires_at, created_at
FROM files
WHERE uploader_type = ? AND uploader_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: DeleteFile :exec
DELETE FROM files
WHERE id = ?;
