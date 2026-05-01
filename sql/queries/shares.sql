-- name: CreateShare :exec
INSERT INTO shares (id, file_id, shared_by_type, shared_by_id, target_type, target_id, message)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetShareByID :one
SELECT id, file_id, shared_by_type, shared_by_id, target_type, target_id, message, created_at
FROM shares
WHERE id = ?;

-- name: ListSharesByTarget :many
SELECT id, file_id, shared_by_type, shared_by_id, target_type, target_id, message, created_at
FROM shares
WHERE target_type = ? AND target_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: DeleteShare :exec
DELETE FROM shares
WHERE id = ?;
