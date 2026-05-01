-- name: CreateClient :exec
INSERT INTO clients (id, email, display_name, password_hash, can_upload, is_active)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetClientByID :one
SELECT id, email, display_name, password_hash, can_upload, is_active, created_at, updated_at
FROM clients
WHERE id = ?;

-- name: GetClientByEmail :one
SELECT id, email, display_name, password_hash, can_upload, is_active, created_at, updated_at
FROM clients
WHERE email = ?;

-- name: ListClients :many
SELECT id, email, display_name, password_hash, can_upload, is_active, created_at, updated_at
FROM clients
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: UpdateClient :exec
UPDATE clients
SET display_name = ?,
    can_upload = ?,
    is_active = ?,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: DeleteClient :exec
DELETE FROM clients
WHERE id = ?;
