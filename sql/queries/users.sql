-- name: CreateUser :exec
INSERT INTO users (id, email, full_name, password_hash, is_active)
VALUES (?, ?, ?, ?, ?);

-- name: GetUserByID :one
SELECT id, email, full_name, password_hash, is_active, created_at, updated_at
FROM users
WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, email, full_name, password_hash, is_active, created_at, updated_at
FROM users
WHERE LOWER(email) = LOWER(?);

-- name: ListUsers :many
SELECT id, email, full_name, password_hash, is_active, created_at, updated_at
FROM users
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: UpdateUser :exec
UPDATE users
SET full_name = ?,
    password_hash = ?,
    is_active = ?,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = ?;
