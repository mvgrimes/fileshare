-- name: CreateSession :exec
INSERT INTO sessions (id, actor_type, actor_id, token_hash, ip_address, user_agent, expires_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSessionByTokenHash :one
SELECT id, actor_type, actor_id, token_hash, ip_address, user_agent, expires_at, created_at, revoked_at
FROM sessions
WHERE token_hash = ?;

-- name: ListSessionsByActor :many
SELECT id, actor_type, actor_id, token_hash, ip_address, user_agent, expires_at, created_at, revoked_at
FROM sessions
WHERE actor_type = ? AND actor_id = ?
ORDER BY created_at DESC;

-- name: RevokeSessionByID :exec
UPDATE sessions
SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions
WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
