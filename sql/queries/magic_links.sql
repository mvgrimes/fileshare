-- name: CreateMagicLink :exec
INSERT INTO magic_links (id, client_id, token_hash, expires_at, consumed_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetMagicLinkByTokenHash :one
SELECT id, client_id, token_hash, expires_at, consumed_at, created_at
FROM magic_links
WHERE token_hash = ?;

-- name: ListMagicLinksByClient :many
SELECT id, client_id, token_hash, expires_at, consumed_at, created_at
FROM magic_links
WHERE client_id = ?
ORDER BY created_at DESC;

-- name: ConsumeMagicLink :exec
UPDATE magic_links
SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?;

-- name: DeleteExpiredMagicLinks :exec
DELETE FROM magic_links
WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now');
