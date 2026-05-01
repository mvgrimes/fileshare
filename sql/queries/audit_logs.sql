-- name: CreateAuditLog :exec
INSERT INTO audit_logs (id, actor_type, actor_id, event_type, entity_type, entity_id, metadata_json)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditLogsByActor :many
SELECT id, actor_type, actor_id, event_type, entity_type, entity_id, metadata_json, created_at
FROM audit_logs
WHERE actor_type = ? AND actor_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAuditLogsByEventType :many
SELECT id, actor_type, actor_id, event_type, entity_type, entity_id, metadata_json, created_at
FROM audit_logs
WHERE event_type = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;
