-- name: CreateEmailEvent :exec
INSERT INTO email_events (id, event_type, recipient_email, provider_message_id, status, error_text, payload_json)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListEmailEventsByStatus :many
SELECT id, event_type, recipient_email, provider_message_id, status, error_text, payload_json, created_at
FROM email_events
WHERE status = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: UpdateEmailEventStatus :exec
UPDATE email_events
SET status = ?,
    error_text = ?
WHERE id = ?;
