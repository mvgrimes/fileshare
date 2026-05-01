-- name: ListRoles :many
SELECT id, name
FROM roles
ORDER BY id ASC;

-- name: AddUserRole :exec
INSERT INTO user_roles (user_id, role_id)
VALUES (?, ?);

-- name: RemoveUserRole :exec
DELETE FROM user_roles
WHERE user_id = ? AND role_id = ?;

-- name: ListUserRoles :many
SELECT ur.user_id, ur.role_id, ur.created_at
FROM user_roles ur
WHERE ur.user_id = ?
ORDER BY ur.created_at DESC;

-- name: CreateUserGroup :exec
INSERT INTO user_groups (id, name, created_by_user_id)
VALUES (?, ?, ?);

-- name: GetUserGroupByID :one
SELECT id, name, created_by_user_id, created_at
FROM user_groups
WHERE id = ?;

-- name: ListUserGroups :many
SELECT id, name, created_by_user_id, created_at
FROM user_groups
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: UpdateUserGroup :exec
UPDATE user_groups
SET name = ?
WHERE id = ?;

-- name: DeleteUserGroup :exec
DELETE FROM user_groups
WHERE id = ?;

-- name: AddUserToGroup :exec
INSERT INTO user_group_members (user_group_id, user_id)
VALUES (?, ?);

-- name: RemoveUserFromGroup :exec
DELETE FROM user_group_members
WHERE user_group_id = ? AND user_id = ?;

-- name: ListGroupUsers :many
SELECT u.id, u.email, u.full_name, u.is_active, u.created_at, u.updated_at
FROM users u
JOIN user_group_members ugm ON ugm.user_id = u.id
WHERE ugm.user_group_id = ?
ORDER BY u.created_at DESC;

-- name: CreateClientUploadPermission :exec
INSERT INTO client_upload_permissions (id, owner_type, owner_id, target_type, target_id)
VALUES (?, ?, ?, ?, ?);

-- name: ListClientUploadPermissionsByOwner :many
SELECT id, owner_type, owner_id, target_type, target_id, created_at
FROM client_upload_permissions
WHERE owner_type = ? AND owner_id = ?
ORDER BY created_at DESC;

-- name: DeleteClientUploadPermission :exec
DELETE FROM client_upload_permissions
WHERE id = ?;

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
