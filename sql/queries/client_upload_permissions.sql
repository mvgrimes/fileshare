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
