-- name: CreateClientGroup :exec
INSERT INTO client_groups (id, name, created_by_user_id)
VALUES (?, ?, ?);

-- name: GetClientGroupByID :one
SELECT id, name, created_by_user_id, created_at
FROM client_groups
WHERE id = ?;

-- name: ListClientGroups :many
SELECT id, name, created_by_user_id, created_at
FROM client_groups
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: UpdateClientGroup :exec
UPDATE client_groups
SET name = ?
WHERE id = ?;

-- name: DeleteClientGroup :exec
DELETE FROM client_groups
WHERE id = ?;

-- name: AddClientToGroup :exec
INSERT INTO client_group_members (client_group_id, client_id)
VALUES (?, ?);

-- name: RemoveClientFromGroup :exec
DELETE FROM client_group_members
WHERE client_group_id = ? AND client_id = ?;

-- name: ListGroupClients :many
SELECT c.id, c.email, c.display_name, c.password_hash, c.can_upload, c.is_active, c.created_at, c.updated_at
FROM clients c
JOIN client_group_members cgm ON cgm.client_id = c.id
WHERE cgm.client_group_id = ?
ORDER BY c.created_at DESC;
