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
