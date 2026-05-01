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
