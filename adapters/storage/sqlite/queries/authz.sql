-- name: CreateRoleBinding :exec
INSERT INTO authz_role_bindings (id, public_id, realm_id, role, principal_type, principal_id, org_id, resource_type, resource_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetRoleBindingByPublicID :one
SELECT * FROM authz_role_bindings WHERE realm_id = ? AND public_id = ?;

-- name: DeleteRoleBinding :execrows
DELETE FROM authz_role_bindings WHERE realm_id = ? AND id = ?;

-- name: ListRoleBindingsByPrincipal :many
SELECT * FROM authz_role_bindings WHERE realm_id = ? AND principal_type = ? AND principal_id = ? ORDER BY created_at, id;

-- name: ListRoleBindingsByRole :many
SELECT * FROM authz_role_bindings WHERE realm_id = ? AND role = ? ORDER BY created_at, id;

-- name: ListRoleBindingsByOrg :many
SELECT * FROM authz_role_bindings WHERE realm_id = ? AND org_id = ? ORDER BY created_at, id;

-- name: CreateRole :exec
INSERT INTO authz_roles (id, public_id, realm_id, org_id, name, permissions, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetRole :one
SELECT * FROM authz_roles WHERE realm_id = ? AND id = ?;

-- name: GetRoleByPublicID :one
SELECT * FROM authz_roles WHERE realm_id = ? AND public_id = ?;

-- name: ListRolesByOrg :many
SELECT * FROM authz_roles WHERE realm_id = ? AND org_id = ? ORDER BY name;

-- name: UpdateRole :execrows
UPDATE authz_roles SET name = ?, permissions = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: DeleteRole :execrows
DELETE FROM authz_roles WHERE realm_id = ? AND id = ?;

-- name: CreateGroup :exec
INSERT INTO authz_groups (id, public_id, realm_id, org_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetGroup :one
SELECT * FROM authz_groups WHERE realm_id = ? AND id = ?;

-- name: GetGroupByPublicID :one
SELECT * FROM authz_groups WHERE realm_id = ? AND public_id = ?;

-- name: ListGroupsByOrg :many
SELECT * FROM authz_groups WHERE realm_id = ? AND org_id = ? ORDER BY name;

-- name: RenameGroup :execrows
UPDATE authz_groups SET name = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: DeleteGroup :execrows
DELETE FROM authz_groups WHERE realm_id = ? AND id = ?;

-- name: DeleteGroupMembers :exec
DELETE FROM authz_group_members WHERE group_id = ?;

-- name: AddGroupMember :exec
INSERT INTO authz_group_members (group_id, member_type, member_id, created_at) VALUES (?, ?, ?, ?);

-- name: RemoveGroupMember :execrows
DELETE FROM authz_group_members WHERE group_id = ? AND member_type = ? AND member_id = ?;

-- name: ListGroupMembers :many
SELECT * FROM authz_group_members WHERE group_id = ? ORDER BY created_at, member_type, member_id;

-- name: ListGroupsByMember :many
SELECT g.* FROM authz_groups g JOIN authz_group_members m ON m.group_id = g.id
WHERE g.realm_id = ? AND m.member_type = ? AND m.member_id = ? ORDER BY m.created_at, g.id;
