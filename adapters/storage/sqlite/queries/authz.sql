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

-- name: ListEffectiveRoleBindings :many
SELECT b.id, b.public_id, b.realm_id, b.role, b.principal_type, b.principal_id, b.org_id, b.resource_type, b.resource_id, b.created_at,
       COALESCE(g.org_id, '') AS group_org_id, r.public_id AS custom_public_id, r.org_id AS custom_org_id, r.name AS custom_name,
       r.permissions AS custom_permissions, r.created_at AS custom_created_at, r.updated_at AS custom_updated_at
FROM authz_role_bindings b
LEFT JOIN authz_groups g ON b.principal_type = 'group' AND g.id = b.principal_id
LEFT JOIN authz_roles r ON r.realm_id = b.realm_id AND r.id = b.role
WHERE b.realm_id = @realm_id AND b.id IN (
    SELECT d.id FROM authz_role_bindings d WHERE d.realm_id = @realm_id AND d.principal_type = @principal_type AND d.principal_id = @principal_id
    UNION ALL
    SELECT x.id FROM authz_group_members m JOIN authz_role_bindings x ON x.realm_id = @realm_id AND x.principal_type = 'group' AND x.principal_id = m.group_id
    WHERE m.member_type = @principal_type AND m.member_id = @principal_id)
ORDER BY b.created_at, b.id;

-- name: ListEffectiveRoleBindingsNested :many
SELECT b.id, b.public_id, b.realm_id, b.role, b.principal_type, b.principal_id, b.org_id, b.resource_type, b.resource_id, b.created_at,
       COALESCE(g.org_id, '') AS group_org_id, r.public_id AS custom_public_id, r.org_id AS custom_org_id, r.name AS custom_name,
       r.permissions AS custom_permissions, r.created_at AS custom_created_at, r.updated_at AS custom_updated_at
FROM authz_role_bindings b
LEFT JOIN authz_groups g ON b.principal_type = 'group' AND g.id = b.principal_id
LEFT JOIN authz_roles r ON r.realm_id = b.realm_id AND r.id = b.role
WHERE b.realm_id = @realm_id AND b.id IN (
    SELECT d.id FROM authz_role_bindings d WHERE d.realm_id = @realm_id AND d.principal_type = @principal_type AND d.principal_id = @principal_id
    UNION ALL
    SELECT x.id FROM authz_group_members m JOIN authz_role_bindings x ON x.realm_id = @realm_id AND x.principal_type = 'group' AND x.principal_id = m.group_id
    WHERE m.member_type = @principal_type AND m.member_id = @principal_id
    UNION ALL
    SELECT y.id FROM authz_group_members n JOIN authz_group_closure c ON c.realm_id = @realm_id AND c.group_id = n.group_id
    JOIN authz_role_bindings y ON y.realm_id = @realm_id AND y.principal_type = 'group' AND y.principal_id = c.ancestor_id
    WHERE n.member_type = @principal_type AND n.member_id = @principal_id)
ORDER BY b.created_at, b.id;

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

-- name: DeleteGroupMemberships :exec
DELETE FROM authz_group_members WHERE member_type = 'group' AND member_id = ?;

-- name: ListGroupAncestors :many
SELECT ancestor_id, depth FROM authz_group_closure WHERE realm_id = ? AND group_id = ? ORDER BY depth, ancestor_id;

-- name: ListGroupDescendants :many
SELECT group_id, depth FROM authz_group_closure WHERE realm_id = ? AND ancestor_id = ? ORDER BY depth, group_id;

-- name: DeleteGroupAncestors :exec
DELETE FROM authz_group_closure WHERE realm_id = ? AND group_id = ?;

-- name: DeleteGroupClosure :exec
DELETE FROM authz_group_closure WHERE realm_id = @realm_id AND (group_id = @group_id OR ancestor_id = @group_id);

-- name: InsertGroupAncestor :exec
INSERT INTO authz_group_closure (realm_id, group_id, ancestor_id, depth) VALUES (?, ?, ?, ?);

-- name: CountNestedGroupMembers :one
SELECT count(*) FROM authz_group_members WHERE member_type = 'group';

-- name: CountGroupClosure :one
SELECT count(*) FROM authz_group_closure;

-- name: PurgeGroupClosure :execrows
DELETE FROM authz_group_closure WHERE (realm_id, group_id, ancestor_id) IN (
    SELECT c.realm_id, c.group_id, c.ancestor_id FROM authz_group_closure c LIMIT sqlc.arg(lim));

-- name: PurgeNestedGroupMembers :execrows
DELETE FROM authz_group_members WHERE member_type = 'group' AND (group_id, member_id) IN (
    SELECT m.group_id, m.member_id FROM authz_group_members m WHERE m.member_type = 'group' LIMIT sqlc.arg(lim));

-- name: ListRiskTypes :many
SELECT * FROM authz_risk_types WHERE realm_id = ? ORDER BY name;

-- name: PutRiskType :exec
INSERT INTO authz_risk_types (realm_id, name, enabled, band_medium, band_high, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (realm_id, name) DO UPDATE SET enabled = excluded.enabled, band_medium = excluded.band_medium, band_high = excluded.band_high,
    updated_at = excluded.updated_at;
