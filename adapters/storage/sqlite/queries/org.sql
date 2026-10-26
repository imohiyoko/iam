-- name: CreateOrg :exec
INSERT INTO orgs (id, public_id, realm_id, kind, name, personal_owner_id, valid_from, valid_until, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOrg :one
SELECT * FROM orgs WHERE realm_id = ? AND id = ?;

-- name: GetOrgByPublicID :one
SELECT * FROM orgs WHERE realm_id = ? AND public_id = ?;

-- name: GetPersonalOrg :one
SELECT * FROM orgs WHERE realm_id = ? AND kind = 'personal' AND personal_owner_id = ?;

-- name: CreateMembership :exec
INSERT INTO memberships (id, public_id, realm_id, user_id, org_id, status, org_role, email_id, valid_from, valid_until, ended_reason,
    created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetMembershipByPublicID :one
SELECT * FROM memberships WHERE realm_id = ? AND public_id = ?;

-- name: GetMembershipByUserOrg :one
SELECT * FROM memberships WHERE realm_id = ? AND user_id = ? AND org_id = ?;

-- name: ListMembershipsByUser :many
SELECT * FROM memberships WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: ListMembershipsByOrg :many
SELECT * FROM memberships WHERE realm_id = ? AND org_id = ? ORDER BY created_at, id;
