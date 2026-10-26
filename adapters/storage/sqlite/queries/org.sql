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
SELECT * FROM memberships WHERE realm_id = ? AND org_id = ? AND public_id > sqlc.arg(after) ORDER BY public_id LIMIT sqlc.arg(lim);

-- name: UpdateMembership :execrows
UPDATE memberships SET status = ?, org_role = ?, email_id = ?, valid_from = ?, valid_until = ?, ended_reason = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: CreateInvitation :exec
INSERT INTO invitations (id, public_id, realm_id, org_id, email_index, email_ciphertext, index_key_id, org_role, token_hash,
    valid_from, valid_until, invited_by, expires_at, status, created_at, closed_at, closed_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetInvitation :one
SELECT * FROM invitations WHERE realm_id = ? AND id = ?;

-- name: GetInvitationByPublicID :one
SELECT * FROM invitations WHERE realm_id = ? AND public_id = ?;

-- name: ListInvitationsByOrg :many
SELECT * FROM invitations WHERE realm_id = ? AND org_id = ? ORDER BY created_at, id;

-- name: CloseInvitation :execrows
UPDATE invitations SET status = ?, closed_at = ?, closed_by = ? WHERE realm_id = ? AND id = ? AND status = 'pending';
