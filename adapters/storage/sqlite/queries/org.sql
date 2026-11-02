-- name: CreateOrg :exec
INSERT INTO orgs (id, public_id, realm_id, kind, name, personal_owner_id, valid_from, valid_until, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOrg :one
SELECT * FROM orgs WHERE realm_id = ? AND id = ?;

-- name: GetOrgByPublicID :one
SELECT * FROM orgs WHERE realm_id = ? AND public_id = ?;

-- name: GetPersonalOrg :one
SELECT * FROM orgs WHERE realm_id = ? AND kind = 'personal' AND personal_owner_id = ?;

-- name: SetOrgValidity :execrows
UPDATE orgs SET valid_from = ?, valid_until = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: SetOrgDeletion :execrows
UPDATE orgs SET deletion_scheduled_at = ?, deleted_at = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: SetOrgSettings :execrows
UPDATE orgs SET settings = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: GetMembership :one
SELECT * FROM memberships WHERE realm_id = ? AND id = ?;

-- name: CreateMembership :exec
INSERT INTO memberships (id, public_id, realm_id, user_id, org_id, status, org_role, email_id, valid_from, valid_until, ended_reason,
    management_requested_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetMembershipByPublicID :one
SELECT * FROM memberships WHERE realm_id = ? AND public_id = ?;

-- name: GetMembershipByUserOrg :one
SELECT * FROM memberships WHERE realm_id = ? AND user_id = ? AND org_id = ?;

-- name: ListMembershipsByUser :many
SELECT * FROM memberships WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: ListMembershipsByOrg :many
SELECT * FROM memberships WHERE realm_id = ? AND org_id = ? AND public_id > sqlc.arg(after) ORDER BY public_id LIMIT sqlc.arg(lim);

-- name: CountActiveMemberships :one
SELECT count(*) FROM memberships WHERE realm_id = ? AND org_id = ? AND status = 'active' AND org_role = ?;

-- name: UpdateMembership :execrows
UPDATE memberships SET status = ?, org_role = ?, email_id = ?, valid_from = ?, valid_until = ?, ended_reason = ?,
    management_requested_at = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: CreateInvitation :exec
INSERT INTO invitations (id, public_id, realm_id, org_id, email_index, email_ciphertext, index_key_id, org_role, token_hash,
    valid_from, valid_until, invited_by, expires_at, status, created_at, closed_at, closed_by, managed)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetInvitation :one
SELECT * FROM invitations WHERE realm_id = ? AND id = ?;

-- name: GetInvitationByPublicID :one
SELECT * FROM invitations WHERE realm_id = ? AND public_id = ?;

-- name: ListInvitationsByOrg :many
SELECT * FROM invitations WHERE realm_id = ? AND org_id = ? ORDER BY created_at, id;

-- name: CloseInvitation :execrows
UPDATE invitations SET status = ?, closed_at = ?, closed_by = ? WHERE realm_id = ? AND id = ? AND status = 'pending';

-- name: CreateQuotaGrant :exec
INSERT INTO org_quota_grants (id, public_id, realm_id, org_id, quota_key, kind, quantity, starts_at, ends_at, source, external_ref,
    created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetQuotaGrantByPublicID :one
SELECT * FROM org_quota_grants WHERE realm_id = ? AND public_id = ?;

-- name: GetQuotaGrantByExternalRef :one
SELECT * FROM org_quota_grants WHERE realm_id = ? AND org_id = ? AND quota_key = ? AND external_ref = ? AND external_ref <> '';

-- name: ListQuotaGrantsByOrg :many
SELECT * FROM org_quota_grants WHERE realm_id = ? AND org_id = ? AND quota_key = ? ORDER BY created_at, id;

-- name: UpdateQuotaGrant :execrows
UPDATE org_quota_grants SET kind = ?, quantity = ?, starts_at = ?, ends_at = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: DeleteQuotaGrant :execrows
DELETE FROM org_quota_grants WHERE realm_id = ? AND id = ?;

-- name: ListOrgs :many
SELECT * FROM orgs WHERE realm_id = ? AND id > sqlc.arg(after) ORDER BY id LIMIT sqlc.arg(lim);

-- name: CountQuotaGrants :one
SELECT count(*) FROM org_quota_grants;

-- name: PurgeQuotaGrants :execrows
DELETE FROM org_quota_grants WHERE id IN (SELECT g.id FROM org_quota_grants g LIMIT sqlc.arg(lim));

-- name: CreateOrgDomain :exec
INSERT INTO org_domains (id, public_id, realm_id, org_id, domain, token, verified_at, checked_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOrgDomainByPublicID :one
SELECT * FROM org_domains WHERE realm_id = ? AND public_id = ?;

-- name: GetVerifiedOrgDomain :one
SELECT * FROM org_domains WHERE realm_id = ? AND domain = ? AND verified_at IS NOT NULL;

-- name: ListOrgDomainsByOrg :many
SELECT * FROM org_domains WHERE realm_id = ? AND org_id = ? ORDER BY created_at, id;

-- name: ListOrgDomainsToRecheck :many
SELECT * FROM org_domains WHERE verified_at IS NOT NULL AND (checked_at IS NULL OR checked_at <= sqlc.arg(before))
ORDER BY checked_at IS NOT NULL, checked_at, id LIMIT sqlc.arg(lim);

-- name: UpdateOrgDomain :execrows
UPDATE org_domains SET verified_at = ?, checked_at = ?, missing_since = ? WHERE realm_id = ? AND id = ?;

-- name: DeleteOrgDomain :execrows
DELETE FROM org_domains WHERE realm_id = ? AND id = ?;

-- name: CountOrgDomains :one
SELECT count(*) FROM org_domains;

-- name: PurgeOrgDomains :execrows
DELETE FROM org_domains WHERE id IN (SELECT d.id FROM org_domains d LIMIT sqlc.arg(lim));

-- name: SetOrgParent :execrows
UPDATE orgs SET parent_org_id = ?, updated_at = ? WHERE realm_id = ? AND id = ?;

-- name: ListOrgChildren :many
SELECT * FROM orgs WHERE realm_id = ? AND parent_org_id = ? ORDER BY id;

-- name: ListOrgAncestors :many
SELECT ancestor_id, depth FROM org_ancestors WHERE realm_id = ? AND org_id = ? ORDER BY depth;

-- name: ListOrgDescendants :many
SELECT org_id, depth FROM org_ancestors WHERE realm_id = ? AND ancestor_id = ? ORDER BY depth, org_id;

-- name: DeleteOrgAncestorsAbove :exec
DELETE FROM org_ancestors WHERE realm_id = ? AND org_id = ? AND depth > ?;

-- name: InsertOrgAncestor :exec
INSERT INTO org_ancestors (realm_id, org_id, ancestor_id, depth) VALUES (?, ?, ?, ?);

-- name: MoveOrgRoles :exec
UPDATE authz_roles SET org_id = sqlc.arg(to_org_id) WHERE realm_id = sqlc.arg(realm_id) AND org_id = sqlc.arg(from_org_id);

-- name: MoveOrgGroups :exec
UPDATE authz_groups SET org_id = sqlc.arg(to_org_id) WHERE realm_id = sqlc.arg(realm_id) AND org_id = sqlc.arg(from_org_id);

-- name: MoveOrgServiceAccounts :exec
UPDATE authn_service_accounts SET org_id = sqlc.arg(to_org_id) WHERE realm_id = sqlc.arg(realm_id) AND org_id = sqlc.arg(from_org_id);

-- name: MoveOrgQuotaGrants :exec
UPDATE org_quota_grants SET org_id = sqlc.arg(to_org_id) WHERE realm_id = sqlc.arg(realm_id) AND org_id = sqlc.arg(from_org_id);

-- name: MoveOrgPasskeyPreferences :exec
UPDATE authn_passkeys SET preferred_org_id = sqlc.arg(to_org_id) WHERE realm_id = sqlc.arg(realm_id) AND preferred_org_id = sqlc.arg(from_org_id);
