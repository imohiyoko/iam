-- name: CreateCredential :exec
INSERT INTO authn_credentials (id, public_id, realm_id, user_id, method, lookup, lookup_key_id, data, data_version, created_at, last_used_at, revoked_at, revoke_reason,
    preferred_org_id, reserve_lookup)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetCredential :one
SELECT * FROM authn_credentials WHERE realm_id = ? AND id = ?;

-- name: GetCredentialByPublicID :one
SELECT * FROM authn_credentials WHERE realm_id = ? AND public_id = ?;

-- name: GetCredentialByLookup :one
SELECT * FROM authn_credentials WHERE realm_id = ? AND method = ? AND lookup = ? AND revoked_at IS NULL;

-- name: ListCredentialLookupKeys :many
SELECT DISTINCT lookup_key_id FROM authn_credentials
WHERE realm_id = ? AND method = ? AND lookup IS NOT NULL AND revoked_at IS NULL ORDER BY lookup_key_id;

-- name: ListCredentialsByUser :many
SELECT * FROM authn_credentials WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: ListCredentialsByUserMethod :many
SELECT * FROM authn_credentials WHERE realm_id = ? AND user_id = ? AND method = ? ORDER BY created_at, id;

-- name: UpdateCredentialData :execrows
UPDATE authn_credentials SET data = sqlc.arg(data), data_version = sqlc.arg(data_version)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id) AND data = sqlc.arg(old) AND revoked_at IS NULL;

-- name: UseCredential :execrows
UPDATE authn_credentials SET last_used_at = ? WHERE realm_id = ? AND id = ?;

-- name: RevokeCredential :exec
UPDATE authn_credentials SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: SetCredentialPreferredOrg :execrows
UPDATE authn_credentials SET preferred_org_id = ? WHERE realm_id = ? AND id = ?;

-- name: RetireCredentialLookup :exec
INSERT INTO authn_retired_credential_lookups (realm_id, method, lookup, lookup_key_id, retired_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (realm_id, method, lookup) DO NOTHING;

-- name: CountRetiredCredentialLookup :one
SELECT count(*) FROM authn_retired_credential_lookups WHERE realm_id = ? AND method = ? AND lookup = ?;

-- name: ListRetiredCredentialLookupKeys :many
SELECT DISTINCT lookup_key_id FROM authn_retired_credential_lookups WHERE realm_id = ? AND method = ? ORDER BY lookup_key_id;

-- name: MoveCredentials :execrows
UPDATE authn_credentials SET user_id = sqlc.arg(to_user_id) WHERE realm_id = sqlc.arg(realm_id) AND user_id = sqlc.arg(from_user_id);

-- name: CountCredentials :one
SELECT count(*) FROM authn_credentials WHERE method = ?;

-- name: PurgeCredentials :execrows
DELETE FROM authn_credentials WHERE id IN (SELECT c.id FROM authn_credentials c WHERE c.method = sqlc.arg(method) LIMIT sqlc.arg(lim));

-- name: EraseUserCredentials :exec
DELETE FROM authn_credentials WHERE realm_id = ? AND user_id = ?;
