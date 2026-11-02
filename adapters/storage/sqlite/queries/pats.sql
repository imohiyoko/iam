-- name: CreatePAT :exec
INSERT INTO authn_personal_access_tokens (id, realm_id, user_id, name, scopes, token_hash, created_at, expires_at, last_used_at, revoked_at, revoke_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPAT :one
SELECT * FROM authn_personal_access_tokens WHERE realm_id = ? AND id = ?;

-- name: ListPATsByUser :many
SELECT * FROM authn_personal_access_tokens WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: TouchPAT :execrows
UPDATE authn_personal_access_tokens SET last_used_at = ? WHERE realm_id = ? AND id = ?;

-- name: RevokePAT :execrows
UPDATE authn_personal_access_tokens SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND id = ? AND revoked_at IS NULL;

-- name: RevokePATsByUser :execrows
UPDATE authn_personal_access_tokens SET revoked_at = ?, revoke_reason = ? WHERE realm_id = ? AND user_id = ? AND revoked_at IS NULL;

-- name: DeletePATsByUser :execrows
DELETE FROM authn_personal_access_tokens WHERE realm_id = ? AND user_id = ?;

-- name: GetPATPolicy :one
SELECT * FROM authn_personal_access_token_policies WHERE realm_id = ?;

-- name: PutPATPolicy :exec
INSERT INTO authn_personal_access_token_policies (realm_id, max_lifetime_seconds, allowed_scopes, require_expiry, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (realm_id) DO UPDATE SET max_lifetime_seconds = excluded.max_lifetime_seconds, allowed_scopes = excluded.allowed_scopes,
    require_expiry = excluded.require_expiry, updated_at = excluded.updated_at;

-- name: CountPATs :one
SELECT count(*) FROM authn_personal_access_tokens;

-- name: CountPATPolicies :one
SELECT count(*) FROM authn_personal_access_token_policies;

-- name: PurgePATs :execrows
DELETE FROM authn_personal_access_tokens WHERE id IN (SELECT p.id FROM authn_personal_access_tokens p ORDER BY p.id LIMIT sqlc.arg(lim));

-- name: PurgePATPolicies :execrows
DELETE FROM authn_personal_access_token_policies WHERE realm_id IN (SELECT p.realm_id FROM authn_personal_access_token_policies p ORDER BY p.realm_id LIMIT sqlc.arg(lim));
