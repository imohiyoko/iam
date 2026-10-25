-- name: CreateUser :exec
INSERT INTO authn_users (id, realm_id, status, valid_from, valid_until, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetUser :one
SELECT * FROM authn_users WHERE realm_id = ? AND id = ?;

-- name: CreateEmail :exec
INSERT INTO authn_user_emails (id, realm_id, user_id, ciphertext, email_index, domain_index, index_key_id, verified_at, verified_via, is_primary, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetEmailByIndex :one
SELECT * FROM authn_user_emails WHERE realm_id = ? AND email_index = ?;

-- name: ListEmailsByUser :many
SELECT * FROM authn_user_emails WHERE realm_id = ? AND user_id = ? ORDER BY id;

-- name: CreateIdentity :exec
INSERT INTO authn_user_identities (id, realm_id, user_id, connection_id, provider_subject, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetIdentityBySubject :one
SELECT * FROM authn_user_identities WHERE realm_id = ? AND connection_id = ? AND provider_subject = ?;

-- name: ListIdentitiesByUser :many
SELECT * FROM authn_user_identities WHERE realm_id = ? AND user_id = ? ORDER BY id;

-- name: CreateConnection :exec
INSERT INTO authn_connections (id, realm_id, slug, type, config, created_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetConnection :one
SELECT * FROM authn_connections WHERE realm_id = ? AND id = ?;

-- name: GetConnectionBySlug :one
SELECT * FROM authn_connections WHERE realm_id = ? AND slug = ?;

-- name: ListConnections :many
SELECT * FROM authn_connections WHERE realm_id = ? ORDER BY slug;

-- name: CreateSession :exec
INSERT INTO authn_sessions (id, realm_id, principal_type, principal_id, active_org_id, token_hash, auth_methods, auth_credential_ids,
    warnings, ip, user_agent, authenticated_at, created_at, last_seen_at, expires_at, revoked_at, revoke_reason)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM authn_sessions WHERE realm_id = ? AND id = ?;

-- name: ListSessionsByPrincipal :many
SELECT * FROM authn_sessions WHERE realm_id = ? AND principal_type = ? AND principal_id = ? ORDER BY id DESC;

-- name: TouchSession :execrows
UPDATE authn_sessions SET last_seen_at = max(last_seen_at, sqlc.arg(at)) WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: RevokeSession :execrows
UPDATE authn_sessions SET revoked_at = coalesce(revoked_at, sqlc.arg(at)),
    revoke_reason = CASE WHEN revoked_at IS NULL THEN sqlc.arg(reason) ELSE revoke_reason END
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: RevokeSessionsByPrincipal :many
UPDATE authn_sessions SET revoked_at = sqlc.arg(at), revoke_reason = sqlc.arg(reason)
WHERE realm_id = sqlc.arg(realm_id) AND principal_type = sqlc.arg(principal_type) AND principal_id = sqlc.arg(principal_id)
    AND id <> sqlc.arg(except_id) AND revoked_at IS NULL
RETURNING id;

-- name: ShortenSession :execrows
UPDATE authn_sessions SET expires_at = min(expires_at, sqlc.arg(at)) WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: CreateServiceAccount :exec
INSERT INTO authn_service_accounts (id, realm_id, name, created_at) VALUES (?, ?, ?, ?);

-- name: GetServiceAccount :one
SELECT * FROM authn_service_accounts WHERE realm_id = ? AND id = ?;

-- name: CreateServiceAccountCredential :exec
INSERT INTO authn_service_account_credentials (id, realm_id, service_account_id, type, secret_hash, created_at, expires_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetServiceAccountCredential :one
SELECT * FROM authn_service_account_credentials WHERE realm_id = ? AND id = ?;

-- name: RevokeServiceAccountCredential :execrows
UPDATE authn_service_account_credentials SET revoked_at = coalesce(revoked_at, sqlc.arg(at)) WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: CreateRoleBinding :exec
INSERT INTO authz_role_bindings (id, realm_id, role, principal_type, principal_id, org_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListRoleBindingsByPrincipal :many
SELECT * FROM authz_role_bindings WHERE realm_id = ? AND principal_type = ? AND principal_id = ? ORDER BY id;

-- name: ListRoleBindingsByRole :many
SELECT * FROM authz_role_bindings WHERE realm_id = ? AND role = ? ORDER BY id;
