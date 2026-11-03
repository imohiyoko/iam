-- name: CreateClient :exec
INSERT INTO authn_clients (id, public_id, realm_id, name, trust_level, redirect_uris, post_logout_redirect_uris, auth_method, secret_hash, jwks,
    id_token_alg, backchannel_logout_uri, frontchannel_logout_uri, frontchannel_logout_session_required, created_at, updated_at, token_exchange, device_grant,
    ciba_mode, ciba_notification_endpoint, require_par, dpop_bound_access_tokens, tls_bound_access_tokens, tls_auth_field, tls_auth_value,
    fapi2_security_profile)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetClient :one
SELECT * FROM authn_clients WHERE realm_id = ? AND id = ?;

-- name: GetClientByPublicID :one
SELECT * FROM authn_clients WHERE realm_id = ? AND public_id = ?;

-- name: ListClients :many
SELECT * FROM authn_clients WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateClient :execrows
UPDATE authn_clients SET name = ?, trust_level = ?, redirect_uris = ?, post_logout_redirect_uris = ?, auth_method = ?, secret_hash = ?, jwks = ?,
    id_token_alg = ?, backchannel_logout_uri = ?, frontchannel_logout_uri = ?, frontchannel_logout_session_required = ?, updated_at = ?, token_exchange = ?, device_grant = ?,
    ciba_mode = ?, ciba_notification_endpoint = ?, require_par = ?, dpop_bound_access_tokens = ?, tls_bound_access_tokens = ?, tls_auth_field = ?, tls_auth_value = ?,
    fapi2_security_profile = ?
WHERE realm_id = ? AND id = ?;

-- name: DeleteClient :execrows
DELETE FROM authn_clients WHERE realm_id = ? AND id = ?;

-- name: CreateSigningKey :exec
INSERT INTO authn_signing_keys (id, realm_id, alg, public_key, private_key, created_at, retired_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListSigningKeys :many
SELECT * FROM authn_signing_keys WHERE realm_id = ? ORDER BY created_at, id;

-- name: RetireSigningKey :execrows
UPDATE authn_signing_keys SET retired_at = ? WHERE realm_id = ? AND id = ?;

-- name: DeleteSigningKey :execrows
DELETE FROM authn_signing_keys WHERE realm_id = ? AND id = ?;

-- name: CreateGrant :exec
INSERT INTO authn_oidc_grants (id, realm_id, client_id, user_id, org_id, sid, scopes, auth_methods, auth_time, created_at, expires_at, revoked_at, revoke_reason, acr,
    exchange, parent_id, actor_user_id, act, audiences)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetGrant :one
SELECT * FROM authn_oidc_grants WHERE realm_id = ? AND id = ?;

-- name: ListGrantsBySID :many
SELECT * FROM authn_oidc_grants WHERE realm_id = ? AND sid = ? ORDER BY created_at, id;

-- name: RevokeGrant :execrows
UPDATE authn_oidc_grants SET
    revoke_reason = CASE WHEN revoked_at IS NULL OR revoked_at > sqlc.arg(at) THEN sqlc.arg(reason) ELSE revoke_reason END,
    revoked_at = CASE WHEN revoked_at IS NULL OR revoked_at > sqlc.arg(at) THEN sqlc.arg(at) ELSE revoked_at END
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: EraseUserGrantTokens :exec
DELETE FROM authn_oidc_tokens WHERE grant_id IN (SELECT g.id FROM authn_oidc_grants g WHERE g.realm_id = sqlc.arg(realm_id)
    AND (g.user_id = sqlc.arg(user_id) OR g.actor_user_id = sqlc.arg(user_id)));

-- name: EraseUserGrants :exec
DELETE FROM authn_oidc_grants WHERE realm_id = sqlc.arg(realm_id) AND (user_id = sqlc.arg(user_id) OR actor_user_id = sqlc.arg(user_id));

-- name: CountExchangedGrants :one
SELECT count(*) FROM authn_oidc_grants WHERE exchange = ?;

-- name: PurgeExchangedGrantTokens :exec
DELETE FROM authn_oidc_tokens WHERE grant_id IN (
    SELECT g.id FROM authn_oidc_grants g WHERE g.exchange = sqlc.arg(exchange) ORDER BY g.id LIMIT sqlc.arg(lim));

-- name: PurgeExchangedGrants :execrows
DELETE FROM authn_oidc_grants WHERE id IN (
    SELECT g.id FROM authn_oidc_grants g WHERE g.exchange = sqlc.arg(exchange) ORDER BY g.id LIMIT sqlc.arg(lim));

-- name: DeleteClientGrantTokens :exec
DELETE FROM authn_oidc_tokens WHERE grant_id IN (SELECT g.id FROM authn_oidc_grants g WHERE g.realm_id = sqlc.arg(realm_id) AND g.client_id = sqlc.arg(client_id));

-- name: DeleteClientGrants :exec
DELETE FROM authn_oidc_grants WHERE realm_id = ? AND client_id = ?;

-- name: CreateOIDCToken :exec
INSERT INTO authn_oidc_tokens (id, realm_id, grant_id, kind, token_hash, created_at, expires_at, used_at, jkt, x5t) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOIDCToken :one
SELECT * FROM authn_oidc_tokens WHERE realm_id = ? AND id = ?;

-- name: CountDPoPBoundOIDCTokens :one
SELECT count(*) FROM authn_oidc_tokens WHERE jkt <> '';

-- name: CountMTLSBoundOIDCTokens :one
SELECT count(*) FROM authn_oidc_tokens WHERE x5t <> '';

-- name: PurgeDPoPBoundOIDCTokens :execrows
DELETE FROM authn_oidc_tokens WHERE id IN (SELECT t.id FROM authn_oidc_tokens t WHERE t.jkt <> '' ORDER BY t.id LIMIT sqlc.arg(lim));

-- name: PurgeMTLSBoundOIDCTokens :execrows
DELETE FROM authn_oidc_tokens WHERE id IN (SELECT t.id FROM authn_oidc_tokens t WHERE t.x5t <> '' ORDER BY t.id LIMIT sqlc.arg(lim));

-- name: UseOIDCToken :execrows
UPDATE authn_oidc_tokens SET used_at = ? WHERE realm_id = ? AND id = ? AND used_at IS NULL;
