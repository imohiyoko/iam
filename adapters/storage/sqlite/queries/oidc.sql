-- name: CreateClient :exec
INSERT INTO authn_clients (id, public_id, realm_id, name, trust_level, redirect_uris, post_logout_redirect_uris, auth_method, secret_hash, jwks,
    id_token_alg, backchannel_logout_uri, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetClient :one
SELECT * FROM authn_clients WHERE realm_id = ? AND id = ?;

-- name: GetClientByPublicID :one
SELECT * FROM authn_clients WHERE realm_id = ? AND public_id = ?;

-- name: ListClients :many
SELECT * FROM authn_clients WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateClient :execrows
UPDATE authn_clients SET name = ?, trust_level = ?, redirect_uris = ?, post_logout_redirect_uris = ?, auth_method = ?, secret_hash = ?, jwks = ?,
    id_token_alg = ?, backchannel_logout_uri = ?, updated_at = ?
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
