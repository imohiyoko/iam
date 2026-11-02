-- name: CreateOAuthResource :exec
INSERT INTO authn_oauth_resources (id, realm_id, uri, name, scopes, clients, service_accounts, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthResource :one
SELECT * FROM authn_oauth_resources WHERE realm_id = ? AND id = ?;

-- name: GetOAuthResourceByURI :one
SELECT * FROM authn_oauth_resources WHERE realm_id = ? AND uri = ?;

-- name: ListOAuthResources :many
SELECT * FROM authn_oauth_resources WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateOAuthResource :execrows
UPDATE authn_oauth_resources SET uri = ?, name = ?, scopes = ?, clients = ?, service_accounts = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: DeleteOAuthResource :execrows
DELETE FROM authn_oauth_resources WHERE realm_id = ? AND id = ?;

-- name: CountOAuthResources :one
SELECT count(*) FROM authn_oauth_resources;

-- name: PurgeOAuthResources :execrows
DELETE FROM authn_oauth_resources WHERE id IN (SELECT r.id FROM authn_oauth_resources r ORDER BY r.id LIMIT sqlc.arg(lim));
