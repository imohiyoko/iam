-- name: CreateDirectoryGroup :exec
INSERT INTO authn_directory_groups (realm_id, connection_id, external_key, group_id, created_at) VALUES (?, ?, ?, ?, ?);

-- name: ListDirectoryGroupsByConnection :many
SELECT * FROM authn_directory_groups WHERE realm_id = ? AND connection_id = ? ORDER BY external_key;

-- name: DeleteDirectoryGroup :execrows
DELETE FROM authn_directory_groups WHERE realm_id = ? AND connection_id = ? AND external_key = ?;

-- name: DeleteDirectoryGroupsByConnection :execrows
DELETE FROM authn_directory_groups WHERE realm_id = ? AND connection_id = ?;

-- name: CountDirectoryGroups :one
SELECT count(*) FROM authn_directory_groups;

-- name: PurgeDirectoryGroups :execrows
DELETE FROM authn_directory_groups WHERE group_id IN (SELECT d.group_id FROM authn_directory_groups d ORDER BY d.group_id LIMIT sqlc.arg(lim));

-- name: ListActiveIdentitiesByConnection :many
SELECT * FROM authn_user_identities WHERE realm_id = ? AND connection_id = ? AND revoked_at IS NULL AND id > sqlc.arg(after) ORDER BY id LIMIT sqlc.arg(lim);
