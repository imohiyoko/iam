-- name: CreateKnownDevice :exec
INSERT INTO authn_known_devices (id, public_id, realm_id, user_id, lookup, data, created_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListKnownDevicesByUser :many
SELECT * FROM authn_known_devices WHERE realm_id = ? AND user_id = ? ORDER BY created_at, id;

-- name: SeeKnownDevice :execrows
UPDATE authn_known_devices SET data = ?, last_seen_at = ? WHERE realm_id = ? AND id = ?;

-- name: DeleteKnownDevice :execrows
DELETE FROM authn_known_devices WHERE realm_id = ? AND id = ?;

-- name: DeleteKnownDevicesByUser :execrows
DELETE FROM authn_known_devices WHERE realm_id = ? AND user_id = ?;

-- name: CountKnownDevices :one
SELECT count(*) FROM authn_known_devices;

-- name: PurgeKnownDevices :execrows
DELETE FROM authn_known_devices WHERE id IN (SELECT d.id FROM authn_known_devices d ORDER BY d.id LIMIT sqlc.arg(lim));
