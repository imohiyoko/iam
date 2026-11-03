-- name: CreateVCIConfiguration :exec
INSERT INTO vci_credential_configurations (id, realm_id, configuration_id, scope, config, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetVCIConfiguration :one
SELECT * FROM vci_credential_configurations WHERE realm_id = ? AND id = ?;

-- name: GetVCIConfigurationByConfigurationID :one
SELECT * FROM vci_credential_configurations WHERE realm_id = ? AND configuration_id = ?;

-- name: ListVCIConfigurations :many
SELECT * FROM vci_credential_configurations WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateVCIConfiguration :execrows
UPDATE vci_credential_configurations SET configuration_id = ?, scope = ?, config = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: DeleteVCIConfiguration :execrows
DELETE FROM vci_credential_configurations WHERE realm_id = ? AND id = ?;

-- name: CountVCIConfigurations :one
SELECT count(*) FROM vci_credential_configurations;

-- name: PurgeVCIConfigurations :execrows
DELETE FROM vci_credential_configurations WHERE id IN (SELECT c.id FROM vci_credential_configurations c ORDER BY c.id LIMIT sqlc.arg(lim));

-- name: CreateVCICredential :exec
INSERT INTO vci_issued_credentials (id, realm_id, user_id, configuration_id, status_index, holder_jkt, issued_at, expires_at, revoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetVCICredential :one
SELECT * FROM vci_issued_credentials WHERE realm_id = ? AND id = ?;

-- name: ListVCICredentialsByUser :many
SELECT * FROM vci_issued_credentials WHERE realm_id = ? AND user_id = ? ORDER BY issued_at DESC, id DESC;

-- name: RevokeVCICredential :execrows
UPDATE vci_issued_credentials SET revoked_at = coalesce(revoked_at, sqlc.arg(revoked_at))
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: RevokeVCICredentialsByUser :exec
UPDATE vci_issued_credentials SET revoked_at = sqlc.arg(revoked_at)
WHERE realm_id = sqlc.arg(realm_id) AND user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: ListVCIRevokedIndexes :many
SELECT status_index FROM vci_issued_credentials
WHERE realm_id = sqlc.arg(realm_id) AND revoked_at IS NOT NULL AND expires_at > sqlc.arg(now);

-- name: DeleteExpiredVCICredentials :execrows
DELETE FROM vci_issued_credentials WHERE id IN (
    SELECT c.id FROM vci_issued_credentials c WHERE c.realm_id = sqlc.arg(realm_id) AND c.expires_at <= sqlc.arg(now)
    ORDER BY c.id LIMIT sqlc.arg(lim));

-- name: CountVCICredentials :one
SELECT count(*) FROM vci_issued_credentials;

-- name: PurgeVCICredentials :execrows
DELETE FROM vci_issued_credentials WHERE id IN (SELECT c.id FROM vci_issued_credentials c ORDER BY c.id LIMIT sqlc.arg(lim));
