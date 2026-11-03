-- name: CreateWorkloadIdentityProvider :exec
INSERT INTO authn_workload_identity_providers (id, realm_id, issuer, name, config, disabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetWorkloadIdentityProvider :one
SELECT * FROM authn_workload_identity_providers WHERE realm_id = ? AND id = ?;

-- name: GetWorkloadIdentityProviderByIssuer :one
SELECT * FROM authn_workload_identity_providers WHERE realm_id = ? AND issuer = ?;

-- name: ListWorkloadIdentityProviders :many
SELECT * FROM authn_workload_identity_providers WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateWorkloadIdentityProvider :execrows
UPDATE authn_workload_identity_providers SET issuer = ?, name = ?, config = ?, disabled = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: DeleteWorkloadIdentityBindingsByProvider :exec
DELETE FROM authn_workload_identity_bindings WHERE realm_id = ? AND provider_id = ?;

-- name: DeleteWorkloadIdentityProvider :execrows
DELETE FROM authn_workload_identity_providers WHERE realm_id = ? AND id = ?;

-- name: CreateWorkloadIdentityBinding :exec
INSERT INTO authn_workload_identity_bindings (id, realm_id, provider_id, service_account_id, conditions, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetWorkloadIdentityBinding :one
SELECT * FROM authn_workload_identity_bindings WHERE realm_id = ? AND id = ?;

-- name: ListWorkloadIdentityBindings :many
SELECT * FROM authn_workload_identity_bindings WHERE realm_id = ? AND provider_id = ? ORDER BY created_at, id;

-- name: DeleteWorkloadIdentityBinding :execrows
DELETE FROM authn_workload_identity_bindings WHERE realm_id = ? AND id = ?;

-- name: CountWorkloadIdentityTokens :one
SELECT count(*) FROM authn_service_account_tokens WHERE substr(credential_id, 1, 4) = 'wib_';

-- name: PurgeWorkloadIdentityTokens :execrows
DELETE FROM authn_service_account_tokens WHERE id IN (
    SELECT t.id FROM authn_service_account_tokens t WHERE substr(t.credential_id, 1, 4) = 'wib_' ORDER BY t.id LIMIT sqlc.arg(lim));

-- name: CountWorkloadIdentityBindings :one
SELECT count(*) FROM authn_workload_identity_bindings;

-- name: PurgeWorkloadIdentityBindings :execrows
DELETE FROM authn_workload_identity_bindings WHERE id IN (
    SELECT b.id FROM authn_workload_identity_bindings b ORDER BY b.id LIMIT sqlc.arg(lim));

-- name: CountWorkloadIdentityProviders :one
SELECT count(*) FROM authn_workload_identity_providers;

-- name: PurgeWorkloadIdentityProviders :execrows
DELETE FROM authn_workload_identity_providers WHERE id IN (
    SELECT p.id FROM authn_workload_identity_providers p
    WHERE NOT EXISTS (SELECT 1 FROM authn_workload_identity_bindings b WHERE b.provider_id = p.id)
    ORDER BY p.id LIMIT sqlc.arg(lim));
