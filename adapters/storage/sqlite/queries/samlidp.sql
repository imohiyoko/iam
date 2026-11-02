-- name: CreateSAMLServiceProvider :exec
INSERT INTO authn_saml_service_providers (id, realm_id, entity_id, name, config, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSAMLServiceProvider :one
SELECT * FROM authn_saml_service_providers WHERE realm_id = ? AND id = ?;

-- name: GetSAMLServiceProviderByEntityID :one
SELECT * FROM authn_saml_service_providers WHERE realm_id = ? AND entity_id = ?;

-- name: ListSAMLServiceProviders :many
SELECT * FROM authn_saml_service_providers WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateSAMLServiceProvider :execrows
UPDATE authn_saml_service_providers SET entity_id = ?, name = ?, config = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: DeleteSAMLServiceProvider :execrows
DELETE FROM authn_saml_service_providers WHERE realm_id = ? AND id = ?;

-- name: CountSAMLServiceProviders :one
SELECT count(*) FROM authn_saml_service_providers;

-- name: PurgeSAMLServiceProviders :execrows
DELETE FROM authn_saml_service_providers WHERE id IN (SELECT s.id FROM authn_saml_service_providers s ORDER BY s.id LIMIT sqlc.arg(lim));

-- name: CreateSAMLIdPCertificate :exec
INSERT INTO authn_saml_idp_certificates (realm_id, key_id, der, created_at) VALUES (?, ?, ?, ?);

-- name: ListSAMLIdPCertificates :many
SELECT * FROM authn_saml_idp_certificates WHERE realm_id = ? ORDER BY key_id;

-- name: DeleteSAMLIdPCertificate :execrows
DELETE FROM authn_saml_idp_certificates WHERE realm_id = ? AND key_id = ?;

-- name: CountSAMLIdPCertificates :one
SELECT count(*) FROM authn_saml_idp_certificates;

-- name: PurgeSAMLIdPCertificates :execrows
DELETE FROM authn_saml_idp_certificates WHERE (realm_id, key_id) IN (
    SELECT c.realm_id, c.key_id FROM authn_saml_idp_certificates c ORDER BY c.realm_id, c.key_id LIMIT sqlc.arg(lim));
