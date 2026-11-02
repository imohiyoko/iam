-- name: CreateWSFedRelyingParty :exec
INSERT INTO authn_wsfed_relying_parties (id, realm_id, realm, name, reply_urls, token_type, claims, token_lifetime, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetWSFedRelyingParty :one
SELECT * FROM authn_wsfed_relying_parties WHERE realm_id = ? AND id = ?;

-- name: GetWSFedRelyingPartyByRealm :one
SELECT * FROM authn_wsfed_relying_parties WHERE realm_id = ? AND realm = ?;

-- name: ListWSFedRelyingParties :many
SELECT * FROM authn_wsfed_relying_parties WHERE realm_id = ? ORDER BY created_at, id;

-- name: UpdateWSFedRelyingParty :execrows
UPDATE authn_wsfed_relying_parties SET realm = ?, name = ?, reply_urls = ?, token_type = ?, claims = ?, token_lifetime = ?, updated_at = ?
WHERE realm_id = ? AND id = ?;

-- name: DeleteWSFedRelyingParty :execrows
DELETE FROM authn_wsfed_relying_parties WHERE realm_id = ? AND id = ?;

-- name: CountWSFedRelyingParties :one
SELECT count(*) FROM authn_wsfed_relying_parties;

-- name: PurgeWSFedRelyingParties :execrows
DELETE FROM authn_wsfed_relying_parties WHERE id IN (SELECT r.id FROM authn_wsfed_relying_parties r ORDER BY r.id LIMIT sqlc.arg(lim));

-- name: CreateWSFedCertificate :exec
INSERT INTO authn_wsfed_certificates (realm_id, key_id, der, created_at) VALUES (?, ?, ?, ?);

-- name: ListWSFedCertificates :many
SELECT * FROM authn_wsfed_certificates WHERE realm_id = ? ORDER BY key_id;

-- name: DeleteWSFedCertificate :execrows
DELETE FROM authn_wsfed_certificates WHERE realm_id = ? AND key_id = ?;

-- name: CountWSFedCertificates :one
SELECT count(*) FROM authn_wsfed_certificates;

-- name: PurgeWSFedCertificates :execrows
DELETE FROM authn_wsfed_certificates WHERE (realm_id, key_id) IN (
    SELECT c.realm_id, c.key_id FROM authn_wsfed_certificates c ORDER BY c.realm_id, c.key_id LIMIT sqlc.arg(lim));
