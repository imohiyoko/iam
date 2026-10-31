-- name: CreateRealm :exec
INSERT INTO authn_realms (id, slug, settings, created_at, updated_at) VALUES (?, ?, ?, ?, ?);

-- name: GetRealm :one
SELECT id, slug, settings, created_at, updated_at FROM authn_realms WHERE id = ?;

-- name: GetRealmBySlug :one
SELECT id, slug, settings, created_at, updated_at FROM authn_realms WHERE slug = ?;

-- name: GetRealmByHost :one
SELECT r.id, r.slug, r.settings, r.created_at, r.updated_at FROM authn_realms r
JOIN authn_realm_hosts h ON h.realm_id = r.id WHERE h.host = ?;

-- name: ListRealms :many
SELECT id, slug, settings, created_at, updated_at FROM authn_realms ORDER BY id;

-- name: UpdateRealm :execrows
UPDATE authn_realms SET settings = ?, updated_at = ? WHERE id = ?;

-- name: ListRealmHosts :many
SELECT host, realm_id FROM authn_realm_hosts ORDER BY realm_id, position;

-- name: ListHostsOfRealm :many
SELECT host FROM authn_realm_hosts WHERE realm_id = ? ORDER BY position;

-- name: AddRealmHost :exec
INSERT INTO authn_realm_hosts (host, realm_id, position) VALUES (?, ?, ?);

-- name: DeleteRealmHosts :exec
DELETE FROM authn_realm_hosts WHERE realm_id = ?;

-- name: ListFeatures :many
SELECT feature, state, data_version, updated_at FROM shared_installed_features ORDER BY feature;

-- name: PutFeature :exec
INSERT INTO shared_installed_features (feature, state, data_version, updated_at) VALUES (?, ?, ?, ?)
ON CONFLICT (feature) DO UPDATE SET state = excluded.state, data_version = excluded.data_version, updated_at = excluded.updated_at;

-- name: DeleteFeature :exec
DELETE FROM shared_installed_features WHERE feature = ?;

-- name: CreateDataKey :exec
INSERT INTO authn_user_data_keys (user_id, wrapped_key, key_id, created_at) VALUES (?, ?, ?, ?);

-- name: GetDataKey :one
SELECT user_id, wrapped_key, key_id, created_at FROM authn_user_data_keys WHERE user_id = ?;

-- name: DeleteDataKey :exec
DELETE FROM authn_user_data_keys WHERE user_id = ?;

-- name: CreateAuditKey :exec
INSERT INTO shared_audit_client_keys (owner, wrapped_key, key_id, created_at) VALUES (?, ?, ?, ?);

-- name: GetAuditKey :one
SELECT owner, wrapped_key, key_id, created_at FROM shared_audit_client_keys WHERE owner = ?;

-- name: DeleteAuditKey :exec
DELETE FROM shared_audit_client_keys WHERE owner = ?;

-- name: LastAuditEvent :one
SELECT seq, realm_id, prev_hash, hash, payload, key_id FROM shared_audit_events ORDER BY seq DESC LIMIT 1;

-- name: AppendAuditEvent :exec
INSERT INTO shared_audit_events (seq, realm_id, prev_hash, hash, payload, key_id) VALUES (?, ?, ?, ?, ?, ?);

-- name: ScanAuditEvents :many
SELECT seq, realm_id, prev_hash, hash, payload, key_id FROM shared_audit_events WHERE seq >= ? ORDER BY seq LIMIT ?;

-- name: ListAuditEventsByRealm :many
SELECT seq, realm_id, prev_hash, hash, payload, key_id FROM shared_audit_events WHERE realm_id = ? AND seq >= ? ORDER BY seq LIMIT ?;

-- name: GetAuditCheckpoint :one
SELECT seq, hash, created_at, key_id FROM shared_audit_checkpoint WHERE id = 1;

-- name: PutAuditCheckpoint :exec
INSERT INTO shared_audit_checkpoint (id, seq, hash, created_at, key_id) VALUES (1, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash, created_at = excluded.created_at, key_id = excluded.key_id;

-- name: TruncateAuditEvents :exec
DELETE FROM shared_audit_events WHERE seq <= ?;

-- name: AddOutbox :exec
INSERT INTO shared_outbox (id, topic, payload, created_at) VALUES (?, ?, ?, ?);

-- name: PendingOutbox :many
SELECT id, topic, payload, created_at, delivered_at FROM shared_outbox
WHERE topic = ? AND delivered_at IS NULL ORDER BY created_at, rowid LIMIT ?;

-- name: MarkOutboxDelivered :exec
UPDATE shared_outbox SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL;

-- name: DeleteDeliveredOutbox :execrows
DELETE FROM shared_outbox WHERE id IN (
    SELECT o.id FROM shared_outbox o WHERE o.delivered_at IS NOT NULL AND o.delivered_at < sqlc.arg(before) LIMIT sqlc.arg(lim));
