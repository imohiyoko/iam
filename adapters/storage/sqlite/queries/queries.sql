-- name: CreateRealm :exec
INSERT INTO authn_realms (id, slug, settings, created_at) VALUES (?, ?, ?, ?);

-- name: GetRealm :one
SELECT id, slug, settings, created_at FROM authn_realms WHERE id = ?;

-- name: GetRealmBySlug :one
SELECT id, slug, settings, created_at FROM authn_realms WHERE slug = ?;

-- name: ListRealms :many
SELECT id, slug, settings, created_at FROM authn_realms ORDER BY id;

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
SELECT seq, realm_id, prev_hash, hash, payload FROM shared_audit_events ORDER BY seq DESC LIMIT 1;

-- name: AppendAuditEvent :exec
INSERT INTO shared_audit_events (seq, realm_id, prev_hash, hash, payload) VALUES (?, ?, ?, ?, ?);

-- name: ScanAuditEvents :many
SELECT seq, realm_id, prev_hash, hash, payload FROM shared_audit_events WHERE seq >= ? ORDER BY seq LIMIT ?;

-- name: ListAuditEventsByRealm :many
SELECT seq, realm_id, prev_hash, hash, payload FROM shared_audit_events WHERE realm_id = ? AND seq >= ? ORDER BY seq LIMIT ?;

-- name: AddOutbox :exec
INSERT INTO shared_outbox (id, topic, payload, created_at) VALUES (?, ?, ?, ?);

-- name: PendingOutbox :many
SELECT id, topic, payload, created_at, delivered_at FROM shared_outbox
WHERE topic = ? AND delivered_at IS NULL ORDER BY created_at, rowid LIMIT ?;

-- name: MarkOutboxDelivered :exec
UPDATE shared_outbox SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL;
