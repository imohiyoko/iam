-- name: AddAuditRef :exec
INSERT INTO shared_audit_refs (realm_id, ref_id, seq) VALUES (sqlc.arg(realm_id), sqlc.arg(ref_id), sqlc.arg(seq)) ON CONFLICT DO NOTHING;

-- name: QueryAuditEvents :many
SELECT e.seq, e.realm_id, e.prev_hash, e.hash, e.payload, e.key_id FROM shared_audit_events e
WHERE e.realm_id = sqlc.arg(realm_id)
    AND e.seq < sqlc.arg(before_seq) AND e.occurred_unix >= sqlc.arg(since_unix) AND e.occurred_unix <= sqlc.arg(until_unix)
    AND (CAST(sqlc.arg(event_type) AS TEXT) = '' OR e.event_type = sqlc.arg(event_type))
    AND (CAST(sqlc.arg(type_prefix) AS TEXT) = '' OR substr(e.event_type, 1, length(sqlc.arg(type_prefix))) = sqlc.arg(type_prefix))
    AND (CAST(sqlc.arg(result) AS TEXT) = '' OR e.result = sqlc.arg(result))
    AND (CAST(sqlc.arg(actor_type) AS TEXT) = '' OR e.actor_type = sqlc.arg(actor_type))
    AND (CAST(sqlc.arg(actor_id) AS TEXT) = '' OR e.actor_id = sqlc.arg(actor_id))
    AND (CAST(sqlc.arg(org_id) AS TEXT) = '' OR e.org_id = sqlc.arg(org_id))
    AND (CAST(sqlc.arg(ref_id) AS TEXT) = '' OR EXISTS (
        SELECT 1 FROM shared_audit_refs r WHERE r.realm_id = e.realm_id AND r.ref_id = sqlc.arg(ref_id) AND r.seq = e.seq))
ORDER BY e.seq DESC LIMIT sqlc.arg(lim);

-- name: GetAuditEventByID :one
SELECT seq, realm_id, prev_hash, hash, payload, key_id FROM shared_audit_events WHERE realm_id = sqlc.arg(realm_id) AND event_id = sqlc.arg(event_id)
ORDER BY seq LIMIT 1;

-- name: CreateEventSubscription :exec
INSERT INTO shared_event_subscriptions (id, realm_id, url, event_types, pii, enabled, secret_ciphertext, created_by, created_at, updated_at,
    cursor_seq, failures, next_attempt_at, last_error, last_delivered_at)
VALUES (sqlc.arg(id), sqlc.arg(realm_id), sqlc.arg(url), sqlc.arg(event_types), sqlc.arg(pii), sqlc.arg(enabled), sqlc.arg(secret_ciphertext),
    sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(updated_at), sqlc.arg(cursor_seq), sqlc.arg(failures), sqlc.arg(next_attempt_at),
    sqlc.arg(last_error), sqlc.arg(last_delivered_at));

-- name: GetEventSubscription :one
SELECT * FROM shared_event_subscriptions WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: ListEventSubscriptions :many
SELECT * FROM shared_event_subscriptions WHERE realm_id = sqlc.arg(realm_id) ORDER BY created_at, id;

-- name: UpdateEventSubscription :execrows
UPDATE shared_event_subscriptions SET url = sqlc.arg(url), event_types = sqlc.arg(event_types), pii = sqlc.arg(pii), enabled = sqlc.arg(enabled),
    secret_ciphertext = sqlc.arg(secret_ciphertext), updated_at = sqlc.arg(updated_at)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: SetEventSubscriptionDelivery :execrows
UPDATE shared_event_subscriptions SET
    cursor_seq = CASE WHEN cursor_seq < sqlc.arg(cursor_seq) THEN sqlc.arg(cursor_seq) ELSE cursor_seq END,
    failures = sqlc.arg(failures), next_attempt_at = sqlc.arg(next_attempt_at), last_error = sqlc.arg(last_error),
    last_delivered_at = sqlc.arg(last_delivered_at)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: DeleteEventSubscription :execrows
DELETE FROM shared_event_subscriptions WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: DueEventSubscriptions :many
SELECT * FROM shared_event_subscriptions
WHERE enabled = 1 AND (next_attempt_at IS NULL OR next_attempt_at <= sqlc.arg(now))
ORDER BY next_attempt_at IS NOT NULL, next_attempt_at, id LIMIT sqlc.arg(lim);

-- name: CountEventSubscriptions :one
SELECT count(*) FROM shared_event_subscriptions;

-- name: PurgeEventSubscriptions :many
DELETE FROM shared_event_subscriptions WHERE id IN (
    SELECT s.id FROM shared_event_subscriptions s ORDER BY s.id LIMIT sqlc.arg(lim))
RETURNING id;
