-- name: CreateSSFStream :exec
INSERT INTO authn_ssf_streams (id, realm_id, service_account_id, delivery_method, endpoint_url, authorization_ciphertext, events_requested,
    events_delivered, description, status, status_reason, created_at, updated_at, cursor_seq, failures, next_attempt_at, last_error, last_delivered_at)
VALUES (sqlc.arg(id), sqlc.arg(realm_id), sqlc.arg(service_account_id), sqlc.arg(delivery_method), sqlc.arg(endpoint_url),
    sqlc.arg(authorization_ciphertext), sqlc.arg(events_requested), sqlc.arg(events_delivered), sqlc.arg(description), sqlc.arg(status),
    sqlc.arg(status_reason), sqlc.arg(created_at), sqlc.arg(updated_at), sqlc.arg(cursor_seq), sqlc.arg(failures), sqlc.arg(next_attempt_at),
    sqlc.arg(last_error), sqlc.arg(last_delivered_at));

-- name: GetSSFStream :one
SELECT * FROM authn_ssf_streams WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: ListSSFStreams :many
SELECT * FROM authn_ssf_streams WHERE realm_id = sqlc.arg(realm_id) ORDER BY created_at, id;

-- name: UpdateSSFStream :execrows
UPDATE authn_ssf_streams SET delivery_method = sqlc.arg(delivery_method), endpoint_url = sqlc.arg(endpoint_url),
    authorization_ciphertext = sqlc.arg(authorization_ciphertext), events_requested = sqlc.arg(events_requested),
    events_delivered = sqlc.arg(events_delivered), description = sqlc.arg(description), status = sqlc.arg(status),
    status_reason = sqlc.arg(status_reason), updated_at = sqlc.arg(updated_at)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: SetSSFStreamDelivery :execrows
UPDATE authn_ssf_streams SET
    cursor_seq = CASE WHEN cursor_seq < sqlc.arg(cursor_seq) THEN sqlc.arg(cursor_seq) ELSE cursor_seq END,
    failures = sqlc.arg(failures), next_attempt_at = sqlc.arg(next_attempt_at), last_error = sqlc.arg(last_error),
    last_delivered_at = sqlc.arg(last_delivered_at)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: DeleteSSFStream :execrows
DELETE FROM authn_ssf_streams WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: DeleteSSFStreamSubjects :exec
DELETE FROM authn_ssf_stream_subjects WHERE stream_id = sqlc.arg(stream_id);

-- name: DeleteSSFPollEvents :exec
DELETE FROM authn_ssf_poll_events WHERE stream_id = sqlc.arg(stream_id);

-- name: DuePushSSFStreams :many
SELECT * FROM authn_ssf_streams
WHERE delivery_method = 'push' AND status = 'enabled' AND (next_attempt_at IS NULL OR next_attempt_at <= sqlc.arg(now))
ORDER BY next_attempt_at IS NOT NULL, next_attempt_at, id LIMIT sqlc.arg(lim);

-- name: AddSSFStreamSubject :exec
INSERT INTO authn_ssf_stream_subjects (stream_id, realm_id, subject, created_at)
VALUES (sqlc.arg(stream_id), sqlc.arg(realm_id), sqlc.arg(subject), sqlc.arg(created_at))
ON CONFLICT (stream_id, subject) DO NOTHING;

-- name: RemoveSSFStreamSubject :execrows
DELETE FROM authn_ssf_stream_subjects WHERE realm_id = sqlc.arg(realm_id) AND stream_id = sqlc.arg(stream_id) AND subject = sqlc.arg(subject);

-- name: HasSSFStreamSubject :one
SELECT count(*) FROM authn_ssf_stream_subjects WHERE realm_id = sqlc.arg(realm_id) AND stream_id = sqlc.arg(stream_id) AND subject = sqlc.arg(subject);

-- name: CountSSFStreamSubjects :one
SELECT count(*) FROM authn_ssf_stream_subjects WHERE realm_id = sqlc.arg(realm_id) AND stream_id = sqlc.arg(stream_id);

-- name: RemoveSSFSubjectEverywhere :execrows
DELETE FROM authn_ssf_stream_subjects WHERE realm_id = sqlc.arg(realm_id) AND subject = sqlc.arg(subject);

-- name: AddSSFPollEvent :exec
INSERT INTO authn_ssf_poll_events (stream_id, realm_id, jti, seq, set_jwt, created_at)
VALUES (sqlc.arg(stream_id), sqlc.arg(realm_id), sqlc.arg(jti), sqlc.arg(seq), sqlc.arg(set_jwt), sqlc.arg(created_at))
ON CONFLICT (stream_id, jti) DO NOTHING;

-- name: ListSSFPollEvents :many
SELECT * FROM authn_ssf_poll_events WHERE realm_id = sqlc.arg(realm_id) AND stream_id = sqlc.arg(stream_id)
ORDER BY seq, jti LIMIT sqlc.arg(lim);

-- name: CountSSFPollEvents :one
SELECT count(*) FROM authn_ssf_poll_events WHERE realm_id = sqlc.arg(realm_id) AND stream_id = sqlc.arg(stream_id);

-- name: AckSSFPollEvent :execrows
DELETE FROM authn_ssf_poll_events WHERE realm_id = sqlc.arg(realm_id) AND stream_id = sqlc.arg(stream_id) AND jti = sqlc.arg(jti);

-- name: CountSSFStreams :one
SELECT count(*) FROM authn_ssf_streams;

-- name: PurgeSSFStreams :many
DELETE FROM authn_ssf_streams WHERE id IN (SELECT s.id FROM authn_ssf_streams s ORDER BY s.id LIMIT sqlc.arg(lim))
RETURNING id;

-- name: CreateSSFTransmitter :exec
INSERT INTO authn_ssf_transmitters (id, realm_id, name, issuer, config, push_token_hash, enabled, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(realm_id), sqlc.arg(name), sqlc.arg(issuer), sqlc.arg(config), sqlc.arg(push_token_hash), sqlc.arg(enabled),
    sqlc.arg(created_at), sqlc.arg(updated_at));

-- name: GetSSFTransmitter :one
SELECT * FROM authn_ssf_transmitters WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: ListSSFTransmitters :many
SELECT * FROM authn_ssf_transmitters WHERE realm_id = sqlc.arg(realm_id) ORDER BY created_at, id;

-- name: UpdateSSFTransmitter :execrows
UPDATE authn_ssf_transmitters SET name = sqlc.arg(name), issuer = sqlc.arg(issuer), config = sqlc.arg(config),
    push_token_hash = sqlc.arg(push_token_hash), enabled = sqlc.arg(enabled), updated_at = sqlc.arg(updated_at)
WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: DeleteSSFTransmitter :execrows
DELETE FROM authn_ssf_transmitters WHERE realm_id = sqlc.arg(realm_id) AND id = sqlc.arg(id);

-- name: CountSSFTransmitters :one
SELECT count(*) FROM authn_ssf_transmitters;

-- name: PurgeSSFTransmitters :execrows
DELETE FROM authn_ssf_transmitters WHERE id IN (SELECT t.id FROM authn_ssf_transmitters t ORDER BY t.id LIMIT sqlc.arg(lim));

-- name: SetDevicePosture :execrows
INSERT INTO authn_device_postures (realm_id, user_id, device_id, status, source, event_at, updated_at)
VALUES (sqlc.arg(realm_id), sqlc.arg(user_id), sqlc.arg(device_id), sqlc.arg(status), sqlc.arg(source), sqlc.arg(event_at), sqlc.arg(updated_at))
ON CONFLICT (realm_id, user_id, device_id) DO UPDATE SET status = excluded.status, source = excluded.source, event_at = excluded.event_at,
    updated_at = excluded.updated_at
WHERE authn_device_postures.event_at <= excluded.event_at;

-- name: GetDevicePosture :one
SELECT * FROM authn_device_postures WHERE realm_id = sqlc.arg(realm_id) AND user_id = sqlc.arg(user_id) AND device_id = sqlc.arg(device_id);

-- name: ListDevicePosturesByUser :many
SELECT * FROM authn_device_postures WHERE realm_id = sqlc.arg(realm_id) AND user_id = sqlc.arg(user_id) ORDER BY device_id;

-- name: DeleteDevicePosturesByUser :execrows
DELETE FROM authn_device_postures WHERE realm_id = sqlc.arg(realm_id) AND user_id = sqlc.arg(user_id);

-- name: DeleteDevicePosturesBySource :execrows
DELETE FROM authn_device_postures WHERE realm_id = sqlc.arg(realm_id) AND source = sqlc.arg(source);

-- name: CountDevicePostures :one
SELECT count(*) FROM authn_device_postures;

-- name: PurgeDevicePostures :execrows
DELETE FROM authn_device_postures WHERE (realm_id, user_id, device_id) IN (
    SELECT p.realm_id, p.user_id, p.device_id FROM authn_device_postures p ORDER BY p.realm_id, p.user_id, p.device_id LIMIT sqlc.arg(lim));
