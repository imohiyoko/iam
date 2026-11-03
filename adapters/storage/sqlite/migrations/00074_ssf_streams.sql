-- M9：OpenID Shared Signals Framework の送信側のストリーム（フィーチャー ssf_transmitter。ADR 0118）。
-- 監査ログを outbox にして、ストリームごとに処理した位置（cursor_seq）を持つ（ADR 0100 の購読と同じ形）。

-- +goose Up
CREATE TABLE authn_ssf_streams (
    id                       TEXT PRIMARY KEY,
    realm_id                 TEXT NOT NULL,
    service_account_id       TEXT NOT NULL,
    delivery_method          TEXT NOT NULL, -- push / poll
    endpoint_url             TEXT NOT NULL,
    authorization_ciphertext BLOB NOT NULL,
    events_requested         TEXT NOT NULL, -- JSON の配列
    events_delivered         TEXT NOT NULL, -- JSON の配列
    description              TEXT NOT NULL,
    status                   TEXT NOT NULL, -- enabled / paused / disabled
    status_reason            TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    cursor_seq               INTEGER NOT NULL,
    failures                 INTEGER NOT NULL,
    next_attempt_at          TEXT,
    last_error               TEXT NOT NULL,
    last_delivered_at        TEXT
) STRICT;
CREATE INDEX authn_ssf_streams_realm ON authn_ssf_streams (realm_id, created_at, id);

-- 対象（ユーザーの公開 ID）。送るのは対象に入っているユーザーのイベントだけ（default_subjects は NONE）。
CREATE TABLE authn_ssf_stream_subjects (
    stream_id  TEXT NOT NULL,
    realm_id   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (stream_id, subject)
) STRICT;
CREATE INDEX authn_ssf_stream_subjects_subject ON authn_ssf_stream_subjects (realm_id, subject);

-- poll（RFC 8936）のストリームで、受信側の確認を待つ SET。
CREATE TABLE authn_ssf_poll_events (
    stream_id  TEXT NOT NULL,
    realm_id   TEXT NOT NULL,
    jti        TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    set_jwt    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (stream_id, jti)
) STRICT;
CREATE INDEX authn_ssf_poll_events_order ON authn_ssf_poll_events (stream_id, seq, jti);

-- +goose Down
DROP INDEX authn_ssf_poll_events_order;
DROP TABLE authn_ssf_poll_events;
DROP INDEX authn_ssf_stream_subjects_subject;
DROP TABLE authn_ssf_stream_subjects;
DROP INDEX authn_ssf_streams_realm;
DROP TABLE authn_ssf_streams;
