-- M9：OpenID Shared Signals Framework の送信側のストリーム（フィーチャー ssf_transmitter。ADR 0118。SQLite の 00074）。
-- 監査ログを outbox にして、ストリームごとに処理した位置（cursor_seq）を持つ（ADR 0100 の購読と同じ形）。

-- +goose Up
CREATE TABLE authn_ssf_streams (
    id                       TEXT COLLATE "C" PRIMARY KEY,
    realm_id                 TEXT COLLATE "C" NOT NULL,
    service_account_id       TEXT COLLATE "C" NOT NULL,
    delivery_method          TEXT COLLATE "C" NOT NULL, -- push / poll
    endpoint_url             TEXT COLLATE "C" NOT NULL,
    authorization_ciphertext BYTEA NOT NULL,
    events_requested         TEXT COLLATE "C" NOT NULL, -- JSON の配列
    events_delivered         TEXT COLLATE "C" NOT NULL, -- JSON の配列
    description              TEXT COLLATE "C" NOT NULL,
    status                   TEXT COLLATE "C" NOT NULL, -- enabled / paused / disabled
    status_reason            TEXT COLLATE "C" NOT NULL,
    created_at               TEXT COLLATE "C" NOT NULL,
    updated_at               TEXT COLLATE "C" NOT NULL,
    cursor_seq               BIGINT NOT NULL,
    failures                 BIGINT NOT NULL,
    next_attempt_at          TEXT COLLATE "C",
    last_error               TEXT COLLATE "C" NOT NULL,
    last_delivered_at        TEXT COLLATE "C"
);
CREATE INDEX authn_ssf_streams_realm ON authn_ssf_streams (realm_id, created_at, id);

-- 対象（ユーザーの公開 ID）。送るのは対象に入っているユーザーのイベントだけ（default_subjects は NONE）。
CREATE TABLE authn_ssf_stream_subjects (
    stream_id  TEXT COLLATE "C" NOT NULL,
    realm_id   TEXT COLLATE "C" NOT NULL,
    subject    TEXT COLLATE "C" NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (stream_id, subject)
);
CREATE INDEX authn_ssf_stream_subjects_subject ON authn_ssf_stream_subjects (realm_id, subject);

-- poll（RFC 8936）のストリームで、受信側の確認を待つ SET。
CREATE TABLE authn_ssf_poll_events (
    stream_id  TEXT COLLATE "C" NOT NULL,
    realm_id   TEXT COLLATE "C" NOT NULL,
    jti        TEXT COLLATE "C" NOT NULL,
    seq        BIGINT NOT NULL,
    set_jwt    TEXT COLLATE "C" NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (stream_id, jti)
);
CREATE INDEX authn_ssf_poll_events_order ON authn_ssf_poll_events (stream_id, seq, jti);

-- +goose Down
DROP INDEX authn_ssf_poll_events_order;
DROP TABLE authn_ssf_poll_events;
DROP INDEX authn_ssf_stream_subjects_subject;
DROP TABLE authn_ssf_stream_subjects;
DROP INDEX authn_ssf_streams_realm;
DROP TABLE authn_ssf_streams;
