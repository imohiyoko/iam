-- マイグレーションは前進のみ（design.md 2.5）。Down は書かない。
-- テーブル名の接頭辞でモジュールを分ける（authn_ / authz_ / shared_。design.md 2.2）。
-- モジュールをまたぐ外部キーは張らない。
-- 時刻は UTC の RFC 3339（ナノ秒まで固定長）で保存し、文字列の順が時刻の順になるようにする。

-- +goose Up
CREATE TABLE authn_realms (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    settings   BLOB NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE authn_user_data_keys (
    user_id     TEXT PRIMARY KEY,
    wrapped_key BLOB NOT NULL,
    key_id      TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE shared_installed_features (
    feature      TEXT PRIMARY KEY,
    state        TEXT NOT NULL,
    data_version INTEGER NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE TABLE shared_audit_events (
    seq       INTEGER PRIMARY KEY,
    realm_id  TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL,
    payload   BLOB NOT NULL
) STRICT;

CREATE INDEX shared_audit_events_realm ON shared_audit_events (realm_id, seq);

CREATE TABLE shared_outbox (
    id           TEXT PRIMARY KEY,
    topic        TEXT NOT NULL,
    payload      BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    delivered_at TEXT
) STRICT;

CREATE INDEX shared_outbox_pending ON shared_outbox (topic, created_at, id) WHERE delivered_at IS NULL;
