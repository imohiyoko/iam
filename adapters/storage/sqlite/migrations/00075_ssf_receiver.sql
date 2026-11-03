-- M9：OpenID Shared Signals Framework の受信側（フィーチャー ssf_receiver。ADR 0118）。
-- 信頼する外部の送信側の登録と、CAEP の device-compliance-change で受けた端末の準拠状態（device posture input）。

-- +goose Up
CREATE TABLE authn_ssf_transmitters (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    config          BLOB NOT NULL, -- JSON（authn/ssf の TransmitterConfig）
    push_token_hash BLOB NOT NULL,
    enabled         INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (realm_id, issuer)
) STRICT;
CREATE INDEX authn_ssf_transmitters_list ON authn_ssf_transmitters (realm_id, created_at, id);

CREATE TABLE authn_device_postures (
    realm_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL, -- 内部 ID
    device_id  TEXT NOT NULL,
    status     TEXT NOT NULL, -- compliant / not-compliant
    source     TEXT NOT NULL, -- authn_ssf_transmitters の ID
    event_at   TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (realm_id, user_id, device_id)
) STRICT;
CREATE INDEX authn_device_postures_source ON authn_device_postures (realm_id, source);

-- +goose Down
DROP INDEX authn_device_postures_source;
DROP TABLE authn_device_postures;
DROP INDEX authn_ssf_transmitters_list;
DROP TABLE authn_ssf_transmitters;
