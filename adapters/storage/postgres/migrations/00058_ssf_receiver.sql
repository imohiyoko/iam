-- M9：OpenID Shared Signals Framework の受信側（フィーチャー ssf_receiver。ADR 0118。SQLite の 00075）。
-- 信頼する外部の送信側の登録と、CAEP の device-compliance-change で受けた端末の準拠状態（device posture input）。

-- +goose Up
CREATE TABLE authn_ssf_transmitters (
    id              TEXT COLLATE "C" PRIMARY KEY,
    realm_id        TEXT COLLATE "C" NOT NULL,
    name            TEXT COLLATE "C" NOT NULL,
    issuer          TEXT COLLATE "C" NOT NULL,
    config          BYTEA NOT NULL, -- JSON（authn/ssf の TransmitterConfig）
    push_token_hash BYTEA NOT NULL,
    enabled         BIGINT NOT NULL,
    created_at      TEXT COLLATE "C" NOT NULL,
    updated_at      TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, issuer)
);
CREATE INDEX authn_ssf_transmitters_list ON authn_ssf_transmitters (realm_id, created_at, id);

CREATE TABLE authn_device_postures (
    realm_id   TEXT COLLATE "C" NOT NULL,
    user_id    TEXT COLLATE "C" NOT NULL, -- 内部 ID
    device_id  TEXT COLLATE "C" NOT NULL,
    status     TEXT COLLATE "C" NOT NULL, -- compliant / not-compliant
    source     TEXT COLLATE "C" NOT NULL, -- authn_ssf_transmitters の ID
    event_at   TEXT COLLATE "C" NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, user_id, device_id)
);
CREATE INDEX authn_device_postures_source ON authn_device_postures (realm_id, source);

-- +goose Down
DROP INDEX authn_device_postures_source;
DROP TABLE authn_device_postures;
DROP INDEX authn_ssf_transmitters_list;
DROP TABLE authn_ssf_transmitters;
