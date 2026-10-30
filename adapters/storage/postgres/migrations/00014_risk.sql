-- M8：認証の文脈とリスク（ADR 0084。SQLite の 00031）。

-- +goose Up
CREATE TABLE authz_risk_types (
    realm_id    TEXT COLLATE "C" NOT NULL,
    name        TEXT COLLATE "C" NOT NULL,
    enabled     BIGINT NOT NULL,
    band_medium BIGINT NOT NULL,
    band_high   BIGINT NOT NULL,
    created_at  TEXT COLLATE "C" NOT NULL,
    updated_at  TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, name)
);

ALTER TABLE authn_sessions ADD COLUMN risk BYTEA NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_sessions DROP COLUMN risk;
DROP TABLE authz_risk_types;
