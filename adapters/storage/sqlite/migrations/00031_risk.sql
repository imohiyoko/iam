-- M8：認証の文脈とリスク（ADR 0084）。realm のリスクの種類の一覧と、セッションのリスクの点数。

-- +goose Up
CREATE TABLE authz_risk_types (
    realm_id    TEXT NOT NULL,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL,
    band_medium INTEGER NOT NULL,
    band_high   INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (realm_id, name)
) STRICT;

-- risk は種類 → 点数の JSON。空なら無し。
ALTER TABLE authn_sessions ADD COLUMN risk BLOB NOT NULL DEFAULT x'';

-- +goose Down
ALTER TABLE authn_sessions DROP COLUMN risk;
DROP TABLE authz_risk_types;
