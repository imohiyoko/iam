-- M11：連携先ごとの FAPI 2.0 Security Profile（ADR 0117。SQLite の 00072）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN fapi2_security_profile BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN fapi2_security_profile;
