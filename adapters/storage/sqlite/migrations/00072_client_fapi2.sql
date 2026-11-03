-- M11：連携先ごとに FAPI 2.0 Security Profile を強いるか（フィーチャー fapi2。ADR 0117）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN fapi2_security_profile INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN fapi2_security_profile;
