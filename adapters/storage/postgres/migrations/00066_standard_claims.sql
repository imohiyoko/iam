-- M11：カスタム属性から OIDC の標準クレームへの対応付け（ADR 0127。SQLite の 00083）。

-- +goose Up
ALTER TABLE authn_attribute_defs ADD COLUMN claim TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX authn_attribute_defs_claim ON authn_attribute_defs (realm_id, claim) WHERE claim <> '';

-- +goose Down
DROP INDEX authn_attribute_defs_claim;
ALTER TABLE authn_attribute_defs DROP COLUMN claim;
