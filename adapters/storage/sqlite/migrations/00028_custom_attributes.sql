-- M7：カスタム属性（design.md 11.7、ADR 0080）。値は JSON か、その暗号文（定義の encrypted）。

-- +goose Up
CREATE TABLE authn_attribute_defs (
    realm_id      TEXT NOT NULL,
    key           TEXT NOT NULL,
    type          TEXT NOT NULL,
    enum_values   TEXT NOT NULL, -- JSON の配列
    max_length    INTEGER NOT NULL,
    user_editable INTEGER NOT NULL,
    in_token      INTEGER NOT NULL,
    encrypted     INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (realm_id, key)
) STRICT;
CREATE TABLE authn_user_attributes (
    realm_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (realm_id, user_id, key)
) STRICT;
CREATE INDEX authn_user_attributes_key ON authn_user_attributes (realm_id, key);

-- +goose Down
DROP TABLE authn_user_attributes;
DROP TABLE authn_attribute_defs;
