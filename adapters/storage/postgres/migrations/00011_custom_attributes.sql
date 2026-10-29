-- M7：カスタム属性（design.md 11.7、ADR 0080。SQLite の 00028）。

-- +goose Up
CREATE TABLE authn_attribute_defs (
    realm_id      TEXT COLLATE "C" NOT NULL,
    key           TEXT COLLATE "C" NOT NULL,
    type          TEXT COLLATE "C" NOT NULL,
    enum_values   TEXT COLLATE "C" NOT NULL,
    max_length    BIGINT NOT NULL,
    user_editable BIGINT NOT NULL,
    in_token      BIGINT NOT NULL,
    encrypted     BIGINT NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    updated_at    TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, key)
);
CREATE TABLE authn_user_attributes (
    realm_id   TEXT COLLATE "C" NOT NULL,
    user_id    TEXT COLLATE "C" NOT NULL,
    key        TEXT COLLATE "C" NOT NULL,
    value      BYTEA NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, user_id, key)
);
CREATE INDEX authn_user_attributes_key ON authn_user_attributes (realm_id, key);

-- +goose Down
DROP TABLE authn_user_attributes;
DROP TABLE authn_attribute_defs;
