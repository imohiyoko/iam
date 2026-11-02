-- M9：ディレクトリ（LDAP / AD）の同期が管理する Group の対応（ADR 0102。SQLite の 00046）。

-- +goose Up
CREATE TABLE authn_directory_groups (
    realm_id      TEXT COLLATE "C" NOT NULL,
    connection_id TEXT COLLATE "C" NOT NULL,
    external_key  TEXT COLLATE "C" NOT NULL,
    group_id      TEXT COLLATE "C" NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, connection_id, external_key),
    UNIQUE (realm_id, group_id)
);

CREATE INDEX authn_user_identities_connection_id ON authn_user_identities (realm_id, connection_id, id) WHERE revoked_at IS NULL;

-- +goose Down
DROP INDEX authn_user_identities_connection_id;
DROP TABLE authn_directory_groups;
