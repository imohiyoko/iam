-- M9：ディレクトリ（LDAP / AD）の同期が作り、ユーザーの所属を管理する Group の対応（ADR 0102）。
-- 同期はここに載っている Group の所属だけを変える。external_key はディレクトリでの Group の識別子（正規化した DN）。

-- +goose Up
CREATE TABLE authn_directory_groups (
    realm_id      TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    external_key  TEXT NOT NULL,
    group_id      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (realm_id, connection_id, external_key),
    UNIQUE (realm_id, group_id)
) STRICT;

CREATE INDEX authn_user_identities_connection_id ON authn_user_identities (realm_id, connection_id, id) WHERE revoked_at IS NULL;

-- +goose Down
DROP INDEX authn_user_identities_connection_id;
DROP TABLE authn_directory_groups;
