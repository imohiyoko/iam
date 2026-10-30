-- M8：操作の名前空間ごとの設定（ADR 0084）。要件と段階の境界（JSON。形は authz/check の Namespace）。

-- +goose Up
CREATE TABLE authz_action_namespaces (
    realm_id   TEXT NOT NULL,
    name       TEXT NOT NULL,
    settings   BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (realm_id, name)
) STRICT;

-- +goose Down
DROP TABLE authz_action_namespaces;
