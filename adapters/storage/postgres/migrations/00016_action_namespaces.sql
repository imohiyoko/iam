-- M8：操作の名前空間ごとの設定（ADR 0084。SQLite の 00033）。

-- +goose Up
CREATE TABLE authz_action_namespaces (
    realm_id   TEXT COLLATE "C" NOT NULL,
    name       TEXT COLLATE "C" NOT NULL,
    settings   BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, name)
);

-- +goose Down
DROP TABLE authz_action_namespaces;
