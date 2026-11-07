-- 連携先の権限のカタログ（ADR 0121。SQLite の 00079）。permissions は JSON（[{"name", "description"}]、名前の順）。

-- +goose Up
CREATE TABLE authz_permission_catalogs (
    realm_id     TEXT COLLATE "C" NOT NULL,
    prefix       TEXT COLLATE "C" NOT NULL,
    display_name TEXT NOT NULL,
    permissions  BYTEA NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    updated_at   TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, prefix)
);

-- +goose Down
DROP TABLE authz_permission_catalogs;
