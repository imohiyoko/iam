-- 連携先の権限のカタログ（ADR 0121）。permissions は JSON（[{"name", "description"}]、名前の順）。

-- +goose Up
CREATE TABLE authz_permission_catalogs (
    realm_id     TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    display_name TEXT NOT NULL,
    permissions  BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (realm_id, prefix)
) STRICT;

-- +goose Down
DROP TABLE authz_permission_catalogs;
