-- M7：複数 realm（design.md 11.1、ADR 0083。SQLite の 00030）。

-- +goose Up
ALTER TABLE authn_realms ADD COLUMN updated_at TEXT COLLATE "C" NOT NULL DEFAULT '';

CREATE TABLE authn_realm_hosts (
    host     TEXT COLLATE "C" PRIMARY KEY,
    realm_id TEXT COLLATE "C" NOT NULL
);

CREATE INDEX authn_realm_hosts_realm ON authn_realm_hosts (realm_id);

-- +goose Down
DROP TABLE authn_realm_hosts;
ALTER TABLE authn_realms DROP COLUMN updated_at;
