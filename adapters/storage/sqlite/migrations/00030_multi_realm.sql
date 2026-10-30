-- M7：複数 realm（design.md 11.1、ADR 0083）。realm を指すホスト名と、realm の更新時刻。

-- +goose Up
ALTER TABLE authn_realms ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';

CREATE TABLE authn_realm_hosts (
    host     TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL,
    -- position はホストの順（最初のホストが issuer になる）。
    position INTEGER NOT NULL
) STRICT;

CREATE INDEX authn_realm_hosts_realm ON authn_realm_hosts (realm_id);
