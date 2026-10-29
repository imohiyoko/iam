-- M7：Org 専用 SSO（design.md 11.3、ADR 0077。SQLite の 00025）。

-- +goose Up
ALTER TABLE authn_connections ADD COLUMN owner_org_id TEXT COLLATE "C" NOT NULL DEFAULT '';
CREATE INDEX authn_connections_owner ON authn_connections (realm_id, owner_org_id) WHERE owner_org_id <> '';
CREATE INDEX authn_user_identities_connection ON authn_user_identities (realm_id, connection_id);

-- +goose Down
DROP INDEX authn_user_identities_connection;
DROP INDEX authn_connections_owner;
ALTER TABLE authn_connections DROP COLUMN owner_org_id;
