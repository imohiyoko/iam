-- M7：Org 管理ユーザー（design.md 11.3、ADR 0076。SQLite の 00023）。

-- +goose Up
ALTER TABLE authn_users ADD COLUMN managed_org_id TEXT COLLATE "C";
ALTER TABLE authn_users ADD COLUMN managed_at TEXT COLLATE "C";
ALTER TABLE memberships ADD COLUMN management_requested_at TEXT COLLATE "C";

CREATE INDEX authn_users_managed_org ON authn_users (realm_id, managed_org_id) WHERE managed_org_id IS NOT NULL;

-- +goose Down
DROP INDEX authn_users_managed_org;
ALTER TABLE memberships DROP COLUMN management_requested_at;
ALTER TABLE authn_users DROP COLUMN managed_at;
ALTER TABLE authn_users DROP COLUMN managed_org_id;
