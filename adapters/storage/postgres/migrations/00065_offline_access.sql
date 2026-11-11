-- M11：offline_access（ADR 0126。SQLite の 00082）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN offline_access BIGINT NOT NULL DEFAULT 0;
ALTER TABLE authn_oidc_grants ADD COLUMN offline BIGINT NOT NULL DEFAULT 0;
ALTER TABLE authn_oidc_grants ADD COLUMN auth_credential_ids TEXT NOT NULL DEFAULT '[]';
CREATE INDEX authn_oidc_grants_offline ON authn_oidc_grants (realm_id, user_id) WHERE offline <> 0;

-- +goose Down
DROP INDEX authn_oidc_grants_offline;
ALTER TABLE authn_oidc_grants DROP COLUMN auth_credential_ids;
ALTER TABLE authn_oidc_grants DROP COLUMN offline;
ALTER TABLE authn_clients DROP COLUMN offline_access;
