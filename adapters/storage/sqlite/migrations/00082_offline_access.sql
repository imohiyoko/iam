-- M11：offline_access（ログインの系列から切り離した認可。フィーチャー offline_access。ADR 0126）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN offline_access INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authn_oidc_grants ADD COLUMN offline INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authn_oidc_grants ADD COLUMN auth_credential_ids TEXT NOT NULL DEFAULT '[]'; -- JSON の配列
CREATE INDEX authn_oidc_grants_offline ON authn_oidc_grants (realm_id, user_id) WHERE offline <> 0;

-- +goose Down
DROP INDEX authn_oidc_grants_offline;
ALTER TABLE authn_oidc_grants DROP COLUMN auth_credential_ids;
ALTER TABLE authn_oidc_grants DROP COLUMN offline;
ALTER TABLE authn_clients DROP COLUMN offline_access;
