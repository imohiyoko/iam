-- M7：汎用サービスアカウント（design.md 11.2、ADR 0074）。Org への所属、有効期間、論理削除、client assertion の公開鍵、
-- client credentials で発行するアクセストークン（秘密は SHA-256 だけを持つ）。

-- +goose Up
ALTER TABLE authn_service_accounts ADD COLUMN org_id TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_service_accounts ADD COLUMN valid_from TEXT;
ALTER TABLE authn_service_accounts ADD COLUMN valid_until TEXT;
ALTER TABLE authn_service_accounts ADD COLUMN deleted_at TEXT;
ALTER TABLE authn_service_accounts ADD COLUMN created_by TEXT NOT NULL DEFAULT '';
CREATE INDEX authn_service_accounts_realm ON authn_service_accounts (realm_id, id);

ALTER TABLE authn_service_account_credentials ADD COLUMN public_key BLOB NOT NULL DEFAULT x'';
ALTER TABLE authn_service_account_credentials ADD COLUMN alg TEXT NOT NULL DEFAULT '';
CREATE INDEX authn_service_account_credentials_account ON authn_service_account_credentials (realm_id, service_account_id);

CREATE TABLE authn_service_account_tokens (
    id                 TEXT PRIMARY KEY,
    realm_id           TEXT NOT NULL,
    service_account_id TEXT NOT NULL,
    credential_id      TEXT NOT NULL,
    token_hash         BLOB NOT NULL,
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL
) STRICT;

CREATE INDEX authn_service_account_tokens_expires ON authn_service_account_tokens (expires_at);

-- +goose Down
DROP TABLE authn_service_account_tokens;
DROP INDEX authn_service_account_credentials_account;
ALTER TABLE authn_service_account_credentials DROP COLUMN alg;
ALTER TABLE authn_service_account_credentials DROP COLUMN public_key;
DROP INDEX authn_service_accounts_realm;
ALTER TABLE authn_service_accounts DROP COLUMN created_by;
ALTER TABLE authn_service_accounts DROP COLUMN deleted_at;
ALTER TABLE authn_service_accounts DROP COLUMN valid_until;
ALTER TABLE authn_service_accounts DROP COLUMN valid_from;
ALTER TABLE authn_service_accounts DROP COLUMN org_id;
