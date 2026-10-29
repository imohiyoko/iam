-- M7：汎用サービスアカウント（design.md 11.2、ADR 0074。SQLite の 00021）。

-- +goose Up
ALTER TABLE authn_service_accounts ADD COLUMN org_id TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_service_accounts ADD COLUMN valid_from TEXT COLLATE "C";
ALTER TABLE authn_service_accounts ADD COLUMN valid_until TEXT COLLATE "C";
ALTER TABLE authn_service_accounts ADD COLUMN deleted_at TEXT COLLATE "C";
ALTER TABLE authn_service_accounts ADD COLUMN created_by TEXT COLLATE "C" NOT NULL DEFAULT '';
CREATE INDEX authn_service_accounts_realm ON authn_service_accounts (realm_id, id);

ALTER TABLE authn_service_account_credentials ADD COLUMN public_key BYTEA NOT NULL DEFAULT ''::bytea;
ALTER TABLE authn_service_account_credentials ADD COLUMN alg TEXT COLLATE "C" NOT NULL DEFAULT '';
CREATE INDEX authn_service_account_credentials_account ON authn_service_account_credentials (realm_id, service_account_id);

CREATE TABLE authn_service_account_tokens (
    id                 TEXT COLLATE "C" PRIMARY KEY,
    realm_id           TEXT COLLATE "C" NOT NULL,
    service_account_id TEXT COLLATE "C" NOT NULL,
    credential_id      TEXT COLLATE "C" NOT NULL,
    token_hash         BYTEA NOT NULL,
    created_at         TEXT COLLATE "C" NOT NULL,
    expires_at         TEXT COLLATE "C" NOT NULL
);

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
