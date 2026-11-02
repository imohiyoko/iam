-- M9：passkey を認証方式のポートに移す（ADR 0106。SQLite の 00050）。汎用の認証情報に、passkey の表にあった列を足す。

-- +goose Up
ALTER TABLE authn_credentials ADD COLUMN preferred_org_id TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_credentials ADD COLUMN reserve_lookup BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_credentials DROP COLUMN reserve_lookup;
ALTER TABLE authn_credentials DROP COLUMN preferred_org_id;
