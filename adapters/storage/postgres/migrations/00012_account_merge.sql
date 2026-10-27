-- M7：アカウント統合（design.md 11.6、ADR 0082。SQLite の 00029）。

-- +goose Up
ALTER TABLE authn_users ADD COLUMN merged_into TEXT COLLATE "C";
ALTER TABLE authn_passkeys ADD COLUMN user_handle BYTEA NOT NULL DEFAULT '\x';

-- +goose Down
ALTER TABLE authn_passkeys DROP COLUMN user_handle;
ALTER TABLE authn_users DROP COLUMN merged_into;
