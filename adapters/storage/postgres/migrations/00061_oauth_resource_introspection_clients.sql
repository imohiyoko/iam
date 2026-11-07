-- M11：リソースに向けたトークンをイントロスペクションしてよい連携先（ADR 0120。SQLite の 00078）。

-- +goose Up
ALTER TABLE authn_oauth_resources ADD COLUMN introspection_clients TEXT COLLATE "C" NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE authn_oauth_resources DROP COLUMN introspection_clients;
