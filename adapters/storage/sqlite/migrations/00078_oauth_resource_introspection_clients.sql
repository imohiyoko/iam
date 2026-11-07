-- M11：リソースに向けたトークンをイントロスペクションしてよい連携先（client_id の JSON の配列）。空の配列ならどの連携先でもよい
-- （ADR 0120）。

-- +goose Up
ALTER TABLE authn_oauth_resources ADD COLUMN introspection_clients TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE authn_oauth_resources DROP COLUMN introspection_clients;
