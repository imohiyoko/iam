-- M9：汎用の認証情報の検索キーを作ったインデックス鍵の ID（ADR 0092、0103。SQLite の 00047）。

-- +goose Up
ALTER TABLE authn_credentials ADD COLUMN lookup_key_id TEXT COLLATE "C" NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_credentials DROP COLUMN lookup_key_id;
