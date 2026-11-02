-- M9：汎用の認証情報の検索キーを作ったインデックス鍵の ID（ADR 0092、0103）。
-- インデックス鍵を切り替えた後も、前の鍵で作った検索キー（X.509 の証明書の指紋など）で引けるようにする。

-- +goose Up
ALTER TABLE authn_credentials ADD COLUMN lookup_key_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_credentials DROP COLUMN lookup_key_id;
