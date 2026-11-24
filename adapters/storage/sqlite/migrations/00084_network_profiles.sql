-- ユーザーが普段使う接続元のネットワークと、そこで使うブラウザの種類（フィーチャー session_binding。ADR 0128）。
-- ユーザーごとに 1 行。data は一覧で、ユーザーのデータ鍵で暗号化して置く（9.5）。

-- +goose Up
CREATE TABLE authn_network_profiles (
    realm_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    data       BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (realm_id, user_id)
) STRICT;

-- +goose Down
DROP TABLE authn_network_profiles;
