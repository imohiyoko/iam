-- M8：認証方式のプラグインの汎用の認証情報（ADR 0090、0092）。
-- data は方式固有のデータで、ユーザーのデータ鍵で暗号化して置く（9.5）。Storage は方式を知らない。
-- lookup は方式が宣言した検索キーのブラインドインデックス（HMAC。任意）。無効化していないものの中で realm と方式ごとに一意。

-- +goose Up
CREATE TABLE authn_credentials (
    id            TEXT PRIMARY KEY,
    public_id     TEXT NOT NULL,
    realm_id      TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    method        TEXT NOT NULL,
    lookup        BLOB,
    data          BLOB NOT NULL,
    data_version  INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT,
    revoke_reason TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE INDEX authn_credentials_user ON authn_credentials (realm_id, user_id);
CREATE INDEX authn_credentials_method ON authn_credentials (method);
CREATE UNIQUE INDEX authn_credentials_lookup ON authn_credentials (realm_id, method, lookup)
    WHERE lookup IS NOT NULL AND revoked_at IS NULL;

-- +goose Down
DROP TABLE authn_credentials;
