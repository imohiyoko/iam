-- M2：メール + パスワード（フィーチャー password。design.md 3.1、4.1）。
-- ハッシュは argon2id の PHC 文字列。有効なパスワードはユーザーに1つまで（部分一意インデックス）。
-- スキーマはフィーチャーの有無で変えない（11.11）。

-- +goose Up
CREATE TABLE authn_password_credentials (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    hash          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    revoked_at    TEXT,
    revoke_reason TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX authn_password_credentials_active ON authn_password_credentials (realm_id, user_id) WHERE revoked_at IS NULL;
