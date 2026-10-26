-- M2：TOTP と2段階認証（design.md 3.1、4.1）。
-- TOTP の秘密はユーザーのデータ鍵で暗号化して置く（9.5）。last_used_step で同じ時間窓のコードの再利用を拒否する。
-- セッションに使える操作の制限（restriction）を足す。空は制限なし。

-- +goose Up
CREATE TABLE authn_totp_credentials (
    id                TEXT PRIMARY KEY,
    public_id         TEXT NOT NULL,
    realm_id          TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    last_used_step    INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    revoked_at        TEXT,
    revoke_reason     TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE INDEX authn_totp_credentials_user ON authn_totp_credentials (realm_id, user_id);

ALTER TABLE authn_sessions ADD COLUMN restriction TEXT NOT NULL DEFAULT '';
