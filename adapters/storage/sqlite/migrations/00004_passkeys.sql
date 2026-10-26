-- M2：passkey（design.md 3.1、4.6、9.4）。
-- 公開鍵は COSE の形で持つ（秘密ではないので暗号化しない）。無効化は削除ではなく revoked_at を記録する。
-- 無効化した credential_id は authn_revoked_passkey_credentials にも残し、passkey の行が消えた後も再登録を拒否する。

-- +goose Up
CREATE TABLE authn_passkeys (
    id            TEXT PRIMARY KEY,
    public_id     TEXT NOT NULL,
    realm_id      TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    credential_id BLOB NOT NULL,
    public_key    BLOB NOT NULL,
    alg           INTEGER NOT NULL,
    sign_count    INTEGER NOT NULL,
    flags         INTEGER NOT NULL,
    aaguid        BLOB NOT NULL,
    transports    TEXT NOT NULL,
    name          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT,
    revoke_reason TEXT NOT NULL,
    UNIQUE (realm_id, credential_id),
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE INDEX authn_passkeys_user ON authn_passkeys (realm_id, user_id);

CREATE TABLE authn_revoked_passkey_credentials (
    realm_id      TEXT NOT NULL,
    credential_id BLOB NOT NULL,
    revoked_at    TEXT NOT NULL,
    PRIMARY KEY (realm_id, credential_id)
) STRICT;
