-- M9：TOTP とパスワードの方式専用の古い表を消す（ADR 0101）。TOTP とパスワードは authn_credentials（方式 totp・password）にあり、
-- 未公開のため古い表からの起動時の移行も持たない。移行の台帳の記録（migration:…）も消す。

-- +goose Up
DROP TABLE authn_password_credentials;
DROP TABLE authn_totp_credentials;
DELETE FROM shared_installed_features WHERE feature = 'migration:authn_credentials_totp_password';

-- +goose Down
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
