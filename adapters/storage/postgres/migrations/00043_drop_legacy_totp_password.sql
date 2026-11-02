-- M9：TOTP とパスワードの方式専用の古い表と、移行の台帳の記録を消す（ADR 0101。SQLite の 00060）。

-- +goose Up
DROP TABLE authn_password_credentials;
DROP TABLE authn_totp_credentials;
DELETE FROM shared_installed_features WHERE feature = 'migration:authn_credentials_totp_password';

-- +goose Down
CREATE TABLE authn_totp_credentials (
    id                TEXT COLLATE "C" PRIMARY KEY,
    public_id         TEXT COLLATE "C" NOT NULL,
    realm_id          TEXT COLLATE "C" NOT NULL,
    user_id           TEXT COLLATE "C" NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    last_used_step    BIGINT NOT NULL,
    created_at        TEXT COLLATE "C" NOT NULL,
    revoked_at        TEXT COLLATE "C",
    revoke_reason     TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_totp_credentials_user ON authn_totp_credentials (realm_id, user_id);

CREATE TABLE authn_password_credentials (
    id            TEXT COLLATE "C" PRIMARY KEY,
    realm_id      TEXT COLLATE "C" NOT NULL,
    user_id       TEXT COLLATE "C" NOT NULL,
    hash          TEXT COLLATE "C" NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    revoked_at    TEXT COLLATE "C",
    revoke_reason TEXT COLLATE "C" NOT NULL
);

CREATE UNIQUE INDEX authn_password_credentials_active ON authn_password_credentials (realm_id, user_id) WHERE revoked_at IS NULL;
