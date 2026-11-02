-- M9：passkey の方式専用の古い表と、移行の台帳の記録を消す（ADR 0106。SQLite の 00061）。

-- +goose Up
DROP TABLE authn_revoked_passkey_credentials;
DROP TABLE authn_passkeys;
DELETE FROM shared_installed_features WHERE feature = 'migration:authn_credentials_passkey';

-- +goose Down
CREATE TABLE authn_passkeys (
    id                 TEXT COLLATE "C" PRIMARY KEY,
    public_id          TEXT COLLATE "C" NOT NULL,
    realm_id           TEXT COLLATE "C" NOT NULL,
    user_id            TEXT COLLATE "C" NOT NULL,
    credential_id      BYTEA NOT NULL,
    public_key         BYTEA NOT NULL,
    alg                BIGINT NOT NULL,
    sign_count         BIGINT NOT NULL,
    flags              BIGINT NOT NULL,
    aaguid             BYTEA NOT NULL,
    transports         TEXT COLLATE "C" NOT NULL,
    name               TEXT COLLATE "C" NOT NULL,
    created_at         TEXT COLLATE "C" NOT NULL,
    last_used_at       TEXT COLLATE "C",
    revoked_at         TEXT COLLATE "C",
    revoke_reason      TEXT COLLATE "C" NOT NULL,
    preferred_org_id   TEXT COLLATE "C" NOT NULL DEFAULT '',
    user_handle        BYTEA NOT NULL DEFAULT '\x',
    attestation_format TEXT COLLATE "C" NOT NULL DEFAULT '',
    attested           BIGINT NOT NULL DEFAULT 0,
    UNIQUE (realm_id, credential_id),
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_passkeys_user ON authn_passkeys (realm_id, user_id);

CREATE TABLE authn_revoked_passkey_credentials (
    realm_id      TEXT COLLATE "C" NOT NULL,
    credential_id BYTEA NOT NULL,
    revoked_at    TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, credential_id)
);
