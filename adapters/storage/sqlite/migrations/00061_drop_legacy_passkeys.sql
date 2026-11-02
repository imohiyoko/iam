-- M9：passkey の方式専用の古い表を消す（ADR 0106）。passkey は authn_credentials（方式 passkey）に、無効化した credential ID は
-- authn_retired_credential_lookups にあり、未公開のため古い表からの起動時の移行も持たない。移行の台帳の記録（migration:…）も消す。

-- +goose Up
DROP TABLE authn_revoked_passkey_credentials;
DROP TABLE authn_passkeys;
DELETE FROM shared_installed_features WHERE feature = 'migration:authn_credentials_passkey';

-- +goose Down
CREATE TABLE authn_passkeys (
    id                 TEXT PRIMARY KEY,
    public_id          TEXT NOT NULL,
    realm_id           TEXT NOT NULL,
    user_id            TEXT NOT NULL,
    credential_id      BLOB NOT NULL,
    public_key         BLOB NOT NULL,
    alg                INTEGER NOT NULL,
    sign_count         INTEGER NOT NULL,
    flags              INTEGER NOT NULL,
    aaguid             BLOB NOT NULL,
    transports         TEXT NOT NULL,
    name               TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    last_used_at       TEXT,
    revoked_at         TEXT,
    revoke_reason      TEXT NOT NULL,
    preferred_org_id   TEXT NOT NULL DEFAULT '',
    user_handle        BLOB NOT NULL DEFAULT x'',
    attestation_format TEXT NOT NULL DEFAULT '',
    attested           INTEGER NOT NULL DEFAULT 0,
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
