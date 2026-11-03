-- M9：OpenID4VCI で発行した資格情報の記録（フィーチャー openid4vci。ADR 0119）。クレームの値は持たない。status_index は
-- realm の status list（Token Status List）の番号で、revoked_at があれば失効（値 1）。期限を過ぎた行は消す。

-- +goose Up
CREATE TABLE vci_issued_credentials (
    id               TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    configuration_id TEXT NOT NULL,
    status_index     INTEGER NOT NULL,
    holder_jkt       TEXT NOT NULL,
    issued_at        TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    revoked_at       TEXT,
    UNIQUE (realm_id, status_index)
) STRICT;

CREATE INDEX vci_issued_credentials_user ON vci_issued_credentials (realm_id, user_id, issued_at);
CREATE INDEX vci_issued_credentials_expires ON vci_issued_credentials (realm_id, expires_at);

-- +goose Down
DROP INDEX vci_issued_credentials_expires;
DROP INDEX vci_issued_credentials_user;
DROP TABLE vci_issued_credentials;
