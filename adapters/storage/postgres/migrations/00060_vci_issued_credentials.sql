-- M9：OpenID4VCI で発行した資格情報の記録（フィーチャー openid4vci。ADR 0119。SQLite の 00077）。

-- +goose Up
CREATE TABLE vci_issued_credentials (
    id               TEXT COLLATE "C" PRIMARY KEY,
    realm_id         TEXT COLLATE "C" NOT NULL,
    user_id          TEXT COLLATE "C" NOT NULL,
    configuration_id TEXT COLLATE "C" NOT NULL,
    status_index     BIGINT NOT NULL,
    holder_jkt       TEXT COLLATE "C" NOT NULL,
    issued_at        TEXT COLLATE "C" NOT NULL,
    expires_at       TEXT COLLATE "C" NOT NULL,
    revoked_at       TEXT COLLATE "C",
    UNIQUE (realm_id, status_index)
);

CREATE INDEX vci_issued_credentials_user ON vci_issued_credentials (realm_id, user_id, issued_at);
CREATE INDEX vci_issued_credentials_expires ON vci_issued_credentials (realm_id, expires_at);

-- +goose Down
DROP INDEX vci_issued_credentials_expires;
DROP INDEX vci_issued_credentials_user;
DROP TABLE vci_issued_credentials;
