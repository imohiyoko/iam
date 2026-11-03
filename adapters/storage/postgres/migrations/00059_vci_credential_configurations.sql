-- M9：OpenID4VCI の資格情報の定義（フィーチャー openid4vci。ADR 0119。SQLite の 00076）。

-- +goose Up
CREATE TABLE vci_credential_configurations (
    id               TEXT COLLATE "C" PRIMARY KEY,
    realm_id         TEXT COLLATE "C" NOT NULL,
    configuration_id TEXT COLLATE "C" NOT NULL,
    scope            TEXT COLLATE "C" NOT NULL,
    config           BYTEA NOT NULL,
    created_at       TEXT COLLATE "C" NOT NULL,
    updated_at       TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, configuration_id)
);

CREATE INDEX vci_credential_configurations_list ON vci_credential_configurations (realm_id, created_at, id);

-- +goose Down
DROP INDEX vci_credential_configurations_list;
DROP TABLE vci_credential_configurations;
