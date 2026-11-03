-- M9：OpenID4VCI の資格情報の定義（iam が発行者。フィーチャー openid4vci。ADR 0119）。configuration_id はメタデータのキー、
-- scope は Authorization Code Flow のスコープ（空なら無し）、config は残りの設定（JSON）。

-- +goose Up
CREATE TABLE vci_credential_configurations (
    id               TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL,
    configuration_id TEXT NOT NULL,
    scope            TEXT NOT NULL,
    config           BLOB NOT NULL, -- JSON（authn/vci の Config）
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE (realm_id, configuration_id)
) STRICT;

CREATE INDEX vci_credential_configurations_list ON vci_credential_configurations (realm_id, created_at, id);

-- +goose Down
DROP INDEX vci_credential_configurations_list;
DROP TABLE vci_credential_configurations;
