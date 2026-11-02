-- M9：SAML 2.0 の SP の登録（iam が IdP。フィーチャー saml_idp。ADR 0115）。entity_id は SP の Entity ID、config は残りの設定（JSON）。

-- +goose Up
CREATE TABLE authn_saml_service_providers (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    entity_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    config     BLOB NOT NULL, -- JSON（authn/samlidp の Config）
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (realm_id, entity_id)
) STRICT;

CREATE INDEX authn_saml_service_providers_list ON authn_saml_service_providers (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_saml_service_providers_list;
DROP TABLE authn_saml_service_providers;
