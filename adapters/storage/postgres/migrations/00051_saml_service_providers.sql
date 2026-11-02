-- M9：SAML 2.0 の SP の登録（フィーチャー saml_idp。ADR 0115。SQLite の 00068）。

-- +goose Up
CREATE TABLE authn_saml_service_providers (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    entity_id  TEXT COLLATE "C" NOT NULL,
    name       TEXT COLLATE "C" NOT NULL,
    config     BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, entity_id)
);

CREATE INDEX authn_saml_service_providers_list ON authn_saml_service_providers (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_saml_service_providers_list;
DROP TABLE authn_saml_service_providers;
