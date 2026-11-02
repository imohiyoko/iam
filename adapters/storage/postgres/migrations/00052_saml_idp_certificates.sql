-- M9：SAML 2.0 の IdP の署名の証明書（ADR 0115。SQLite の 00069）。

-- +goose Up
CREATE TABLE authn_saml_idp_certificates (
    realm_id   TEXT COLLATE "C" NOT NULL,
    key_id     TEXT COLLATE "C" NOT NULL,
    der        BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, key_id)
);

-- +goose Down
DROP TABLE authn_saml_idp_certificates;
