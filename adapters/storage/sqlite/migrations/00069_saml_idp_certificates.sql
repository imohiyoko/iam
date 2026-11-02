-- M9：SAML 2.0 の IdP の署名の証明書（ADR 0115）。realm の ES256 の署名鍵ごとの自己署名の証明書を、作ったまま同じものを返すために置く。

-- +goose Up
CREATE TABLE authn_saml_idp_certificates (
    realm_id   TEXT NOT NULL,
    key_id     TEXT NOT NULL, -- signing_keys の ID
    der        BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (realm_id, key_id)
) STRICT;

-- +goose Down
DROP TABLE authn_saml_idp_certificates;
