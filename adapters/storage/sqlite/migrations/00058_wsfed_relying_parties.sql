-- M9：WS-Federation の RP（iam が IdP。フィーチャー wsfed。ADR 0110）。realm は wtrealm、reply_urls は wreply の許可リスト。

-- +goose Up
CREATE TABLE authn_wsfed_relying_parties (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL,
    realm          TEXT NOT NULL, -- wtrealm
    name           TEXT NOT NULL,
    reply_urls     TEXT NOT NULL, -- JSON の配列
    token_type     TEXT NOT NULL, -- saml11 / saml20
    claims         BLOB NOT NULL, -- JSON
    token_lifetime INTEGER NOT NULL, -- 秒
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (realm_id, realm)
) STRICT;

CREATE INDEX authn_wsfed_relying_parties_list ON authn_wsfed_relying_parties (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_wsfed_relying_parties_list;
DROP TABLE authn_wsfed_relying_parties;
