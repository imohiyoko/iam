-- M9：WS-Federation の RP（フィーチャー wsfed。ADR 0110。SQLite の 00058）。

-- +goose Up
CREATE TABLE authn_wsfed_relying_parties (
    id             TEXT COLLATE "C" PRIMARY KEY,
    realm_id       TEXT COLLATE "C" NOT NULL,
    realm          TEXT COLLATE "C" NOT NULL,
    name           TEXT COLLATE "C" NOT NULL,
    reply_urls     TEXT COLLATE "C" NOT NULL,
    token_type     TEXT COLLATE "C" NOT NULL,
    claims         BYTEA NOT NULL,
    token_lifetime BIGINT NOT NULL,
    created_at     TEXT COLLATE "C" NOT NULL,
    updated_at     TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, realm)
);

CREATE INDEX authn_wsfed_relying_parties_list ON authn_wsfed_relying_parties (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_wsfed_relying_parties_list;
DROP TABLE authn_wsfed_relying_parties;
