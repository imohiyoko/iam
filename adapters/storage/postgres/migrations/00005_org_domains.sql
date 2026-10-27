-- M7：Org のドメインの所有証明（design.md 11.3、ADR 0075。SQLite の 00022）。

-- +goose Up
CREATE TABLE org_domains (
    id          TEXT COLLATE "C" PRIMARY KEY,
    public_id   TEXT COLLATE "C" NOT NULL,
    realm_id    TEXT COLLATE "C" NOT NULL,
    org_id      TEXT COLLATE "C" NOT NULL,
    domain      TEXT COLLATE "C" NOT NULL,
    token       TEXT COLLATE "C" NOT NULL,
    verified_at TEXT COLLATE "C",
    checked_at  TEXT COLLATE "C",
    created_by  TEXT COLLATE "C" NOT NULL,
    created_at  TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, org_id, domain)
);

CREATE UNIQUE INDEX org_domains_verified ON org_domains (realm_id, domain) WHERE verified_at IS NOT NULL;

-- +goose Down
DROP TABLE org_domains;
