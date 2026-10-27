-- M7：Org のドメインの所有証明（design.md 11.3、ADR 0075）。証明済みのドメインは realm で1つの Org だけが持てる。

-- +goose Up
CREATE TABLE org_domains (
    id          TEXT PRIMARY KEY,
    public_id   TEXT NOT NULL,
    realm_id    TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    domain      TEXT NOT NULL,
    token       TEXT NOT NULL,
    verified_at TEXT,
    checked_at  TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, org_id, domain)
) STRICT;

CREATE UNIQUE INDEX org_domains_verified ON org_domains (realm_id, domain) WHERE verified_at IS NOT NULL;

-- +goose Down
DROP TABLE org_domains;
