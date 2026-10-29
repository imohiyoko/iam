-- M6：Quota の付与（design.md 11.14。SQLite の 00019）。

-- +goose Up
CREATE TABLE org_quota_grants (
    id           TEXT COLLATE "C" PRIMARY KEY,
    public_id    TEXT COLLATE "C" NOT NULL,
    realm_id     TEXT COLLATE "C" NOT NULL,
    org_id       TEXT COLLATE "C" NOT NULL,
    quota_key    TEXT COLLATE "C" NOT NULL,
    kind         TEXT COLLATE "C" NOT NULL,
    quantity     BIGINT NOT NULL,
    starts_at    TEXT COLLATE "C" NOT NULL,
    ends_at      TEXT COLLATE "C",
    source       TEXT COLLATE "C" NOT NULL,
    external_ref TEXT COLLATE "C" NOT NULL,
    created_by   TEXT COLLATE "C" NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    updated_at   TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX org_quota_grants_org ON org_quota_grants (realm_id, org_id, quota_key);

CREATE UNIQUE INDEX org_quota_grants_external_ref ON org_quota_grants (realm_id, org_id, quota_key, external_ref)
    WHERE external_ref <> '';

-- +goose Down
DROP TABLE org_quota_grants;
