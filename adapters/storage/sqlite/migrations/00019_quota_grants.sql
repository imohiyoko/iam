-- M6：Quota の付与（design.md 11.14）。上限は期間つきの付与の合算で求める。
-- external_ref は外部（課金など）の付与の参照で、空でなければ (org, quota_key) ごとに一意（冪等な上書き）。

-- +goose Up
CREATE TABLE org_quota_grants (
    id           TEXT PRIMARY KEY,
    public_id    TEXT NOT NULL,
    realm_id     TEXT NOT NULL,
    org_id       TEXT NOT NULL,
    quota_key    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    quantity     INTEGER NOT NULL,
    starts_at    TEXT NOT NULL,
    ends_at      TEXT,
    source       TEXT NOT NULL,
    external_ref TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE INDEX org_quota_grants_org ON org_quota_grants (realm_id, org_id, quota_key);
CREATE UNIQUE INDEX org_quota_grants_external_ref ON org_quota_grants (realm_id, org_id, quota_key, external_ref)
    WHERE external_ref <> '';
