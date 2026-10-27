-- M7：Org 階層（design.md 11.4、ADR 0078。SQLite の 00026）。

-- +goose Up
ALTER TABLE orgs ADD COLUMN parent_org_id TEXT COLLATE "C" NOT NULL DEFAULT '';
CREATE INDEX orgs_parent ON orgs (realm_id, parent_org_id) WHERE parent_org_id <> '';
CREATE TABLE org_ancestors (
    realm_id    TEXT COLLATE "C" NOT NULL,
    org_id      TEXT COLLATE "C" NOT NULL,
    ancestor_id TEXT COLLATE "C" NOT NULL,
    depth       BIGINT NOT NULL,
    PRIMARY KEY (realm_id, org_id, ancestor_id)
);
CREATE INDEX org_ancestors_ancestor ON org_ancestors (realm_id, ancestor_id);

-- +goose Down
DROP TABLE org_ancestors;
DROP INDEX orgs_parent;
ALTER TABLE orgs DROP COLUMN parent_org_id;
