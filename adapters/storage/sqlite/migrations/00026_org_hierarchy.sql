-- M7：Org 階層（design.md 11.4、ADR 0078）。祖先の一覧は書き込み時に計算する（閉包テーブル。depth 1 が親）。

-- +goose Up
ALTER TABLE orgs ADD COLUMN parent_org_id TEXT NOT NULL DEFAULT '';
CREATE INDEX orgs_parent ON orgs (realm_id, parent_org_id) WHERE parent_org_id <> '';
CREATE TABLE org_ancestors (
    realm_id    TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    ancestor_id TEXT NOT NULL,
    depth       INTEGER NOT NULL,
    PRIMARY KEY (realm_id, org_id, ancestor_id)
) STRICT;
CREATE INDEX org_ancestors_ancestor ON org_ancestors (realm_id, ancestor_id);

-- +goose Down
DROP TABLE org_ancestors;
DROP INDEX orgs_parent;
ALTER TABLE orgs DROP COLUMN parent_org_id;
