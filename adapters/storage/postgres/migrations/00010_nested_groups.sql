-- M7：Group のネスト（design.md 11.5、ADR 0079。SQLite の 00027）。

-- +goose Up
CREATE TABLE authz_group_closure (
    realm_id    TEXT COLLATE "C" NOT NULL,
    group_id    TEXT COLLATE "C" NOT NULL,
    ancestor_id TEXT COLLATE "C" NOT NULL,
    depth       BIGINT NOT NULL,
    PRIMARY KEY (realm_id, group_id, ancestor_id)
);
CREATE INDEX authz_group_closure_ancestor ON authz_group_closure (realm_id, ancestor_id);

-- +goose Down
DROP TABLE authz_group_closure;
