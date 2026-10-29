-- M7：Group のネスト（design.md 11.5、ADR 0079）。Group を含む Group の一覧は書き込み時に計算する
-- （閉包テーブル。depth は最も長い経路の段数で、1 が直接）。Group としての所属は authz_group_members の member_type = 'group'。

-- +goose Up
CREATE TABLE authz_group_closure (
    realm_id    TEXT NOT NULL,
    group_id    TEXT NOT NULL,
    ancestor_id TEXT NOT NULL,
    depth       INTEGER NOT NULL,
    PRIMARY KEY (realm_id, group_id, ancestor_id)
) STRICT;
CREATE INDEX authz_group_closure_ancestor ON authz_group_closure (realm_id, ancestor_id);

-- +goose Down
DROP TABLE authz_group_closure;
