-- M4：認可（design.md 3.2、ADR 0064）。独自のロール、範囲つきのロール付与、Group と所属。
-- 組み込みのロールはコードにあり、付与の role には名前を、独自のロールは roles の内部 ID を入れる。
-- 既存の付与には外部 ID を振る（外部 ID の形 "<接頭辞>_<26 文字>" に合わせた乱数）。

-- +goose Up
CREATE TABLE authz_role_bindings_new (
    id             TEXT PRIMARY KEY,
    public_id      TEXT NOT NULL,
    realm_id       TEXT NOT NULL,
    role           TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id   TEXT NOT NULL,
    org_id         TEXT NOT NULL, -- 空なら realm 全体
    resource_type  TEXT NOT NULL, -- 空なら Org（realm）全体
    resource_id    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, role, principal_type, principal_id, org_id, resource_type, resource_id)
) STRICT;

INSERT INTO authz_role_bindings_new (id, public_id, realm_id, role, principal_type, principal_id, org_id, resource_type, resource_id, created_at)
SELECT id, 'rbd_' || char(48 + abs(random() % 8)) || substr(hex(randomblob(13)), 1, 25), realm_id, role, principal_type, principal_id, org_id, '', '', created_at
FROM authz_role_bindings;

DROP TABLE authz_role_bindings;
ALTER TABLE authz_role_bindings_new RENAME TO authz_role_bindings;
CREATE INDEX authz_role_bindings_principal ON authz_role_bindings (realm_id, principal_type, principal_id);
CREATE INDEX authz_role_bindings_org ON authz_role_bindings (realm_id, org_id);
CREATE INDEX authz_role_bindings_role ON authz_role_bindings (realm_id, role);

CREATE TABLE authz_roles (
    id          TEXT PRIMARY KEY,
    public_id   TEXT NOT NULL,
    realm_id    TEXT NOT NULL,
    org_id      TEXT NOT NULL, -- 空なら realm 共通
    name        TEXT NOT NULL,
    permissions TEXT NOT NULL, -- JSON の配列（role_permissions）
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, org_id, name)
) STRICT;

CREATE TABLE authz_groups (
    id         TEXT PRIMARY KEY,
    public_id  TEXT NOT NULL,
    realm_id   TEXT NOT NULL,
    org_id     TEXT NOT NULL, -- 空なら realm 全体
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, org_id, name)
) STRICT;

CREATE TABLE authz_group_members (
    group_id    TEXT NOT NULL REFERENCES authz_groups (id) ON DELETE CASCADE,
    member_type TEXT NOT NULL,
    member_id   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (group_id, member_type, member_id)
) STRICT;

CREATE INDEX authz_group_members_member ON authz_group_members (member_type, member_id);
