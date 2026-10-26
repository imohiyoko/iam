-- M3：Org と Membership（design.md 3.1、11.13）。個人 Org はユーザーに1つ（personal_owner_id が realm 内で一意）。
-- Membership はユーザーと Org の組に1つ。終了は削除せず status = ended と ended_reason で表す。

-- +goose Up
CREATE TABLE orgs (
    id                TEXT PRIMARY KEY,
    public_id         TEXT NOT NULL,
    realm_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    name              TEXT NOT NULL,
    personal_owner_id TEXT NOT NULL,
    valid_from        TEXT,
    valid_until       TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE UNIQUE INDEX orgs_personal_owner ON orgs (realm_id, personal_owner_id) WHERE kind = 'personal';

CREATE TABLE memberships (
    id           TEXT PRIMARY KEY,
    public_id    TEXT NOT NULL,
    realm_id     TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    org_id       TEXT NOT NULL,
    status       TEXT NOT NULL,
    org_role     TEXT NOT NULL,
    email_id     TEXT NOT NULL,
    valid_from   TEXT,
    valid_until  TEXT,
    ended_reason TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, user_id, org_id)
) STRICT;

CREATE INDEX memberships_org ON memberships (realm_id, org_id);
