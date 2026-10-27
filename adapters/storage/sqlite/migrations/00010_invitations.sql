-- M3：Org への招待（design.md 3.1、4.4）。アドレスは招待ごとのデータ鍵で暗号化し、受け入れ・取り消しの後に鍵を消す。
-- トークンは秘密のハッシュだけを持つ。期限切れは expires_at から計算する。

-- +goose Up
CREATE TABLE invitations (
    id               TEXT PRIMARY KEY,
    public_id        TEXT NOT NULL,
    realm_id         TEXT NOT NULL,
    org_id           TEXT NOT NULL,
    email_index      BLOB NOT NULL,
    email_ciphertext BLOB NOT NULL,
    index_key_id     TEXT NOT NULL,
    org_role         TEXT NOT NULL,
    token_hash       BLOB NOT NULL,
    valid_from       TEXT,
    valid_until      TEXT,
    invited_by       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    closed_at        TEXT,
    closed_by        TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE INDEX invitations_org ON invitations (realm_id, org_id);
