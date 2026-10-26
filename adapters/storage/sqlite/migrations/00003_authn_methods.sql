-- M2：認証手段（design.md 4.2、4.3、4.6）。
-- メールと外部 ID の紐付けを API に出すため、外部 ID（public_id）を足す（ADR 0045）。
-- 既存の行には randomblob の乱数（100bit）で、id パッケージと同じ形の値を入れる。
-- 外部 ID の紐付けは無効化した行を残すので、一意制約は無効化していない行だけに効かせる。

-- +goose Up
ALTER TABLE authn_user_emails ADD COLUMN public_id TEXT NOT NULL DEFAULT '';
UPDATE authn_user_emails SET public_id = 'eml_0' || substr(hex(randomblob(13)), 2);
CREATE UNIQUE INDEX authn_user_emails_public ON authn_user_emails (realm_id, public_id);

CREATE TABLE authn_user_identities_v2 (
    id               TEXT PRIMARY KEY,
    public_id        TEXT NOT NULL,
    realm_id         TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    connection_id    TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    revoked_at       TEXT,
    revoke_reason    TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

INSERT INTO authn_user_identities_v2 (id, public_id, realm_id, user_id, connection_id, provider_subject, created_at, revoked_at, revoke_reason)
SELECT id, 'idn_0' || substr(hex(randomblob(13)), 2), realm_id, user_id, connection_id, provider_subject, created_at, revoked_at, ''
FROM authn_user_identities;

DROP TABLE authn_user_identities;
ALTER TABLE authn_user_identities_v2 RENAME TO authn_user_identities;

CREATE INDEX authn_user_identities_user ON authn_user_identities (realm_id, user_id);
CREATE UNIQUE INDEX authn_user_identities_active ON authn_user_identities (connection_id, provider_subject) WHERE revoked_at IS NULL;

