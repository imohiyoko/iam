-- M9：本人の Personal Access Token と realm のポリシー（フィーチャー personal_access_tokens。ADR 0109）。
-- id はトークンの文字列の一部の外部 ID（pat_…）。秘密は SHA-256（token_hash）だけを持つ。scopes は権限の名前の JSON の配列。

-- +goose Up
CREATE TABLE authn_personal_access_tokens (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    name          TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    token_hash    BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_used_at  TEXT,
    revoked_at    TEXT,
    revoke_reason TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX authn_personal_access_tokens_user ON authn_personal_access_tokens (realm_id, user_id, created_at);

CREATE TABLE authn_personal_access_token_policies (
    realm_id             TEXT PRIMARY KEY,
    max_lifetime_seconds INTEGER NOT NULL,
    allowed_scopes       TEXT NOT NULL,
    require_expiry       INTEGER NOT NULL,
    updated_at           TEXT NOT NULL
) STRICT;

-- +goose Down
DROP TABLE authn_personal_access_token_policies;
DROP INDEX authn_personal_access_tokens_user;
DROP TABLE authn_personal_access_tokens;
