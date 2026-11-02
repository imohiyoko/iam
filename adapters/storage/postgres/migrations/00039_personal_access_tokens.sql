-- M9：本人の Personal Access Token と realm のポリシー（フィーチャー personal_access_tokens。ADR 0109。SQLite の 00056）。

-- +goose Up
CREATE TABLE authn_personal_access_tokens (
    id            TEXT COLLATE "C" PRIMARY KEY,
    realm_id      TEXT COLLATE "C" NOT NULL,
    user_id       TEXT COLLATE "C" NOT NULL,
    name          TEXT NOT NULL,
    scopes        TEXT COLLATE "C" NOT NULL,
    token_hash    BYTEA NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    expires_at    TEXT COLLATE "C",
    last_used_at  TEXT COLLATE "C",
    revoked_at    TEXT COLLATE "C",
    revoke_reason TEXT COLLATE "C" NOT NULL DEFAULT ''
);

CREATE INDEX authn_personal_access_tokens_user ON authn_personal_access_tokens (realm_id, user_id, created_at);

CREATE TABLE authn_personal_access_token_policies (
    realm_id             TEXT COLLATE "C" PRIMARY KEY,
    max_lifetime_seconds BIGINT NOT NULL,
    allowed_scopes       TEXT COLLATE "C" NOT NULL,
    require_expiry       BIGINT NOT NULL,
    updated_at           TEXT COLLATE "C" NOT NULL
);

-- +goose Down
DROP TABLE authn_personal_access_token_policies;
DROP INDEX authn_personal_access_tokens_user;
DROP TABLE authn_personal_access_tokens;
