-- M5：ログインの系列（sid）と、連携先への認可・不透明なトークン（design.md 5.1、5.2）。

-- +goose Up
ALTER TABLE authn_sessions ADD COLUMN sid TEXT NOT NULL DEFAULT '';
UPDATE authn_sessions SET sid = id WHERE sid = '';
CREATE INDEX authn_sessions_sid ON authn_sessions (realm_id, sid, created_at);

CREATE TABLE authn_oidc_grants (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL,
    client_id     TEXT NOT NULL, -- 内部 ID
    user_id       TEXT NOT NULL,
    org_id        TEXT NOT NULL,
    sid           TEXT NOT NULL,
    scopes        TEXT NOT NULL, -- JSON の配列
    auth_methods  TEXT NOT NULL, -- JSON の配列
    auth_time     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT,
    revoke_reason TEXT NOT NULL
) STRICT;

CREATE INDEX authn_oidc_grants_sid ON authn_oidc_grants (realm_id, sid);
CREATE INDEX authn_oidc_grants_user ON authn_oidc_grants (realm_id, user_id);
CREATE INDEX authn_oidc_grants_client ON authn_oidc_grants (realm_id, client_id);

CREATE TABLE authn_oidc_tokens (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    grant_id   TEXT NOT NULL,
    kind       TEXT NOT NULL,
    token_hash BLOB NOT NULL, -- 秘密部分の SHA-256
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
) STRICT;

CREATE INDEX authn_oidc_tokens_grant ON authn_oidc_tokens (grant_id);
