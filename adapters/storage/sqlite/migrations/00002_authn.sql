-- M1：個人識別（design.md 3.1）。
-- realm に属する表は realm_id を持ち、一意制約は realm 内で効かせる。

-- +goose Up
CREATE TABLE authn_users (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL,
    status      TEXT NOT NULL,
    valid_from  TEXT,
    valid_until TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

CREATE TABLE authn_user_emails (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    ciphertext   BLOB NOT NULL,
    email_index  BLOB NOT NULL,
    domain_index BLOB NOT NULL,
    index_key_id TEXT NOT NULL,
    verified_at  TEXT,
    verified_via TEXT NOT NULL,
    is_primary   INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (realm_id, email_index)
) STRICT;

CREATE INDEX authn_user_emails_user ON authn_user_emails (realm_id, user_id);

CREATE TABLE authn_user_identities (
    id               TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    connection_id    TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    revoked_at       TEXT,
    UNIQUE (connection_id, provider_subject)
) STRICT;

CREATE INDEX authn_user_identities_user ON authn_user_identities (realm_id, user_id);

CREATE TABLE authn_connections (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    slug       TEXT NOT NULL,
    type       TEXT NOT NULL,
    config     BLOB NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (realm_id, slug)
) STRICT;

CREATE TABLE authn_sessions (
    id                  TEXT PRIMARY KEY,
    realm_id            TEXT NOT NULL,
    principal_type      TEXT NOT NULL,
    principal_id        TEXT NOT NULL,
    active_org_id       TEXT NOT NULL,
    token_hash          BLOB NOT NULL,
    auth_methods        TEXT NOT NULL, -- JSON の配列
    auth_credential_ids TEXT NOT NULL, -- JSON の配列
    warnings            BLOB NOT NULL,
    ip                  BLOB NOT NULL,
    user_agent          BLOB NOT NULL,
    authenticated_at    TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    revoked_at          TEXT,
    revoke_reason       TEXT NOT NULL
) STRICT;

CREATE INDEX authn_sessions_principal ON authn_sessions (realm_id, principal_type, principal_id);

CREATE TABLE authn_service_accounts (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE authn_service_account_credentials (
    id                 TEXT PRIMARY KEY,
    realm_id           TEXT NOT NULL,
    service_account_id TEXT NOT NULL REFERENCES authn_service_accounts (id),
    type               TEXT NOT NULL,
    secret_hash        BLOB NOT NULL,
    created_at         TEXT NOT NULL,
    expires_at         TEXT,
    revoked_at         TEXT
) STRICT;

-- 認可側（design.md 3.2）。M1 では組み込みのロールを名前で付与する（M4 でロールの表に置き換える）。
CREATE TABLE authz_role_bindings (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL,
    role           TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id   TEXT NOT NULL,
    org_id         TEXT NOT NULL, -- 空なら realm 全体
    created_at     TEXT NOT NULL,
    UNIQUE (realm_id, role, principal_type, principal_id, org_id)
) STRICT;

CREATE INDEX authz_role_bindings_principal ON authz_role_bindings (realm_id, principal_type, principal_id);
