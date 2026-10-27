-- PostgreSQL のスキーマ（SQLite のマイグレーションを適用した後の形と同じ。design.md 2.4、ADR 0067）。
-- 文字列の比較と並びはバイト順にする（COLLATE "C"）。時刻は SQLite と同じ固定長の RFC 3339 の文字列で持つ。

-- +goose Up
CREATE TABLE authn_realms (
    id         TEXT COLLATE "C" PRIMARY KEY,
    slug       TEXT COLLATE "C" NOT NULL UNIQUE,
    settings   BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL
);

CREATE TABLE authn_user_data_keys (
    user_id     TEXT COLLATE "C" PRIMARY KEY,
    wrapped_key BYTEA NOT NULL,
    key_id      TEXT COLLATE "C" NOT NULL,
    created_at  TEXT COLLATE "C" NOT NULL
);

CREATE TABLE shared_installed_features (
    feature      TEXT COLLATE "C" PRIMARY KEY,
    state        TEXT COLLATE "C" NOT NULL,
    data_version BIGINT NOT NULL,
    updated_at   TEXT COLLATE "C" NOT NULL
);

CREATE TABLE shared_audit_events (
    seq       BIGINT PRIMARY KEY,
    realm_id  TEXT COLLATE "C" NOT NULL,
    prev_hash BYTEA NOT NULL,
    hash      BYTEA NOT NULL,
    payload   BYTEA NOT NULL
);

CREATE INDEX shared_audit_events_realm ON shared_audit_events (realm_id, seq);

CREATE TABLE shared_outbox (
    id           TEXT COLLATE "C" PRIMARY KEY,
    topic        TEXT COLLATE "C" NOT NULL,
    payload      BYTEA NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    delivered_at TEXT COLLATE "C",
    ord          BIGSERIAL NOT NULL
);

CREATE INDEX shared_outbox_pending ON shared_outbox (topic, created_at, ord) WHERE delivered_at IS NULL;

CREATE TABLE authn_users (
    id          TEXT COLLATE "C" PRIMARY KEY,
    public_id   TEXT COLLATE "C" NOT NULL,
    realm_id    TEXT COLLATE "C" NOT NULL,
    status      TEXT COLLATE "C" NOT NULL,
    valid_from  TEXT COLLATE "C",
    valid_until TEXT COLLATE "C",
    created_at  TEXT COLLATE "C" NOT NULL,
    updated_at  TEXT COLLATE "C" NOT NULL,
    deletion_scheduled_at TEXT COLLATE "C",
    legal_hold BIGINT NOT NULL DEFAULT 0,
    UNIQUE (realm_id, public_id)
);

CREATE TABLE authn_user_emails (
    id           TEXT COLLATE "C" PRIMARY KEY,
    realm_id     TEXT COLLATE "C" NOT NULL,
    user_id      TEXT COLLATE "C" NOT NULL,
    ciphertext   BYTEA NOT NULL,
    email_index  BYTEA NOT NULL,
    domain_index BYTEA NOT NULL,
    index_key_id TEXT COLLATE "C" NOT NULL,
    verified_at  TEXT COLLATE "C",
    verified_via TEXT COLLATE "C" NOT NULL,
    is_primary   BIGINT NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    public_id TEXT COLLATE "C" NOT NULL DEFAULT '',
    UNIQUE (realm_id, email_index)
);

CREATE INDEX authn_user_emails_user ON authn_user_emails (realm_id, user_id);

CREATE TABLE authn_connections (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    slug       TEXT COLLATE "C" NOT NULL,
    type       TEXT COLLATE "C" NOT NULL,
    config     BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, slug)
);

CREATE TABLE authn_sessions (
    id                  TEXT COLLATE "C" PRIMARY KEY,
    realm_id            TEXT COLLATE "C" NOT NULL,
    principal_type      TEXT COLLATE "C" NOT NULL,
    principal_id        TEXT COLLATE "C" NOT NULL,
    active_org_id       TEXT COLLATE "C" NOT NULL,
    token_hash          BYTEA NOT NULL,
    auth_methods        TEXT COLLATE "C" NOT NULL, -- JSON の配列
    auth_credential_ids TEXT COLLATE "C" NOT NULL, -- JSON の配列
    warnings            BYTEA NOT NULL,
    ip                  BYTEA NOT NULL,
    user_agent          BYTEA NOT NULL,
    authenticated_at    TEXT COLLATE "C" NOT NULL,
    created_at          TEXT COLLATE "C" NOT NULL,
    last_seen_at        TEXT COLLATE "C" NOT NULL,
    expires_at          TEXT COLLATE "C" NOT NULL,
    revoked_at          TEXT COLLATE "C",
    revoke_reason       TEXT COLLATE "C" NOT NULL
,
    restriction TEXT COLLATE "C" NOT NULL DEFAULT '',
    sid TEXT COLLATE "C" NOT NULL DEFAULT '');

CREATE INDEX authn_sessions_principal ON authn_sessions (realm_id, principal_type, principal_id);

CREATE TABLE authn_service_accounts (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    name       TEXT COLLATE "C" NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL
);

CREATE TABLE authn_service_account_credentials (
    id                 TEXT COLLATE "C" PRIMARY KEY,
    realm_id           TEXT COLLATE "C" NOT NULL,
    service_account_id TEXT COLLATE "C" NOT NULL REFERENCES authn_service_accounts (id),
    type               TEXT COLLATE "C" NOT NULL,
    secret_hash        BYTEA NOT NULL,
    created_at         TEXT COLLATE "C" NOT NULL,
    expires_at         TEXT COLLATE "C",
    revoked_at         TEXT COLLATE "C"
);

CREATE UNIQUE INDEX authn_user_emails_public ON authn_user_emails (realm_id, public_id);

CREATE TABLE authn_user_identities (
    id               TEXT COLLATE "C" PRIMARY KEY,
    public_id        TEXT COLLATE "C" NOT NULL,
    realm_id         TEXT COLLATE "C" NOT NULL,
    user_id          TEXT COLLATE "C" NOT NULL,
    connection_id    TEXT COLLATE "C" NOT NULL,
    provider_subject TEXT COLLATE "C" NOT NULL,
    created_at       TEXT COLLATE "C" NOT NULL,
    revoked_at       TEXT COLLATE "C",
    revoke_reason    TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_user_identities_user ON authn_user_identities (realm_id, user_id);

CREATE UNIQUE INDEX authn_user_identities_active ON authn_user_identities (connection_id, provider_subject) WHERE revoked_at IS NULL;

CREATE TABLE authn_passkeys (
    id            TEXT COLLATE "C" PRIMARY KEY,
    public_id     TEXT COLLATE "C" NOT NULL,
    realm_id      TEXT COLLATE "C" NOT NULL,
    user_id       TEXT COLLATE "C" NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key    BYTEA NOT NULL,
    alg           BIGINT NOT NULL,
    sign_count    BIGINT NOT NULL,
    flags         BIGINT NOT NULL,
    aaguid        BYTEA NOT NULL,
    transports    TEXT COLLATE "C" NOT NULL,
    name          TEXT COLLATE "C" NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    last_used_at  TEXT COLLATE "C",
    revoked_at    TEXT COLLATE "C",
    revoke_reason TEXT COLLATE "C" NOT NULL,
    preferred_org_id TEXT COLLATE "C" NOT NULL DEFAULT '',
    UNIQUE (realm_id, credential_id),
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_passkeys_user ON authn_passkeys (realm_id, user_id);

CREATE TABLE authn_revoked_passkey_credentials (
    realm_id      TEXT COLLATE "C" NOT NULL,
    credential_id BYTEA NOT NULL,
    revoked_at    TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, credential_id)
);

CREATE TABLE authn_totp_credentials (
    id                TEXT COLLATE "C" PRIMARY KEY,
    public_id         TEXT COLLATE "C" NOT NULL,
    realm_id          TEXT COLLATE "C" NOT NULL,
    user_id           TEXT COLLATE "C" NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    last_used_step    BIGINT NOT NULL,
    created_at        TEXT COLLATE "C" NOT NULL,
    revoked_at        TEXT COLLATE "C",
    revoke_reason     TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_totp_credentials_user ON authn_totp_credentials (realm_id, user_id);

CREATE TABLE authn_password_credentials (
    id            TEXT COLLATE "C" PRIMARY KEY,
    realm_id      TEXT COLLATE "C" NOT NULL,
    user_id       TEXT COLLATE "C" NOT NULL,
    hash          TEXT COLLATE "C" NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    revoked_at    TEXT COLLATE "C",
    revoke_reason TEXT COLLATE "C" NOT NULL
);

CREATE UNIQUE INDEX authn_password_credentials_active ON authn_password_credentials (realm_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE authn_suspensions (
    id           TEXT COLLATE "C" PRIMARY KEY,
    public_id    TEXT COLLATE "C" NOT NULL,
    realm_id     TEXT COLLATE "C" NOT NULL,
    target_type  TEXT COLLATE "C" NOT NULL,
    target_id    TEXT COLLATE "C" NOT NULL,
    category     TEXT COLLATE "C" NOT NULL,
    reason       TEXT COLLATE "C" NOT NULL,
    external_ref TEXT COLLATE "C" NOT NULL,
    starts_at    TEXT COLLATE "C" NOT NULL,
    ends_at      TEXT COLLATE "C",
    created_by   TEXT COLLATE "C" NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    lifted_at    TEXT COLLATE "C",
    lifted_by    TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_suspensions_target ON authn_suspensions (realm_id, target_type, target_id);

CREATE UNIQUE INDEX authn_suspensions_external_ref ON authn_suspensions (realm_id, target_type, target_id, category, external_ref)
    WHERE external_ref <> '';

CREATE TABLE scheduled_events (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    ref        TEXT COLLATE "C" NOT NULL,
    event_type TEXT COLLATE "C" NOT NULL,
    payload    BYTEA NOT NULL,
    fire_at    TEXT COLLATE "C" NOT NULL,
    fired_at   TEXT COLLATE "C",
    created_at TEXT COLLATE "C" NOT NULL
);

CREATE INDEX scheduled_events_due ON scheduled_events (fire_at, id) WHERE fired_at IS NULL;

CREATE INDEX scheduled_events_ref ON scheduled_events (realm_id, ref);

CREATE TABLE authn_recovery_codes (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    user_id    TEXT COLLATE "C" NOT NULL,
    lookup     TEXT COLLATE "C" NOT NULL,
    hash       TEXT COLLATE "C" NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    used_at    TEXT COLLATE "C"
);

CREATE UNIQUE INDEX authn_recovery_codes_lookup ON authn_recovery_codes (realm_id, user_id, lookup);

CREATE TABLE orgs (
    id                TEXT COLLATE "C" PRIMARY KEY,
    public_id         TEXT COLLATE "C" NOT NULL,
    realm_id          TEXT COLLATE "C" NOT NULL,
    kind              TEXT COLLATE "C" NOT NULL,
    name              TEXT COLLATE "C" NOT NULL,
    personal_owner_id TEXT COLLATE "C" NOT NULL,
    valid_from        TEXT COLLATE "C",
    valid_until       TEXT COLLATE "C",
    created_at        TEXT COLLATE "C" NOT NULL,
    updated_at        TEXT COLLATE "C" NOT NULL,
    deletion_scheduled_at TEXT COLLATE "C",
    deleted_at TEXT COLLATE "C",
    settings BYTEA,
    UNIQUE (realm_id, public_id)
);

CREATE UNIQUE INDEX orgs_personal_owner ON orgs (realm_id, personal_owner_id) WHERE kind = 'personal';

CREATE TABLE memberships (
    id           TEXT COLLATE "C" PRIMARY KEY,
    public_id    TEXT COLLATE "C" NOT NULL,
    realm_id     TEXT COLLATE "C" NOT NULL,
    user_id      TEXT COLLATE "C" NOT NULL,
    org_id       TEXT COLLATE "C" NOT NULL,
    status       TEXT COLLATE "C" NOT NULL,
    org_role     TEXT COLLATE "C" NOT NULL,
    email_id     TEXT COLLATE "C" NOT NULL,
    valid_from   TEXT COLLATE "C",
    valid_until  TEXT COLLATE "C",
    ended_reason TEXT COLLATE "C" NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    updated_at   TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, user_id, org_id)
);

CREATE INDEX memberships_org ON memberships (realm_id, org_id, public_id);

CREATE TABLE invitations (
    id               TEXT COLLATE "C" PRIMARY KEY,
    public_id        TEXT COLLATE "C" NOT NULL,
    realm_id         TEXT COLLATE "C" NOT NULL,
    org_id           TEXT COLLATE "C" NOT NULL,
    email_index      BYTEA NOT NULL,
    email_ciphertext BYTEA NOT NULL,
    index_key_id     TEXT COLLATE "C" NOT NULL,
    org_role         TEXT COLLATE "C" NOT NULL,
    token_hash       BYTEA NOT NULL,
    valid_from       TEXT COLLATE "C",
    valid_until      TEXT COLLATE "C",
    invited_by       TEXT COLLATE "C" NOT NULL,
    expires_at       TEXT COLLATE "C" NOT NULL,
    status           TEXT COLLATE "C" NOT NULL,
    created_at       TEXT COLLATE "C" NOT NULL,
    closed_at        TEXT COLLATE "C",
    closed_by        TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX invitations_org ON invitations (realm_id, org_id);

CREATE TABLE shared_audit_client_keys (
    owner       TEXT COLLATE "C" PRIMARY KEY,
    wrapped_key BYTEA NOT NULL,
    key_id      TEXT COLLATE "C" NOT NULL,
    created_at  TEXT COLLATE "C" NOT NULL
);

CREATE TABLE authz_role_bindings (
    id             TEXT COLLATE "C" PRIMARY KEY,
    public_id      TEXT COLLATE "C" NOT NULL,
    realm_id       TEXT COLLATE "C" NOT NULL,
    role           TEXT COLLATE "C" NOT NULL,
    principal_type TEXT COLLATE "C" NOT NULL,
    principal_id   TEXT COLLATE "C" NOT NULL,
    org_id         TEXT COLLATE "C" NOT NULL, -- 空なら realm 全体
    resource_type  TEXT COLLATE "C" NOT NULL, -- 空なら Org（realm）全体
    resource_id    TEXT COLLATE "C" NOT NULL,
    created_at     TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, role, principal_type, principal_id, org_id, resource_type, resource_id)
);

CREATE INDEX authz_role_bindings_principal ON authz_role_bindings (realm_id, principal_type, principal_id);

CREATE INDEX authz_role_bindings_org ON authz_role_bindings (realm_id, org_id);

CREATE INDEX authz_role_bindings_role ON authz_role_bindings (realm_id, role);

CREATE TABLE authz_roles (
    id          TEXT COLLATE "C" PRIMARY KEY,
    public_id   TEXT COLLATE "C" NOT NULL,
    realm_id    TEXT COLLATE "C" NOT NULL,
    org_id      TEXT COLLATE "C" NOT NULL, -- 空なら realm 共通
    name        TEXT COLLATE "C" NOT NULL,
    permissions TEXT COLLATE "C" NOT NULL, -- JSON の配列（role_permissions）
    created_at  TEXT COLLATE "C" NOT NULL,
    updated_at  TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, org_id, name)
);

CREATE TABLE authz_groups (
    id         TEXT COLLATE "C" PRIMARY KEY,
    public_id  TEXT COLLATE "C" NOT NULL,
    realm_id   TEXT COLLATE "C" NOT NULL,
    org_id     TEXT COLLATE "C" NOT NULL, -- 空なら realm 全体
    name       TEXT COLLATE "C" NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, org_id, name)
);

CREATE TABLE authz_group_members (
    group_id    TEXT COLLATE "C" NOT NULL,
    member_type TEXT COLLATE "C" NOT NULL,
    member_id   TEXT COLLATE "C" NOT NULL,
    created_at  TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (group_id, member_type, member_id)
);

CREATE INDEX authz_group_members_member ON authz_group_members (member_type, member_id);

CREATE TABLE authn_clients (
    id                        TEXT COLLATE "C" PRIMARY KEY,
    public_id                 TEXT COLLATE "C" NOT NULL, -- client_id
    realm_id                  TEXT COLLATE "C" NOT NULL,
    name                      TEXT COLLATE "C" NOT NULL,
    trust_level               TEXT COLLATE "C" NOT NULL,
    redirect_uris             TEXT COLLATE "C" NOT NULL, -- JSON の配列
    post_logout_redirect_uris TEXT COLLATE "C" NOT NULL, -- JSON の配列
    auth_method               TEXT COLLATE "C" NOT NULL,
    secret_hash               BYTEA,
    jwks                      BYTEA,
    id_token_alg              TEXT COLLATE "C" NOT NULL,
    backchannel_logout_uri    TEXT COLLATE "C" NOT NULL,
    created_at                TEXT COLLATE "C" NOT NULL,
    updated_at                TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE TABLE authn_signing_keys (
    id          TEXT COLLATE "C" PRIMARY KEY, -- kid
    realm_id    TEXT COLLATE "C" NOT NULL,
    alg         TEXT COLLATE "C" NOT NULL,
    public_key  BYTEA NOT NULL,
    private_key BYTEA NOT NULL, -- マスター鍵から導いた鍵で暗号化
    created_at  TEXT COLLATE "C" NOT NULL,
    retired_at  TEXT COLLATE "C"
);

CREATE INDEX authn_signing_keys_realm ON authn_signing_keys (realm_id, created_at);

CREATE INDEX authn_sessions_sid ON authn_sessions (realm_id, sid, created_at);

CREATE TABLE authn_oidc_grants (
    id            TEXT COLLATE "C" PRIMARY KEY,
    realm_id      TEXT COLLATE "C" NOT NULL,
    client_id     TEXT COLLATE "C" NOT NULL, -- 内部 ID
    user_id       TEXT COLLATE "C" NOT NULL,
    org_id        TEXT COLLATE "C" NOT NULL,
    sid           TEXT COLLATE "C" NOT NULL,
    scopes        TEXT COLLATE "C" NOT NULL, -- JSON の配列
    auth_methods  TEXT COLLATE "C" NOT NULL, -- JSON の配列
    auth_time     TEXT COLLATE "C" NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    expires_at    TEXT COLLATE "C" NOT NULL,
    revoked_at    TEXT COLLATE "C",
    revoke_reason TEXT COLLATE "C" NOT NULL
);

CREATE INDEX authn_oidc_grants_sid ON authn_oidc_grants (realm_id, sid);

CREATE INDEX authn_oidc_grants_user ON authn_oidc_grants (realm_id, user_id);

CREATE INDEX authn_oidc_grants_client ON authn_oidc_grants (realm_id, client_id);

CREATE TABLE authn_oidc_tokens (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    grant_id   TEXT COLLATE "C" NOT NULL,
    kind       TEXT COLLATE "C" NOT NULL,
    token_hash BYTEA NOT NULL, -- 秘密部分の SHA-256
    created_at TEXT COLLATE "C" NOT NULL,
    expires_at TEXT COLLATE "C" NOT NULL,
    used_at    TEXT COLLATE "C"
);

CREATE INDEX authn_oidc_tokens_grant ON authn_oidc_tokens (grant_id);

-- +goose Down
DROP TABLE authn_oidc_tokens;
DROP TABLE authn_oidc_grants;
DROP TABLE authn_signing_keys;
DROP TABLE authn_clients;
DROP TABLE authz_group_members;
DROP TABLE authz_groups;
DROP TABLE authz_roles;
DROP TABLE authz_role_bindings;
DROP TABLE shared_audit_client_keys;
DROP TABLE invitations;
DROP TABLE memberships;
DROP TABLE orgs;
DROP TABLE authn_recovery_codes;
DROP TABLE scheduled_events;
DROP TABLE authn_suspensions;
DROP TABLE authn_password_credentials;
DROP TABLE authn_totp_credentials;
DROP TABLE authn_revoked_passkey_credentials;
DROP TABLE authn_passkeys;
DROP TABLE authn_user_identities;
DROP TABLE authn_service_account_credentials;
DROP TABLE authn_service_accounts;
DROP TABLE authn_sessions;
DROP TABLE authn_connections;
DROP TABLE authn_user_emails;
DROP TABLE authn_users;
DROP TABLE shared_outbox;
DROP TABLE shared_audit_events;
DROP TABLE shared_installed_features;
DROP TABLE authn_user_data_keys;
DROP TABLE authn_realms;
