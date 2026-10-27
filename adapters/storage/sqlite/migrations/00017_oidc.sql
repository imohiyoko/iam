-- M5：OIDC Provider の連携先（clients）と ID トークンの署名鍵（design.md 3.1、5.5、9.3）。

-- +goose Up
CREATE TABLE authn_clients (
    id                        TEXT PRIMARY KEY,
    public_id                 TEXT NOT NULL, -- client_id
    realm_id                  TEXT NOT NULL,
    name                      TEXT NOT NULL,
    trust_level               TEXT NOT NULL,
    redirect_uris             TEXT NOT NULL, -- JSON の配列
    post_logout_redirect_uris TEXT NOT NULL, -- JSON の配列
    auth_method               TEXT NOT NULL,
    secret_hash               BLOB,
    jwks                      BLOB,
    id_token_alg              TEXT NOT NULL,
    backchannel_logout_uri    TEXT NOT NULL,
    created_at                TEXT NOT NULL,
    updated_at                TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE TABLE authn_signing_keys (
    id          TEXT PRIMARY KEY, -- kid
    realm_id    TEXT NOT NULL,
    alg         TEXT NOT NULL,
    public_key  BLOB NOT NULL,
    private_key BLOB NOT NULL, -- マスター鍵から導いた鍵で暗号化
    created_at  TEXT NOT NULL,
    retired_at  TEXT
) STRICT;

CREATE INDEX authn_signing_keys_realm ON authn_signing_keys (realm_id, created_at);
