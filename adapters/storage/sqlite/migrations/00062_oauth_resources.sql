-- M11：自前の API（リソースサーバー）の登録（Resource Indicators、RFC 8707。フィーチャー resource_indicators。ADR 0112）。
-- uri は resource の値（絶対 URI）でアクセストークンの aud になる。scopes はそのリソースで使えるスコープ、clients と
-- service_accounts は要求してよい連携先（client_id）とサービスアカウント（ID）。どれも JSON の配列。

-- +goose Up
CREATE TABLE authn_oauth_resources (
    id               TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL,
    uri              TEXT NOT NULL,
    name             TEXT NOT NULL,
    scopes           TEXT NOT NULL,
    clients          TEXT NOT NULL,
    service_accounts TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE (realm_id, uri)
) STRICT;

CREATE INDEX authn_oauth_resources_list ON authn_oauth_resources (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_oauth_resources_list;
DROP TABLE authn_oauth_resources;
