-- M11：自前の API（リソースサーバー）の登録（RFC 8707。フィーチャー resource_indicators。ADR 0112。SQLite の 00062）。

-- +goose Up
CREATE TABLE authn_oauth_resources (
    id               TEXT COLLATE "C" PRIMARY KEY,
    realm_id         TEXT COLLATE "C" NOT NULL,
    uri              TEXT COLLATE "C" NOT NULL,
    name             TEXT COLLATE "C" NOT NULL,
    scopes           TEXT COLLATE "C" NOT NULL,
    clients          TEXT COLLATE "C" NOT NULL,
    service_accounts TEXT COLLATE "C" NOT NULL,
    created_at       TEXT COLLATE "C" NOT NULL,
    updated_at       TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, uri)
);

CREATE INDEX authn_oauth_resources_list ON authn_oauth_resources (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_oauth_resources_list;
DROP TABLE authn_oauth_resources;
