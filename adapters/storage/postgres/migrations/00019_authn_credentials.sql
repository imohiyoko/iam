-- M8：認証方式のプラグインの汎用の認証情報（ADR 0090、0092。SQLite の 00036）。

-- +goose Up
CREATE TABLE authn_credentials (
    id            TEXT COLLATE "C" PRIMARY KEY,
    public_id     TEXT COLLATE "C" NOT NULL,
    realm_id      TEXT COLLATE "C" NOT NULL,
    user_id       TEXT COLLATE "C" NOT NULL,
    method        TEXT COLLATE "C" NOT NULL,
    lookup        BYTEA,
    data          BYTEA NOT NULL,
    data_version  BIGINT NOT NULL,
    created_at    TEXT COLLATE "C" NOT NULL,
    last_used_at  TEXT COLLATE "C",
    revoked_at    TEXT COLLATE "C",
    revoke_reason TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id)
);

CREATE INDEX authn_credentials_user ON authn_credentials (realm_id, user_id);
CREATE INDEX authn_credentials_method ON authn_credentials (method);
CREATE UNIQUE INDEX authn_credentials_lookup ON authn_credentials (realm_id, method, lookup)
    WHERE lookup IS NOT NULL AND revoked_at IS NULL;

-- +goose Down
DROP TABLE authn_credentials;
