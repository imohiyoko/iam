-- M9：退役した検索キー（ADR 0106。SQLite の 00051）。

-- +goose Up
CREATE TABLE authn_retired_credential_lookups (
    realm_id      TEXT COLLATE "C" NOT NULL,
    method        TEXT COLLATE "C" NOT NULL,
    lookup        BYTEA NOT NULL,
    lookup_key_id TEXT COLLATE "C" NOT NULL,
    retired_at    TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, method, lookup)
);

-- +goose Down
DROP TABLE authn_retired_credential_lookups;
