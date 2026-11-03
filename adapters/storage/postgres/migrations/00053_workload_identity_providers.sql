-- M9：Workload Identity Federation の発行者（フィーチャー workload_identity。ADR 0116。SQLite の 00070）。

-- +goose Up
CREATE TABLE authn_workload_identity_providers (
    id         TEXT COLLATE "C" PRIMARY KEY,
    realm_id   TEXT COLLATE "C" NOT NULL,
    issuer     TEXT COLLATE "C" NOT NULL,
    name       TEXT COLLATE "C" NOT NULL,
    config     BYTEA NOT NULL,
    disabled   BIGINT NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, issuer)
);

CREATE INDEX authn_workload_identity_providers_list ON authn_workload_identity_providers (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_workload_identity_providers_list;
DROP TABLE authn_workload_identity_providers;
