-- M9：Workload Identity Federation の結び付け（ADR 0116。SQLite の 00071）。

-- +goose Up
CREATE TABLE authn_workload_identity_bindings (
    id                 TEXT COLLATE "C" PRIMARY KEY,
    realm_id           TEXT COLLATE "C" NOT NULL,
    provider_id        TEXT COLLATE "C" NOT NULL REFERENCES authn_workload_identity_providers (id) ON DELETE CASCADE,
    service_account_id TEXT COLLATE "C" NOT NULL,
    conditions         BYTEA NOT NULL,
    created_at         TEXT COLLATE "C" NOT NULL
);

CREATE INDEX authn_workload_identity_bindings_provider ON authn_workload_identity_bindings (realm_id, provider_id, created_at, id);

-- +goose Down
DROP INDEX authn_workload_identity_bindings_provider;
DROP TABLE authn_workload_identity_bindings;
