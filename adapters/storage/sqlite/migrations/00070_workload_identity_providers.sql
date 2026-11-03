-- M9：Workload Identity Federation の発行者（フィーチャー workload_identity。ADR 0116）。issuer は JWT の iss（完全一致）、
-- config は残りの設定（JSON。aud・鍵・alg・寿命の上限）。

-- +goose Up
CREATE TABLE authn_workload_identity_providers (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    issuer     TEXT NOT NULL,
    name       TEXT NOT NULL,
    config     BLOB NOT NULL, -- JSON（authn/workloadidentity の Config）
    disabled   INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (realm_id, issuer)
) STRICT;

CREATE INDEX authn_workload_identity_providers_list ON authn_workload_identity_providers (realm_id, created_at, id);

-- +goose Down
DROP INDEX authn_workload_identity_providers_list;
DROP TABLE authn_workload_identity_providers;
