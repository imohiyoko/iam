-- M9：Workload Identity Federation の結び付け（ADR 0116）。条件（JSON）を満たす外部の主体をサービスアカウントに対応させる。
-- 結び付けで発行したアクセストークンは authn_service_account_tokens の credential_id に結び付けの ID を持つ。

-- +goose Up
CREATE TABLE authn_workload_identity_bindings (
    id                 TEXT PRIMARY KEY,
    realm_id           TEXT NOT NULL,
    provider_id        TEXT NOT NULL REFERENCES authn_workload_identity_providers (id) ON DELETE CASCADE,
    service_account_id TEXT NOT NULL,
    conditions         BLOB NOT NULL, -- JSON（authn/workloadidentity の Condition の配列）
    created_at         TEXT NOT NULL
) STRICT;

CREATE INDEX authn_workload_identity_bindings_provider ON authn_workload_identity_bindings (realm_id, provider_id, created_at, id);

-- +goose Down
DROP INDEX authn_workload_identity_bindings_provider;
DROP TABLE authn_workload_identity_bindings;
