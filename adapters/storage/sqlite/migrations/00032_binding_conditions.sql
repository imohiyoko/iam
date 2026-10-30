-- M8：付与の条件（ADR 0084）。条件の言語の型付きの木（JSON）。空なら条件なし。

-- +goose Up
ALTER TABLE authz_role_bindings ADD COLUMN condition BLOB NOT NULL DEFAULT x'';

-- +goose Down
ALTER TABLE authz_role_bindings DROP COLUMN condition;
