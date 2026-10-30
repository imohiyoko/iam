-- M8：付与の条件（ADR 0084。SQLite の 00032）。

-- +goose Up
ALTER TABLE authz_role_bindings ADD COLUMN condition BYTEA NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authz_role_bindings DROP COLUMN condition;
