-- M8：認可の acr（フィーチャー acr、ADR 0093。SQLite の 00037）。

-- +goose Up
ALTER TABLE authn_oidc_grants ADD COLUMN acr TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_oidc_grants DROP COLUMN acr;
