-- M8：認可の acr（フィーチャー acr、ADR 0093）。空ならフィーチャーがオフのときの認可で、acr を返さない。

-- +goose Up
ALTER TABLE authn_oidc_grants ADD COLUMN acr TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_oidc_grants DROP COLUMN acr;
