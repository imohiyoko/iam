-- M11：連携先ごとの JWT のアクセストークン（ADR 0123。SQLite の 00080）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN jwt_access_tokens BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN jwt_access_tokens;
