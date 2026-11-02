-- M9：連携先ごとに Device Authorization Grant（RFC 8628）を許すか（フィーチャー device_flow。ADR 0095。SQLite の 00039）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN device_grant BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN device_grant;
