-- M11：連携先ごとにアクセストークンを JWT（RFC 9068）で出すか（フィーチャー jwt_access_tokens。ADR 0123）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN jwt_access_tokens INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN jwt_access_tokens;
