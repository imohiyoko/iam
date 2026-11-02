-- M11：送信者制約トークン（DPoP・RFC 9449、OAuth の mTLS・RFC 8705。フィーチャー dpop・mtls_client_auth。ADR 0113）。
-- 連携先の設定と、トークンを結び付けた鍵（jkt）・証明書（x5t#S256）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN dpop_bound_access_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authn_clients ADD COLUMN tls_bound_access_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authn_clients ADD COLUMN tls_auth_field TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_clients ADD COLUMN tls_auth_value TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_oidc_tokens ADD COLUMN jkt TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_oidc_tokens ADD COLUMN x5t TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_service_account_tokens ADD COLUMN jkt TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_service_account_tokens DROP COLUMN jkt;
ALTER TABLE authn_oidc_tokens DROP COLUMN x5t;
ALTER TABLE authn_oidc_tokens DROP COLUMN jkt;
ALTER TABLE authn_clients DROP COLUMN tls_auth_value;
ALTER TABLE authn_clients DROP COLUMN tls_auth_field;
ALTER TABLE authn_clients DROP COLUMN tls_bound_access_tokens;
ALTER TABLE authn_clients DROP COLUMN dpop_bound_access_tokens;
