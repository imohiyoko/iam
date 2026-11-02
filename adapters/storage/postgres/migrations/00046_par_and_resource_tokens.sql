-- M11：連携先ごとの PAR（RFC 9126）の必須と、サービスアカウントのアクセストークンの aud とスコープ（RFC 8707。ADR 0112。
-- SQLite の 00063）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN require_par BIGINT NOT NULL DEFAULT 0;
ALTER TABLE authn_service_account_tokens ADD COLUMN audience TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_service_account_tokens ADD COLUMN scopes TEXT COLLATE "C" NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE authn_service_account_tokens DROP COLUMN scopes;
ALTER TABLE authn_service_account_tokens DROP COLUMN audience;
ALTER TABLE authn_clients DROP COLUMN require_par;
