-- M11：連携先ごとに PAR（RFC 9126）を必須にするか（フィーチャー par）と、サービスアカウントのアクセストークンの aud と
-- スコープ（RFC 8707。フィーチャー resource_indicators）。audience が空のトークンは今までどおり管理 API 向け（ADR 0112）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN require_par INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authn_service_account_tokens ADD COLUMN audience TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_service_account_tokens ADD COLUMN scopes TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE authn_service_account_tokens DROP COLUMN scopes;
ALTER TABLE authn_service_account_tokens DROP COLUMN audience;
ALTER TABLE authn_clients DROP COLUMN require_par;
