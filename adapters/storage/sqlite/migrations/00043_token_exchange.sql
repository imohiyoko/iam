-- M11：Token Exchange（RFC 8693）の委任となりすまし（ADR 0099）。連携先ごとに許す交換と、交換で作った認可の印。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN token_exchange BLOB; -- JSON（provider.ExchangePolicy）。NULL なら何も許さない

ALTER TABLE authn_oidc_grants ADD COLUMN exchange TEXT NOT NULL DEFAULT ''; -- delegation / impersonation。空なら認可コードの認可
ALTER TABLE authn_oidc_grants ADD COLUMN parent_id TEXT NOT NULL DEFAULT ''; -- 交換の元の認可
ALTER TABLE authn_oidc_grants ADD COLUMN actor_user_id TEXT NOT NULL DEFAULT ''; -- 行為者のユーザー（なりすましの運営者など）
ALTER TABLE authn_oidc_grants ADD COLUMN act BLOB; -- act クレーム（JSON）
ALTER TABLE authn_oidc_grants ADD COLUMN audiences TEXT NOT NULL DEFAULT '[]'; -- JSON の配列

CREATE INDEX authn_oidc_grants_actor ON authn_oidc_grants (realm_id, actor_user_id) WHERE actor_user_id <> '';
CREATE INDEX authn_oidc_grants_exchange ON authn_oidc_grants (exchange) WHERE exchange <> '';

-- +goose Down
DROP INDEX authn_oidc_grants_exchange;
DROP INDEX authn_oidc_grants_actor;
ALTER TABLE authn_oidc_grants DROP COLUMN audiences;
ALTER TABLE authn_oidc_grants DROP COLUMN act;
ALTER TABLE authn_oidc_grants DROP COLUMN actor_user_id;
ALTER TABLE authn_oidc_grants DROP COLUMN parent_id;
ALTER TABLE authn_oidc_grants DROP COLUMN exchange;
ALTER TABLE authn_clients DROP COLUMN token_exchange;
