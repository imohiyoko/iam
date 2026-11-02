-- M11：Token Exchange（RFC 8693）の委任となりすまし（ADR 0099。SQLite の 00043）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN token_exchange BYTEA;

ALTER TABLE authn_oidc_grants ADD COLUMN exchange TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_oidc_grants ADD COLUMN parent_id TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_oidc_grants ADD COLUMN actor_user_id TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_oidc_grants ADD COLUMN act BYTEA;
ALTER TABLE authn_oidc_grants ADD COLUMN audiences TEXT COLLATE "C" NOT NULL DEFAULT '[]';

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
