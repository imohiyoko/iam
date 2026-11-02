-- M8：Front-Channel Logout の連携先の登録（フィーチャー oidc_logout。ADR 0094。SQLite の 00038）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN frontchannel_logout_uri TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_clients ADD COLUMN frontchannel_logout_session_required BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN frontchannel_logout_session_required;
ALTER TABLE authn_clients DROP COLUMN frontchannel_logout_uri;
