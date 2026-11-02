-- M8：Front-Channel Logout の連携先の登録（フィーチャー oidc_logout。ADR 0094）。
-- frontchannel_logout_uri は空なら開かない。frontchannel_logout_session_required は 0 か 1。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN frontchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_clients ADD COLUMN frontchannel_logout_session_required INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN frontchannel_logout_session_required;
ALTER TABLE authn_clients DROP COLUMN frontchannel_logout_uri;
