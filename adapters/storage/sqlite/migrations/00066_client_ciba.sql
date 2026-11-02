-- M9：連携先ごとの CIBA のトークンの受け取り方と ping の通知先（フィーチャー ciba。ADR 0114）。

-- +goose Up
ALTER TABLE authn_clients ADD COLUMN ciba_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_clients ADD COLUMN ciba_notification_endpoint TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE authn_clients DROP COLUMN ciba_notification_endpoint;
ALTER TABLE authn_clients DROP COLUMN ciba_mode;
