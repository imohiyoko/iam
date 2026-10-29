-- M7：アカウント統合（design.md 11.6、ADR 0082）。merged_into は統合先のユーザー（内部 ID）。
-- user_handle は passkey の登録時のユーザーハンドル（空なら持ち主の公開 ID。統合で移した passkey は元のユーザーの公開 ID）。

-- +goose Up
ALTER TABLE authn_users ADD COLUMN merged_into TEXT;
ALTER TABLE authn_passkeys ADD COLUMN user_handle BLOB NOT NULL DEFAULT x'';

-- +goose Down
ALTER TABLE authn_passkeys DROP COLUMN user_handle;
ALTER TABLE authn_users DROP COLUMN merged_into;
