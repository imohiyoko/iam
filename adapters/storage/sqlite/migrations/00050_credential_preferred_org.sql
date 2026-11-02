-- M9：passkey を認証方式のポートに移す（ADR 0106）。汎用の認証情報に、passkey の表にあった列を足す。
-- preferred_org_id はこの認証情報でログインしたときに入る Org（4.4。空文字は指定なし）。
-- reserve_lookup は、無効化で検索キーを退役済み（authn_retired_credential_lookups）に加える印（passkey の credential ID。4.6）。

-- +goose Up
ALTER TABLE authn_credentials ADD COLUMN preferred_org_id TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_credentials ADD COLUMN reserve_lookup INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_credentials DROP COLUMN reserve_lookup;
ALTER TABLE authn_credentials DROP COLUMN preferred_org_id;
