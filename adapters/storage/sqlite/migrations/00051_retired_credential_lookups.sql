-- M9：退役した検索キー（ADR 0106）。無効化した passkey の credential ID（のブラインドインデックス）を残し、持ち主を消した後も
-- 同じ realm・方式で再登録させない（4.6。authn_revoked_passkey_credentials の汎用版。移行で写す）。
-- lookup_key_id はインデックス鍵の ID（鍵を切り替えた後も前の鍵で引く）。

-- +goose Up
CREATE TABLE authn_retired_credential_lookups (
    realm_id      TEXT NOT NULL,
    method        TEXT NOT NULL,
    lookup        BLOB NOT NULL,
    lookup_key_id TEXT NOT NULL,
    retired_at    TEXT NOT NULL,
    PRIMARY KEY (realm_id, method, lookup)
) STRICT;

-- +goose Down
DROP TABLE authn_retired_credential_lookups;
