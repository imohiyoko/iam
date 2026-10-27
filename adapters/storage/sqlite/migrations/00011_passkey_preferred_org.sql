-- M3：passkey ごとの、ログインで入る Org（design.md 3.1、4.4）。空文字は指定なし。

-- +goose Up
ALTER TABLE authn_passkeys ADD COLUMN preferred_org_id TEXT NOT NULL DEFAULT '';
