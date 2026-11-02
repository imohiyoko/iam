-- M9：passkey の attestation（design.md 9.4、ADR 0096）。attestation_format は登録のときの attestation の形式
-- （空はこの列を足す前に登録したもの）。attested は証明書の連なりを信頼の起点（MDS か設定）まで確かめたか。
-- 既存の行は attestation を確かめていない（attested = 0）。AAGUID は前から持っている（認証器の自己申告）。

-- +goose Up
ALTER TABLE authn_passkeys ADD COLUMN attestation_format TEXT NOT NULL DEFAULT '';
ALTER TABLE authn_passkeys ADD COLUMN attested INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_passkeys DROP COLUMN attested;
ALTER TABLE authn_passkeys DROP COLUMN attestation_format;
