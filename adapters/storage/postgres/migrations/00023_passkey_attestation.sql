-- M9：passkey の attestation（design.md 9.4、ADR 0096。SQLite の 00040）。

-- +goose Up
ALTER TABLE authn_passkeys ADD COLUMN attestation_format TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE authn_passkeys ADD COLUMN attested BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE authn_passkeys DROP COLUMN attested;
ALTER TABLE authn_passkeys DROP COLUMN attestation_format;
