-- M11：WS-Federation の RP ごとの署名のアルゴリズム（ADR 0125。SQLite の 00081）。

-- +goose Up
ALTER TABLE authn_wsfed_relying_parties ADD COLUMN signing_alg TEXT NOT NULL DEFAULT 'ES256';

-- +goose Down
ALTER TABLE authn_wsfed_relying_parties DROP COLUMN signing_alg;
