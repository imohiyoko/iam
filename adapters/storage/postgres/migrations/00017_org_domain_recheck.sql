-- 証明済みのドメインの確かめ直し（ADR 0087。SQLite の 00034）。TXT が続けて見つからなくなった最初の時刻。

-- +goose Up
ALTER TABLE org_domains ADD COLUMN missing_since TEXT COLLATE "C";

-- +goose Down
ALTER TABLE org_domains DROP COLUMN missing_since;
