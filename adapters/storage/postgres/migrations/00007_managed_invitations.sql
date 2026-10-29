-- M7：管理ユーザーとして招く（design.md 11.3、ADR 0076。SQLite の 00024）。

-- +goose Up
ALTER TABLE invitations ADD COLUMN managed BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE invitations DROP COLUMN managed;
