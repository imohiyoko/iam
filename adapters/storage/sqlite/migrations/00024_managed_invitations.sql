-- M7：管理ユーザーとして招く（design.md 11.3、ADR 0076）。受け入れで新しく登録した人は管理ユーザーになり、
-- 既存のユーザーには管理を求める（本人の同意を待つ）。

-- +goose Up
ALTER TABLE invitations ADD COLUMN managed INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE invitations DROP COLUMN managed;
