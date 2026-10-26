-- M3：Org の段のセキュリティ設定（design.md 2.8、5.4、10章）。NULL は未設定（realm に従う）。

-- +goose Up
ALTER TABLE orgs ADD COLUMN settings BLOB;
