-- M3：Org の削除（design.md 4.10）。予定は猶予期間の終わり、削除した Org は墓標として行を残す。

-- +goose Up
ALTER TABLE orgs ADD COLUMN deletion_scheduled_at TEXT;
ALTER TABLE orgs ADD COLUMN deleted_at TEXT;
