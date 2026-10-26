-- M3：アカウントの削除（design.md 4.10）。予定は猶予期間の終わり、legal_hold は運営者による消去の保留。

-- +goose Up
ALTER TABLE authn_users ADD COLUMN deletion_scheduled_at TEXT;
ALTER TABLE authn_users ADD COLUMN legal_hold INTEGER NOT NULL DEFAULT 0;
