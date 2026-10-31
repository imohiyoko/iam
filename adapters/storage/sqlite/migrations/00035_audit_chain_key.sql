-- 監査ログのハッシュチェーンの鍵（ADR 0086）。ハッシュを計算した監査の鍵の ID（空なら鍵なし）。

-- +goose Up
ALTER TABLE shared_audit_events ADD COLUMN key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE shared_audit_checkpoint ADD COLUMN key_id TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE shared_audit_checkpoint DROP COLUMN key_id;
ALTER TABLE shared_audit_events DROP COLUMN key_id;
