-- M6：保持期間（design.md 6.5、9.6）。監査ログの切り詰めの位置（最後に消したレコード）を1行だけ持つ。
-- 削除の対象を探す索引を足す。

-- +goose Up
CREATE TABLE shared_audit_checkpoint (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    seq        INTEGER NOT NULL,
    hash       BLOB NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX shared_outbox_delivered ON shared_outbox (delivered_at) WHERE delivered_at IS NOT NULL;
CREATE INDEX scheduled_events_fired ON scheduled_events (fired_at) WHERE fired_at IS NOT NULL;
CREATE INDEX authn_sessions_expires ON authn_sessions (expires_at);
CREATE INDEX authn_sessions_revoked ON authn_sessions (revoked_at) WHERE revoked_at IS NOT NULL;

-- +goose Down
DROP INDEX authn_sessions_revoked;
DROP INDEX authn_sessions_expires;
DROP INDEX scheduled_events_fired;
DROP INDEX shared_outbox_delivered;
DROP TABLE shared_audit_checkpoint;
