-- M6：保持期間（design.md 6.5、9.6。SQLite の 00020）。

-- +goose Up
CREATE TABLE shared_audit_checkpoint (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    seq        BIGINT NOT NULL,
    hash       BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL
);

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
