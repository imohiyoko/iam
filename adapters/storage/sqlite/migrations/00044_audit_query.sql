-- M10：監査ログの照会の索引と、イベントの Webhook の購読（ADR 0100）。
-- 索引はペイロードから作る値で、ハッシュの対象外（audit.IndexOf と同じ規則で埋め戻す）。

-- +goose Up
ALTER TABLE shared_audit_events ADD COLUMN event_id TEXT NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN occurred_unix INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shared_audit_events ADD COLUMN event_type TEXT NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN result TEXT NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN actor_type TEXT NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN actor_id TEXT NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN org_id TEXT NOT NULL DEFAULT '';

UPDATE shared_audit_events SET
    event_id      = coalesce(json_extract(CAST(payload AS TEXT), '$.id'), ''),
    occurred_unix = coalesce(unixepoch(json_extract(CAST(payload AS TEXT), '$.time')), 0),
    event_type    = coalesce(json_extract(CAST(payload AS TEXT), '$.type'), ''),
    result        = coalesce(json_extract(CAST(payload AS TEXT), '$.result'), ''),
    actor_type    = coalesce(json_extract(CAST(payload AS TEXT), '$.actor.type'), ''),
    actor_id      = coalesce(json_extract(CAST(payload AS TEXT), '$.actor.id'), ''),
    org_id        = coalesce(json_extract(CAST(payload AS TEXT), '$.org_id'), '');

CREATE INDEX shared_audit_events_event_id ON shared_audit_events (realm_id, event_id);
CREATE INDEX shared_audit_events_type ON shared_audit_events (realm_id, event_type, seq);
CREATE INDEX shared_audit_events_actor ON shared_audit_events (realm_id, actor_id, seq);
CREATE INDEX shared_audit_events_org ON shared_audit_events (realm_id, org_id, seq);

-- 対象の ID（details の、名前が _id で終わる文字列の値）。
CREATE TABLE shared_audit_refs (
    realm_id TEXT NOT NULL,
    ref_id   TEXT NOT NULL,
    seq      INTEGER NOT NULL,
    PRIMARY KEY (realm_id, ref_id, seq)
) STRICT;
CREATE INDEX shared_audit_refs_seq ON shared_audit_refs (seq);

INSERT OR IGNORE INTO shared_audit_refs (realm_id, ref_id, seq)
SELECT e.realm_id, d.value, e.seq FROM shared_audit_events e, json_each(CAST(e.payload AS TEXT), '$.details') d
WHERE d.type = 'text' AND length(d.key) >= 3 AND substr(d.key, length(d.key) - 2) = '_id' AND length(d.value) BETWEEN 1 AND 200;

CREATE TABLE shared_event_subscriptions (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL,
    url               TEXT NOT NULL,
    event_types       TEXT NOT NULL, -- JSON の配列
    pii               TEXT NOT NULL,
    enabled           INTEGER NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    created_by        TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    cursor_seq        INTEGER NOT NULL,
    failures          INTEGER NOT NULL,
    next_attempt_at   TEXT,
    last_error        TEXT NOT NULL,
    last_delivered_at TEXT
) STRICT;
CREATE INDEX shared_event_subscriptions_realm ON shared_event_subscriptions (realm_id, created_at, id);

-- +goose Down
DROP TABLE shared_event_subscriptions;
DROP TABLE shared_audit_refs;
DROP INDEX shared_audit_events_org;
DROP INDEX shared_audit_events_actor;
DROP INDEX shared_audit_events_type;
DROP INDEX shared_audit_events_event_id;
ALTER TABLE shared_audit_events DROP COLUMN org_id;
ALTER TABLE shared_audit_events DROP COLUMN actor_id;
ALTER TABLE shared_audit_events DROP COLUMN actor_type;
ALTER TABLE shared_audit_events DROP COLUMN result;
ALTER TABLE shared_audit_events DROP COLUMN event_type;
ALTER TABLE shared_audit_events DROP COLUMN occurred_unix;
ALTER TABLE shared_audit_events DROP COLUMN event_id;
