-- M10：監査ログの照会の索引と、イベントの Webhook の購読（ADR 0100。SQLite の 00044）。
-- 索引はペイロードから作る値で、ハッシュの対象外（audit.IndexOf と同じ規則で埋め戻す）。

-- +goose Up
ALTER TABLE shared_audit_events ADD COLUMN event_id TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN occurred_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE shared_audit_events ADD COLUMN event_type TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN result TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN actor_type TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN actor_id TEXT COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE shared_audit_events ADD COLUMN org_id TEXT COLLATE "C" NOT NULL DEFAULT '';

UPDATE shared_audit_events e SET
    event_id      = coalesce(p.j->>'id', ''),
    occurred_unix = coalesce(floor(extract(epoch FROM (p.j->>'time')::timestamptz))::bigint, 0),
    event_type    = coalesce(p.j->>'type', ''),
    result        = coalesce(p.j->>'result', ''),
    actor_type    = coalesce(p.j->'actor'->>'type', ''),
    actor_id      = coalesce(p.j->'actor'->>'id', ''),
    org_id        = coalesce(p.j->>'org_id', '')
FROM (SELECT seq, convert_from(payload, 'UTF8')::jsonb AS j FROM shared_audit_events) p
WHERE p.seq = e.seq;

CREATE INDEX shared_audit_events_event_id ON shared_audit_events (realm_id, event_id);
CREATE INDEX shared_audit_events_type ON shared_audit_events (realm_id, event_type, seq);
CREATE INDEX shared_audit_events_actor ON shared_audit_events (realm_id, actor_id, seq);
CREATE INDEX shared_audit_events_org ON shared_audit_events (realm_id, org_id, seq);

-- 対象の ID（details の、名前が _id で終わる文字列の値）。
CREATE TABLE shared_audit_refs (
    realm_id TEXT COLLATE "C" NOT NULL,
    ref_id   TEXT COLLATE "C" NOT NULL,
    seq      BIGINT NOT NULL,
    PRIMARY KEY (realm_id, ref_id, seq)
);
CREATE INDEX shared_audit_refs_seq ON shared_audit_refs (seq);

INSERT INTO shared_audit_refs (realm_id, ref_id, seq)
SELECT e.realm_id, d.value #>> '{}', e.seq
FROM shared_audit_events e, jsonb_each(CASE WHEN jsonb_typeof(convert_from(e.payload, 'UTF8')::jsonb->'details') = 'object'
    THEN convert_from(e.payload, 'UTF8')::jsonb->'details' ELSE '{}'::jsonb END) d
WHERE jsonb_typeof(d.value) = 'string' AND right(d.key, 3) = '_id' AND length(d.value #>> '{}') BETWEEN 1 AND 200
ON CONFLICT DO NOTHING;

CREATE TABLE shared_event_subscriptions (
    id                TEXT COLLATE "C" PRIMARY KEY,
    realm_id          TEXT COLLATE "C" NOT NULL,
    url               TEXT COLLATE "C" NOT NULL,
    event_types       TEXT COLLATE "C" NOT NULL,
    pii               TEXT COLLATE "C" NOT NULL,
    enabled           BIGINT NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    created_by        TEXT COLLATE "C" NOT NULL,
    created_at        TEXT COLLATE "C" NOT NULL,
    updated_at        TEXT COLLATE "C" NOT NULL,
    cursor_seq        BIGINT NOT NULL,
    failures          BIGINT NOT NULL,
    next_attempt_at   TEXT COLLATE "C",
    last_error        TEXT COLLATE "C" NOT NULL,
    last_delivered_at TEXT COLLATE "C"
);
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
