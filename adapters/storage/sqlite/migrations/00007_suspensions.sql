-- M2：停止と、時刻の境界の出来事（design.md 3.1、4.7、4.8）。
-- 停止中かは時刻から計算する（starts_at ≤ 今 < min(ends_at, lifted_at)）。解除は削除せず lifted_at を記録する。
-- scheduled_events は境界の出来事の予約。発火したら fired_at を記録する。ref は取り消しの単位。

-- +goose Up
CREATE TABLE authn_suspensions (
    id           TEXT PRIMARY KEY,
    public_id    TEXT NOT NULL,
    realm_id     TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    category     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    external_ref TEXT NOT NULL,
    starts_at    TEXT NOT NULL,
    ends_at      TEXT,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    lifted_at    TEXT,
    lifted_by    TEXT NOT NULL,
    UNIQUE (realm_id, public_id)
) STRICT;

CREATE INDEX authn_suspensions_target ON authn_suspensions (realm_id, target_type, target_id);
CREATE UNIQUE INDEX authn_suspensions_external_ref ON authn_suspensions (realm_id, target_type, target_id, category, external_ref)
    WHERE external_ref <> '';

CREATE TABLE scheduled_events (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    ref        TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload    BLOB NOT NULL,
    fire_at    TEXT NOT NULL,
    fired_at   TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX scheduled_events_due ON scheduled_events (fire_at, id) WHERE fired_at IS NULL;
CREATE INDEX scheduled_events_ref ON scheduled_events (realm_id, ref);
