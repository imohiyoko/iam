-- M9：本人がログインした端末（フィーチャー device_recognition。ADR 0105。SQLite の 00049）。

-- +goose Up
CREATE TABLE authn_known_devices (
    id           TEXT COLLATE "C" PRIMARY KEY,
    public_id    TEXT COLLATE "C" NOT NULL,
    realm_id     TEXT COLLATE "C" NOT NULL,
    user_id      TEXT COLLATE "C" NOT NULL,
    lookup       BYTEA NOT NULL,
    data         BYTEA NOT NULL,
    created_at   TEXT COLLATE "C" NOT NULL,
    last_seen_at TEXT COLLATE "C" NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, user_id, lookup)
);

-- +goose Down
DROP TABLE authn_known_devices;
