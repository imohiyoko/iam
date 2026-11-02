-- M9：本人がログインした端末（フィーチャー device_recognition。ADR 0105）。
-- lookup は端末の Cookie の乱数のブラインドインデックス（HMAC）。ユーザーごとに一意（同じブラウザを複数のユーザーが使える）。
-- data は端末の詳細（User-Agent・IP・場所など）で、ユーザーのデータ鍵で暗号化して置く（9.5）。

-- +goose Up
CREATE TABLE authn_known_devices (
    id           TEXT PRIMARY KEY,
    public_id    TEXT NOT NULL,
    realm_id     TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    lookup       BLOB NOT NULL,
    data         BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE (realm_id, public_id),
    UNIQUE (realm_id, user_id, lookup)
) STRICT;

-- +goose Down
DROP TABLE authn_known_devices;
