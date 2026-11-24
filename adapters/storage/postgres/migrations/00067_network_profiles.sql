-- ユーザーが普段使う接続元の一覧（フィーチャー session_binding。ADR 0128。SQLite の 00084）。

-- +goose Up
CREATE TABLE authn_network_profiles (
    realm_id   TEXT COLLATE "C" NOT NULL,
    user_id    TEXT COLLATE "C" NOT NULL,
    data       BYTEA NOT NULL,
    updated_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, user_id)
);

-- +goose Down
DROP TABLE authn_network_profiles;
