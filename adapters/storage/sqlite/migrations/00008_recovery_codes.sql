-- M2：リカバリーコード（design.md 4.12）。コードは argon2id の PHC 文字列で持ち、先頭の数文字（lookup）で照合するものを絞る。
-- 作り直すときはユーザーの行をすべて消して入れ直す。

-- +goose Up
CREATE TABLE authn_recovery_codes (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    lookup     TEXT NOT NULL,
    hash       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at    TEXT
) STRICT;

CREATE UNIQUE INDEX authn_recovery_codes_lookup ON authn_recovery_codes (realm_id, user_id, lookup);
