-- M9：WS-Federation の署名の証明書（ADR 0110。SQLite の 00059）。

-- +goose Up
CREATE TABLE authn_wsfed_certificates (
    realm_id   TEXT COLLATE "C" NOT NULL,
    key_id     TEXT COLLATE "C" NOT NULL,
    der        BYTEA NOT NULL,
    created_at TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (realm_id, key_id)
);

-- +goose Down
DROP TABLE authn_wsfed_certificates;
