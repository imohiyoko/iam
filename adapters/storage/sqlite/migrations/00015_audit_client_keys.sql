-- M3：監査ログの IP と User-Agent を暗号化する、realm と日ごとの鍵（design.md 9.6、ADR 0063）。
-- 保持期間の後に鍵を消すと、その日の全文は復号できなくなる（切り詰めた値はペイロードに平文で残る）。

-- +goose Up
CREATE TABLE shared_audit_client_keys (
    owner       TEXT PRIMARY KEY,
    wrapped_key BLOB NOT NULL,
    key_id      TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;
