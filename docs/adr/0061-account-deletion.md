# 0061. アカウントの削除

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.10、9.5、[0020](0020-leaving-and-deletion.md)、[0059](0059-leaving-removal-and-transfer.md)、[0060](0060-org-deletion-and-scheduled-cleanup.md)

## 背景

design.md 4.10 と ADR 0020 は、アカウントの削除を猶予期間（既定30日）の後に行い、その間はログインできず本人確認で取り消せる、
猶予の後はデータ鍵を消して（crypto-shredding）個人情報を読めなくし、ID は墓標として残す、運営者は legal hold で消去を
保留できる、とする。「ログインできないが本人確認で取り消せる」をどう実現するかと、消すものの範囲を決める必要があった。

## 決定

- 予約（本人は `POST /v1/me/account:delete`、直近の本人確認が要る。運営者は `POST /v1/admin/users/{id}:delete`、`users:delete`）は
  `users.deletion_scheduled_at` を猶予期間の終わりにし、`user.deleted` を予約する（ADR 0060 の後始末）。既存のセッションは
  すべて失効させる。運営者は `immediate` で今消せる。共有 Org の最後のオーナーの間は、本人も運営者もできない（`last_owner`）
- 猶予期間の間のログインは、本人確認（2要素目まで）の後に取り消し専用のセッション（`RestrictionDeletion`、
  `next: cancel_deletion`）を発行する。使えるのは `POST /v1/me/account:cancel-deletion` とログアウトだけで、取り消すと
  同じ本人確認のまま通常のセッションに入れ替わる。通常のセッションは、削除の予定があれば検証で拒む
- legal hold（`POST /v1/admin/users/{id}:legal-hold`、`users:legal_hold`、realm:owner だけ）の間は、猶予が終わっても消さず
  `user.deletion_held` を残す（`user.deleted` は出さない。Handler が `eventlog.ErrSkip` を返す）。保留を解いたときに猶予が
  終わっていれば、次の回に消すよう予約し直す
- 消去
  - 共有 Org の所属を `account_deleted` で終える。猶予の間に最後のオーナーになっていても終える（Org は運営者が引き継ぐ）
  - 個人 Org を削除する
  - `UserRepo.Erase` で、メール（インデックスごと。同じアドレスで新しく登録できる）・外部 ID の紐付け・passkey・TOTP・
    パスワード・リカバリーコード・セッション・ロールの付与を消し、ユーザーを `deleted` の墓標にする
  - データ鍵を消す。残った暗号文（監査ログなど）は復号できなくなる
  - 停止の記録と監査ログは残す（個人情報は持たない。監査ログの IP と UA は #52 の残りで暗号化する）

## 後回し

- Back-Channel Logout による通知（M5）
- Org 管理ユーザーの削除（管理ユーザーはまだ無い）

## 結果

- 本人は猶予の間いつでも取り消せ、猶予の後は個人情報を復号できない
