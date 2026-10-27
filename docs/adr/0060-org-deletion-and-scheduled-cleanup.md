# 0060. Org の削除と、予約した後始末

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.8、4.10、[0053](0053-user-suspension-and-validity.md)、[0056](0056-invitations-and-membership-email.md)、[0059](0059-leaving-removal-and-transfer.md)

## 背景

design.md 4.10 は、Org の削除をオーナーか運営者が猶予期間つきで行い、全 Membership を `org_deleted` で終えるとする。
猶予の後に処理を動かす仕組みが要る。ADR 0056 は、期限の過ぎた pending の招待のアドレスの鍵を後で消すとして残していた。
どちらも「時刻を過ぎたら一度だけ動かす処理」で、時刻の境界のイベント（`scheduled_events`。4.8）と同じ形になる。

## 決定

- `eventlog.Scheduler` に、出来事の種類ごとの後始末（`Handler`）を持たせる。発火の記録と監査ログと同じトランザクションで
  呼ぶので、複数のインスタンスでも1回だけ動く。失敗すれば全体を取り消し、次の回にやり直す
- Org の削除
  - `orgs` に `deletion_scheduled_at`・`deleted_at` を足す。削除した Org は墓標として行を残す
  - 予約（本人は `POST /v1/me/orgs/{id}:delete`、`org:delete`。運営者は `POST /v1/admin/orgs/{id}:delete`、`orgs:delete`）は
    `realm.org_deletion_grace`（既定30日）の後に `org.deleted` を予約する。運営者は `immediate` で今削除できる
  - 猶予期間の間はメンバーが入れない（`deletion_scheduled`。`org.Check`）。オーナーと運営者は取り消せる（`:cancel-deletion`）
  - 削除では、全 Membership を `org_deleted` で終え（セッションは個人 Org に移る。ADR 0059）、pending の招待を取り消して
    アドレスの鍵を消し、`deleted_at` を記録する。削除した Org には入れず、操作もできない
  - サービスアカウント・Group・ロール・Quota・ポリシーの削除は、それぞれを作る段で足す
- 招待の後始末：招待の作成で、期限の時刻に `org.invitation.expired` を予約する。発火で pending の招待を `expired` にし、
  アドレスの鍵を消す。受け入れ・取り消しでは予約を取り消す

## 結果

- 猶予期間つきの処理を、予約の仕組みに乗せて書ける（アカウントの削除も同じ形にする）
- 期限の過ぎた招待のアドレスは、期限から `outbox.interval` ほどの後には復号できなくなる
