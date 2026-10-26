# 0059. 退会・除名・オーナーの譲渡

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.10、[0020](0020-leaving-and-deletion.md)、[0055](0055-org-foundation.md)、[0058](0058-org-and-membership-suspension.md)

## 背景

design.md 4.10 と ADR 0020 は、個人ユーザーの共有 Org からの退会を常に許し、Org には常に1人以上のオーナーを置くとする。
退会は有効期間の終わりと `ended_reason` で表し、active にしているセッションは個人 Org に切り替える。これを API と Storage で
どう実現するかを決める必要があった。

## 決定

- 退会（`POST /v1/me/orgs/{id}:leave`）と除名（`.../members/{membership_id}:remove`、`org:remove`）は同じ処理
  （`org.Service.end`）で、Membership を `ended` にし、`valid_until` を終了の時刻に、`ended_reason` を `left`・`removed` にする。
  結び付けたメールは外す（メールを消せるように）。監査ログは `membership.ended`
- 退会は停止中・有効期間の外でも許す（本人が関係を断てることを保証する）。除名は管理者の Org が使えるときだけ
- 最後のオーナー（active な owner が1人）は退会も除名もできない（`last_owner`）。数は `MembershipRepo.CountActive` で数える。
  同時に2人のオーナーが抜ける競合は、SQLite では書き込みの直列化で防ぐ。PostgreSQL の adapter では Org の行を
  ロックする（M6）
- その Org を active にしているセッションは `SessionRepo.MoveOrg` で個人 Org に移す。ID は入れ替えない（入れる範囲が狭まるだけなので）
- 再参加は新しい招待で。終わった Membership を再び active にして使う（Membership の ID は変わらない）
- オーナーの譲渡（`POST /v1/me/orgs/{id}:transfer`、`org:transfer`）は、譲り先を owner に、譲った本人を admin にする。
  譲り先は同じ Org の active なメンバー（でなければ `not_member`）。監査ログは `org.ownership_transferred`

## 後回し

- 予約した退会（未来の `valid_until` で抜ける）。今は有効期間の変更（ADR 0058）で代わりにできる
- Group 所属とロール付与を外す（M4）、Quota の枠（11.14）、`pre_membership_end` のフック（11.9）
- Org 管理ユーザーの退会の制限（管理ユーザーはまだ無い）

## 結果

- 本人はいつでも共有 Org から抜けられ、Org には必ずオーナーが残る
