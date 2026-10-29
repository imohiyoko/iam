# 0053. ユーザーの停止と有効期間

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.7、4.8、4.9、4.11、4.13、5.3、[0022](0022-deny-reason-disclosure.md)、[0052](0052-admin-credential-revocation.md)

## 背景

M2 ではユーザーの停止（種別つき、予約、重ね掛け）と有効期間を作る（Org・Membership・サービスアカウントは M3）。design.md は
「判定は時刻から計算し、境界のイベントは `scheduled_events` から出す」とだけ決めており、セッションとの関係、権限、API の細部を
決める必要があった。

## 決定

- 判定（`account.Check`）は保存した時刻から計算する。スケジューラの遅れに左右されない
  - `status` が active でなければ理由を返さない（削除・統合済み）
  - 有効期間の外なら `outside_validity`、停止中なら `suspended.<category>`（種別ごとに1つ、すべて返す）。本人確認の後の
    拒否なので理由を返し（4.9）、`reason` は返さない
  - 停止の期間は `[starts_at, min(ends_at, lifted_at))`。始まる前に解除した予約は効かない
- セッションの検証でも同じ判定をする。停止の判定の始まりは認証の時刻で、**停止をまたいだセッションは解除の後も戻らない**
  （再ログインが要る）。次に可否が変わる時刻（予約の開始、`valid_until`）を検証のキャッシュの期限に入れ、境界の時刻ちょうどに効かせる
- 停止・有効期間の変更の後は、そのユーザーのセッションの検証のキャッシュを消す（すぐに効く。消せなくても `validity_max_delay` 以内）
- ログインでの判定は本人確認の後に行う（パスワードは照合が通った後）。本人確認の前の応答は変えない（0022）
- 境界のイベント：停止の開始（予約のとき）と終わり、有効期間の始まりと終わりを `scheduled_events` に予約し、`eventlog.Scheduler` が
  時刻の後に監査ログ（と outbox）に出す（`user.suspension_started` など）。発火の記録と監査ログは同じトランザクションで書き、
  複数のインスタンスでも1回だけ出る。解除・有効期間の置き換えでは未発火の予約を取り消す
- 権限は種別ごと（4.11）：`suspensions:<category>` を `realm:owner`（すべて）、`realm:admin`（`tos_violation`・`customer_request`）、
  `realm:security`（`security_risk`）、`realm:billing`（`billing`）に付ける。realm で足した種別（`security.suspension_categories`）は
  `realm:owner`（`suspensions:*`）だけ。一覧は `suspensions:read`、有効期間の変更は `users:update`
- 本人は自分の停止を解除できない（予約も）
- ユーザーの停止・解除と有効期間の変更は、呼び出し側が対象のロールの権限をすべて持つときだけ（なりすましと同じ outranks の判定。
  下位のロールの運営者が上位の運営者を止めない。足りなければ `403 permission_denied`）
- 管理 API：
  - `POST /v1/admin/users/{id}/suspensions`：`{category, reason, starts_at, ends_at, external_ref}`。`reason` は必須（4.13）。
    `starts_at` が省略か過去なら今から（遡らない）。`external_ref` が同じ停止（対象・種別も同じ）があれば 200 でそれを返す（冪等）
  - `GET /v1/admin/users/{id}/suspensions`、`POST /v1/admin/suspensions/{id}:lift`（`{reason}` が必須）
  - `PATCH /v1/admin/users/{id}`：`{valid_from, valid_until}` の両方を置き換える（省略か null は制限なし）。片方だけの変更は
    受け付けない（省略と null を区別しない生成コードに合わせ、取り違えを防ぐ）
- ホスト型ログイン画面は種別ごとの文言（4.7 の表）を出し、realm で足した種別には共通の文言を出す

## 結果

- 予約した停止と有効期間の境界は、偽の時計で時刻ちょうどに効くことを確かめられる
- Org・Membership・サービスアカウントの停止は M3 で、同じ `authn_suspensions` と `Check` の形を広げて足す
- Back-Channel Logout による連携先への通知は M5 で足す
