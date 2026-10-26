# 0058. Org と Membership の停止と有効期間

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.7、4.8、4.9、5.3、[0053](0053-user-suspension-and-validity.md)、[0055](0055-org-foundation.md)、[0057](0057-org-selection-and-switching.md)

## 背景

design.md 4.7・4.8 は、ユーザーと同じく Org と Membership にも停止と有効期間を持たせ、「Org を止めればメンバーが入れず、
その Org を active にしているセッションは個人 Org に切り替えるまで Org の操作ができない」「Membership を止めればその Org にだけ
入れない」とする。Org の管理者は自分の Org の Membership を customer_request で止められる。ユーザーの停止（0053）の仕組みを
どこまで使い回し、セッション・ログイン・Org の操作のどこで判定するかを決める必要があった。

## 決定

- 停止の表（`suspensions`）と判定の規則はユーザーと共有する。`account.Suspend` は対象（`account.Target`：種類・内部 ID・
  公開 ID）を取り、監査ログの種類と詳細の鍵は対象で変わる（`org.suspended`、`membership.suspension_lifted`、`org_id` など）。
  有効期間の境界のイベント（`<対象>.validity_started`・`_ended`）も同じ
- 可否は `org.Check(Org, Membership, now)` が時刻から計算する。Org と Membership の有効期間・停止の理由を合わせて返す
  （`*account.UnavailableError`）。個人 Org は止められず有効期間も持たない（本人の可否はユーザーの検証で見る）
- ユーザーの停止と違い、Org・Membership の停止は解除すれば戻る（判定の始まりは常に now。停止をまたいだセッションも戻る）。
  これはユーザー本人への措置ではなく、Org という場への措置だから。セッションも失効させない
- 判定する場所
  - ログイン（`Pick`）：使えない Org は候補から外す。明示的な指定（切り替え・2要素目の続き・招待からの登録）で使えなければ理由を返す
  - セッションの検証：active な Org が使えなければ `Validated.OrgUnavailable` に理由を載せる（セッションは有効なまま）。
    次の判定の時刻（予約や有効期間の終わり）もキャッシュの期限に入れる
  - Org の操作（`/v1/me/orgs/{id}/...`）：その場で `org.Check` を呼び、使えなければ `403` と理由（`suspended.<category>`、
    `outside_validity`）。キャッシュを通さないので遅れは無い
  - 自分の Org の一覧は、入れない Org に `unavailable`（理由）を付ける
- 運営者の API：`/v1/admin/orgs/{id}`・`/v1/admin/memberships/{id}` の PATCH（有効期間、権限 `orgs:update`）と
  `/suspensions`（権限は種別ごと。ユーザーと同じ）。停止の表示は `target_type`・`target_id`（と、ユーザーと Membership なら `user_id`）
- Org の管理者の API：`/v1/me/orgs/{id}/members/{membership_id}` の PATCH（有効期間、`org:invite`）、`/suspensions`
  （customer_request だけ、`org:suspend`）、`/v1/me/orgs/{id}/suspensions/{id}:lift`。本人は対象にできず（`self_target`）、
  owner を対象にできるのは owner だけ（招待と同じ）。一覧に運営者による停止は出さず、解除もできない
- 検証結果のキャッシュは、Membership の変更では本人の分を消す。Org の停止は全メンバーの分を消さず、`validity_max_delay`
  の保証に任せる（Org の操作はキャッシュを通さず判定するので、保証が要るのはセッションの表示だけ）

## 後回し

- Org の停止で、その Org のサービスアカウントと管理ユーザーを止める（どちらもまだ無い。管理ユーザーを止めるかは停止時に選ぶ）
- Membership の作成・変更時の前提条件（Quota、ドメイン。11.3、11.14）

## 結果

- 停止・有効期間の判定の規則が対象で揃い、監査ログも同じ形で出る
- 停止中の Org にいるメンバーは、セッションを失わずに個人 Org へ切り替えて作業を続けられる
