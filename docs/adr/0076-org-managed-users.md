# 0076. Org 管理ユーザーは users.managed_org_id で表し、既存のユーザーは本人の同意で切り替える

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 4.10、11.3、[0075](0075-org-domain-verification.md)

## 背景

個人ユーザーは本人が所有し、Org は所属から外すことしかできない（11.3）。企業は、自社のドメインのアドレスを使う人の
アカウントを Org として所有し、退職などで扱いたい。所有が移ると本人の権利（退会・削除）が狭まるので、同意の手順が要る。

## 決定

- フィーチャー `org_managed_users`（ドメインの所有証明と同じ。ADR 0075）。`users.managed_org_id`（内部 ID）と `managed_at`
- 既存のユーザーは、Org の owner（`org:settings`）が `POST /v1/me/orgs/{id}/members/{membership_id}:request-management` で求め
  （`memberships.management_requested_at`）、本人が `POST /v1/me/orgs/{id}:accept-management` で受け入れる。`:decline-management` で断れる
- 対象は、この Org で使うメール（結び付けたメールか primary）が確認済みで、そのドメインを Org が証明済みのメンバー。
  ドメインは完全一致（サブドメインは別に証明する）。受け入れの時点でも確かめ直す。管理する Org は1つだけ
- 管理ユーザーはその Org を自分で抜けられず（`409 managed_user`）、自分でアカウントを消せない
- Org が `:release-management` で手放す・除名する・Org を削除すると、個人ユーザーに戻る
- 一覧（`/v1/me/orgs`・Org のメンバー一覧）に `managed` と `management_requested` を出す
- 監査ログ：`org.management.requested`・`declined`・`canceled`、`user.managed`、`user.management_released`
- フィーチャーを無効にするときは、管理ユーザーを個人ユーザーに戻し、ドメインを消す

## 理由

- 所有は Membership ではなくユーザーの属性（Org を抜けても所有は残りうる、という状態を作らない。除名で手放す）
- 同意を Membership の列で持てば、求めの一覧が Org と本人の両方から引ける。求めが終われば消える一時の状態なので、別のテーブルにしない
- ドメインの証明だけで既存のアカウントを取ると、個人で作ったアカウントを本人の知らないうちに失う

## 影響

- Org の owner による管理ユーザーの停止・削除、ログイン方法の強制、招待から新しく登録した人を最初から管理ユーザーにすることは、次の段で足す
- 管理ユーザーの削除（運営者）と、本人の削除の猶予期間（4.10）は変わらない

## 検討した代替案

- 証明済みドメインのアドレスのユーザーを自動で管理ユーザーにする：本人の同意が無い
- 管理の求めを別のテーブルに持つ：Membership と1対1で、終われば消える
