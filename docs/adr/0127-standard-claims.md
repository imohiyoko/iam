# 0127. profile・phone・address の標準クレームは、カスタム属性に対応付けて出す

- 状態: 承認
- 日付: 2026-11-11
- 関連: [design.md](../design.md) 5.1、11.0、11.7、[0080](0080-custom-attributes.md)

## 背景

iam のスコープは `openid` と `email` だけで、`profile`・`phone`・`address` を求められても標準クレーム（OIDC Core 5.1）を返さなかった。
`name` や `locale` を前提にする RP（表示名を出す SaaS、言語を合わせるアプリ）は、iam の外で値を持つか、`attributes` クレームを
読む作り込みが要った。ユーザーには氏名などの項目が無く、realm ごとに要る項目は違う（姓名を分けるか、電話番号を持つか）。

## 決定

- フィーチャー `standard_claims`（既定オフ。`custom_attributes` に依存する）
- カスタム属性の定義に `claim`（標準クレームの名前）を足す。値はカスタム属性のもので、ユーザーに新しい項目は足さない
  - profile：`name`・`family_name`・`given_name`・`middle_name`・`nickname`・`preferred_username`・`profile`・`picture`・`website`・
    `gender`・`birthdate`・`zoneinfo`・`locale`（string か enum）
  - phone：`phone_number`（string か enum）、`phone_number_verified`（boolean）
  - address：`address.formatted`・`address.street_address`・`address.locality`・`address.region`・`address.postal_code`・
    `address.country`（string か enum）。ID トークン・UserInfo では `address` のオブジェクトにまとめる
  - `email`・`email_verified`・`sub`・`updated_at` は対応付けない（iam が持つ値か、属性から作れない値）
- 1 つの標準クレームは realm で 1 つの属性にだけ対応付ける（`409 claim_taken`。保存でも部分一意索引で守る）
- スコープ `profile`・`phone`・`address` を許した ID トークンと UserInfo に、対応付けた属性の値を載せる。`in_token` とは別で、
  暗号化した属性も載せる。値の無い属性は出さない
- Discovery の `scopes_supported` に 3 つのスコープを、`claims_supported` に対応付けられるクレームの名前を出す
- 無効化（片付け）は定義の `claim` を外す。属性と値は `custom_attributes` のものとして残る
- `claims` パラメーター（OIDC Core 5.5）はこの決定では扱わない（`acr` のほかは今までどおり読まない）

## 結果

- `profile` などを求める一般の RP が、realm で定義した属性から標準クレームを受け取れる
- 管理者が属性を作るまでは、スコープを許しても何も出ない（RP には「値が無い」と同じに見える）
- 値の形（`birthdate` の `YYYY-MM-DD`、`locale` の BCP 47、`phone_number` の E.164 など）は確かめない。enum や長さの制約で絞る

## 検討した代替案

- ユーザーに氏名などの項目を足す：realm ごとに要る項目が違い、使わない realm にも個人情報の列が増える
- 属性の key をクレームの名前にする（`name` という key の属性を `name` にする）：既存の属性と名前がぶつかり、address の下位の名前を表せない
- realm の設定で対応付けの表を持つ：定義と別の場所にあると、属性の削除・型の変更と食い違う
