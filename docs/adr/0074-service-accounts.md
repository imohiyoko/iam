# 0074. 汎用サービスアカウントは管理 API で作り、API キーか client credentials の短命トークンで管理 API を使う

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 2.4、4.7、11.2、[0045](0045-internal-and-external-ids.md)

## 背景

M7 の最初に、Org または realm に属する機械の主体（11.2）を足す。これまでは通知の配信用のサービスアカウント（2.4）だけがあり、
作る手段がテストの中にしか無かった。

## 決定

- フィーチャー `service_accounts`（既定オフ）。配信用（ロール `system:notification_delivery` だけを持つもの）はフィーチャーにかかわらず作れる。
  `iam service-account create -name … [-role …]` で作り、API キーを1回だけ表示する。フィーチャーがオフならロールは配信用に限る
- サービスアカウントは realm か Org（`org_id`）に属し、有効期間（`valid_from`・`valid_until`）と停止（4.7）を持つ。
  Org が停止・削除されれば、その Org のサービスアカウントも使えない。削除は論理削除（`deleted_at`）で、以後は認証できない
- 管理 API：`/v1/admin/service-accounts`（作成・一覧・取得・削除）、`…/{id}/credentials`（作成・一覧・無効化）、
  `…/{id}/suspensions`。権限は `service_accounts:manage`（realm:owner と realm:admin）。ロールの付与と Group は既存の API で、principal を `service_account` にする
- 認証情報の種類：
  - `api_key`：`sac_….<秘密>` を Bearer で送る（これまでどおり）
  - `client_secret`：client credentials（RFC 6749 4.4）。`client_id` はサービスアカウントの ID、秘密は SHA-256 で持つ
  - `private_key_jwt`：client credentials の client assertion（RFC 7523）。公開鍵は JWK で登録し、`alg` は ES256・EdDSA・ML-DSA-65。
    `iss` と `sub` は `client_id`、`aud` は issuer（`server.public_url`）、`exp` は 5 分以内、`jti` は期限まで再利用を拒否する
- トークンのエンドポイントは管理 API の `POST /v1/admin/token`（form）。発行するのは不透明なアクセストークン `sat_….<秘密>`
  （SHA-256 で持つ。既定 10 分、`service_accounts.token_ttl`）。検証のたびにサービスアカウントの状態（削除・有効期間・停止）を確かめる
- 監査ログの主体は `service_account` とサービスアカウントの ID（外部 ID）

## 理由

- 管理 API は内部のネットワークに置くため、機械のトークンの発行も同じリスナーに置けば公開の面が増えない
- OIDC の Provider（zitadel/oidc）の client credentials は ML-DSA の client assertion を扱えず、RP とサービスアカウントは別の主体なので、別のエンドポイントにする
- 不透明なトークンなら、停止と削除が次の要求から効く

## 影響

- Org の管理者が公開 API で自分の Org のサービスアカウントを扱う口は後に回す（管理 API の `org_id` で作れる）
- 公開 API と OIDC のイントロスペクションは、サービスアカウントのトークンを受け付けない

## 検討した代替案

- JWT のアクセストークン：失効を待つ間に停止が効かない
- OIDC の RP（clients）に client credentials を足す：RP は利用者の代わりにログインする主体で、ロールの付与の対象にならない
