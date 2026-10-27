# 0077. Org 専用 SSO は Org の管理ユーザーのための OIDC の connection にする

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 4.1、4.4、11.3、[0075](0075-org-domain-verification.md)、[0076](0076-org-managed-users.md)

## 背景

企業は自社の IdP でメンバーをログインさせたい（design.md 11.3「Org 専用 SSO は `connections.owner_org_id` で表す」）。
connection の設定は Org の owner が行うため、運営者が設定する realm 共通の connection とは信頼の度合いが違う。
Org の IdP は任意の `sub` とメールを返せるので、何もしなければ他人になりすませる。トークンエンドポイントへの
問い合わせはサーバーから出るので、内部のアドレスを指せば SSRF になる。

## 決定

- `connections.owner_org_id`（空なら realm 共通）。フィーチャー `org_managed_users`（ドメインの所有証明と管理ユーザーと同じ）
- Org の owner（`org:settings`）が公開 API の `/v1/me/orgs/{id}/connections` で OIDC の connection を登録・一覧・削除する。
  issuer・認可・トークンのエンドポイント・client_id・client_secret（封をして置く）・scopes。1 Org に 5 まで。個人 Org には置けない。
  connection の ID（`con_…`）を slug にする（運営者の slug は `_` を含まないので重ならない）
- 戻り先はホスト型ログイン画面の `/login/oauth/callback` に固定する（Org は選べない。`server.public_url` が要る）
- その Org の管理ユーザーだけがログイン・連携でき（連携は `409 not_managed_by_org`）、ログインはその Org に入る
  （入れなければログインが失敗する）。Org が管理を手放すと、その Org の connection の外部 ID を無効化する
- 未登録なら、Org が証明したドメインのアドレス（IdP が確認済みとしたもの）に限り、確認の経路 `sso` でユーザーを作り、
  その Org の管理ユーザーとメンバー（`member`、メールを結び付ける）にする（`400 email_domain_not_verified`、Quota を確かめる）。
  既存のユーザーのアドレスなら自動リンクしない（`409 account_exists`。4.2）
- トークンエンドポイントは名前を解決し、公開のユニキャストアドレス（プライベート・ループバック・リンクローカル・CGNAT・
  文書用・NAT64・6to4 などを除く）でなければつながない。解決したアドレスに直接つなぐ（DNS rebinding を防ぐ）。
  プロキシを使う設定なら、アドレスを確かめたうえで接続はプロキシに任せる。開発モードでは確かめない
- ログインポリシー `require_sso`：この Org の connection で認証したセッション（認証情報に、その connection の有効な外部 ID がある）
  だけを入れる。ログインと Org の切り替えで判定する。フィーチャー `org_managed_users` がオフなら判定しない
- `POST /v1/login/sso:discover`：アドレスのドメインを証明済みの Org の connection を返す（ホームレルム発見）。
  ドメインが SSO を使うことは公開の情報とみなし、アドレスの登録の有無は返さない。ホスト型の画面の一覧には Org の connection を出さない
- connection を消すと、紐付けた外部 ID を無効化する。Org の削除では connection とドメインを消す
- 監査ログ：`org.connection.added`・`removed`、`org.member.joined_sso`
- フィーチャーを無効にするときは、connection を消し（外部 ID を無効化）、ログインポリシーの `require_sso` を外す
- SAML は扱わない（design.md 15章。別に決める）

## 理由

- 管理ユーザーに限れば、Org の IdP がなりすませるのは Org が既に所有するアカウントだけになる。個人ユーザーの
  アカウントは、Org の IdP からは触れない
- 戻り先を固定すれば、Org の設定で認可コードを外に流させる余地が無い。アプリ側の戻り先が要るなら realm 共通の connection を使う
- ドメインの証明（ADR 0075）があるので、登録で作るアカウントのアドレスを Org が所有していると言える

## 影響

- Org の IdP が返す `email_verified` を信じる範囲は、証明済みドメインのアドレスに限られる
- 管理ユーザーにしかログインさせないため、既存の個人ユーザーは管理を受け入れてから（ADR 0076）連携する

## 検討した代替案

- Org の connection にも任意の戻り先を許す：Org がコードを外に送れる。利点が小さい
- 個人ユーザーにも連携を許す：Org の IdP がそのアカウントになりすませる
- ドメインの証明なしで登録させる：Org が所有しないアドレスのアカウントを作れる
