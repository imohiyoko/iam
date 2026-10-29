# 0066. OIDC の認可コードフローと、トークンをログインの系列に結び付けること

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 5.1、5.2、5.3、5.5、9.3、[0021](0021-opaque-access-tokens.md)、[0038](0038-library-selection.md)、[0040](0040-spike-mldsa-opaque-signer.md)、[0045](0045-internal-and-external-ids.md)、[0065](0065-oidc-clients-and-signing-keys.md)

## 背景

M5 で、連携先が標準の OIDC でログインを任せられるようにする。要求の解析をどこまでライブラリに任せるか、ログイン画面との受け渡し、
発行したトークンがいつまで使えるかを決める。セッションの ID はログインの後も入れ替わる（5.2）ので、`sid` に今のセッションの ID は
使えない。

## 決定

- 要求の解析と検証（戻り先・スコープ・response_type・クライアントの認証情報の取り出し）は zitadel/oidc の `op.Server`
  （`op.RegisterServer`）に任せる。状態（認可要求・認可コード・認可・トークン）と ID トークンの署名は `authn/provider` で行う
  （zitadel/oidc の Storage と署名の経路は使わない。0040）
- エンドポイント：`/.well-known/openid-configuration`、`/oauth2/authorize`、`/oauth2/token`、`/oauth2/userinfo`、
  `/oauth2/keys`、`/oauth2/introspect`、`/oauth2/revoke`。issuer は `server.public_url`。public_url が無ければ OIDC Provider のエンドポイントを出さない
- 認可コードフローだけ（`response_type=code`、`response_mode=query`）。PKCE は S256 だけで、すべての連携先に求める
  （OAuth 2.0 Security BCP）。`request` パラメーターは受けない
- ログイン画面との受け渡し
  - 未ログイン、または `prompt=login`・`max_age` を満たさないときは、検証済みの認可要求を EphemeralStore に封をして預け
    （キーは要求 ID の SHA-256、既定 10 分）、`/login?return_to=/oauth2/authorize/resume?request=<ID>` に転送する
  - ログインの後、`/oauth2/authorize/resume` で預けた要求を読み、連携先の登録を確かめ直してから認可コードを発行する
  - `prompt=none` で未ログインなら `login_required`。active な Org が使えないセッションは `access_denied`
  - 外部プロバイダを経るログインでは、戻り先を同じタブの sessionStorage に預ける
- 認可コードは EphemeralStore に封をして置き（既定 1 分）、`Take` で1回だけ取り出す。連携先・戻り先・code_verifier の
  どれかが違えば、そのコードはもう使えない
- 連携先の認証：`client_secret_basic` / `client_secret_post`、`private_key_jwt`（iss = sub = client_id、aud は token
  エンドポイントか issuer、exp は 5 分以内、jti は1回だけ）、`none`（公開クライアント。loopback の戻り先はポートを問わない。
  RFC 8252 7.3）
- ログインの系列（`sid`）
  - セッションに `sid`（最初のセッションの ID）を持たせ、ID の入れ替え・Org の切り替えで引き継ぐ。同じブラウザで同じ本人が
    ログインし直したときも引き継ぐ。別の本人のログイン・2要素目の前の段のセッションは新しい系列にする
  - ID トークンの `sid` はこの値で、Back-Channel Logout（5.2）でも使う
- 認可（`oidc_grants`）とトークン（`oidc_tokens`）
  - 認可コードを交換するたびに認可を作る（連携先・ユーザー・Org・sid・スコープ・amr・auth_time）。寿命は
    `oidc.refresh_token_ttl`
  - アクセストークンは不透明（0021）で、`<ID>.<256bit 乱数>`。保存するのは秘密部分の SHA-256 だけ（セッションと同じ。5.2）
  - トークンの検証では、認可の失効・期限に加え、系列の今のセッションを Validate と同じ規則（失効・期限・寿命・停止・有効期間・
    認証情報の無効化）で確かめ、認可した Org の可否も確かめる。系列が終われば（ログアウト・失効など）トークンも使えない
  - アクセストークンの利用はセッションの無操作の期限を延ばさない。リフレッシュは延ばす（連携先での利用も利用とみなす）
  - リフレッシュトークンも不透明で1回限り。使うたびに新しいものに替え（期限は認可の期限）、使用済みのものが再び来たら
    認可ごと失効させる（OAuth 2.0 Security BCP 4.14。監査ログ `oidc.refresh_reused`）。リフレッシュでも系列と Org を確かめる
  - イントロスペクション（RFC 7662）は client_secret か private_key_jwt で認証した連携先（リソースサーバー）だけが呼べ、
    どの連携先のトークンでも確かめられる。結果はトークンの検証と同じ規則で毎回求め、キャッシュしない（停止・失効はすぐ反映される）
  - 失効（RFC 7009）はアクセストークンでもリフレッシュトークンでも認可ごと失効させる。知らないトークン・別の連携先の
    トークンは何もしないで 200（監査ログ `oidc.grant_revoked`）
  - 連携先の削除とユーザーの消去で、認可とトークンも消す
- ID トークンのクレーム：`iss`、`sub`（ユーザーの外部 ID）、`aud` / `azp`（client_id）、`exp`、`iat`、`auth_time`、`nonce`、
  `amr`、`sid`、`org_id`（Org オンのみ。外部 ID）、`email` / `email_verified`（`email` スコープのみ。Membership に結び付けたメール。
  4.4）。UserInfo は `sub`・`org_id`・`email`・`email_verified`
- 対応するスコープは `openid` と `email`。ほかは無視する
- OIDC のエンドポイントは CrossOriginProtection の外に置く（token は連携先のサーバー、authorize はトップレベルの遷移から呼ばれる）。
  Cookie を見るのは GET の authorize とその続きだけで、Cookie は SameSite=Lax。書き込みの公開 API（`/v1`）は今まで通り
  CrossOriginProtection で別オリジンを拒み、CORS も付けない
- CORS：Discovery と JWKS はどのオリジンにも許す。token・userinfo・revoke は公開クライアント（`none`）の戻り先のオリジンだけに
  許す（機密の連携先はサーバーから呼ぶ）。`Access-Control-Allow-Credentials` は付けない。authorize と introspect には付けない
- Back-Channel Logout（5.2）
  - ログインの系列が終わったとき（今のセッションの失効：ログアウト・本人や運営者による失効・認証情報の変更・削除の予約・復旧、
    ユーザーの停止の始まり、有効期間の終わり）、系列の認可を失効させ、`backchannel_logout_uri` を登録した連携先ごとに
    Logout Token の送信を outbox に積む（同じトランザクション。少なくとも1回。ID の入れ替え・Org の切り替えでは終わらない。
    認可が期限切れでも送る。連携先のログインは認可の期限とは別に残りうる）
  - Logout Token は ID トークンと同じ鍵・アルゴリズムで署名し（`typ: logout+jwt`）、`iss`・`aud`・`iat`・`exp`（2 分）・
    `jti`（outbox の ID）・`sid`・`sub`・`events` を持つ。`nonce` は持たない
  - 送れなければ次の送出でまた送り、1 時間であきらめる（送れなかったものは outbox の末尾に積み直し、1件の失敗で他を止めない）
  - 停止が解けてもセッションは使えるが、終えた系列の認可は戻らず、同じ系列に2度は送らない
  - 無操作・寿命による期限切れでは送らない。Org の停止や離脱は認可の検証で拒むだけで、送らない
- エラーの説明に内部のエラーを載せない（zitadel/oidc は既定でエラーの文字列を説明にするので、`oidc.Error` に置き換えてから返す）
- 監査ログ：認可コードの交換で `oidc.authorized`（client_id とスコープ）

## 理由

- 系列に結び付ければ、ログアウト・停止・認証情報の無効化が、同じ仕組み（5.3）で連携先のトークンにも効く
- `sid` を入れ替えで変えないことで、連携先は1つのログインを1つの `sid` で追える（Back-Channel Logout の照合に使える）
- 認可要求と認可コードは短命で1回限りなので、EphemeralStore の `Take` で並行の二重交換を防げる

## 影響

- `offline_access` は扱わない（リフレッシュトークンも系列に結び付く）。必要になればサードパーティの開放と併せて決める
- 認可要求の ID を知る別のブラウザが続きを開いても、そのブラウザのセッションでコードが発行され、登録した戻り先に送られるだけ
  （state を確かめない連携先のログイン CSRF は、通常の認可要求と同じ）
- メールのリンクを別のタブで開いたログインでは、連携先に自動では戻らない（コードの入力では戻る）
