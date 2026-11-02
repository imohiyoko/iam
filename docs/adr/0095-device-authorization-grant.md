# 0095. Device Authorization Grant は状態を EphemeralStore に置き、承認は本人のログインと確認の画面で行う

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.1、5.5、11.16、[0010](0010-feature-toggles.md)、[0011](0011-build-time-features.md)、[0022](0022-deny-reason-disclosure.md)、
  [0065](0065-oidc-clients-and-signing-keys.md)、[0066](0066-oidc-authorization-code-flow.md)、[0073](0073-build-and-feature-toggle.md)、
  [0089](0089-enterprise-full-scope.md)、[0091](0091-process-roles.md)

## 背景

テレビ・CLI・IoT のように、ブラウザを持たないか文字の入力が難しい端末からも、連携先がログインを任せられるようにしたい。
標準は OAuth 2.0 Device Authorization Grant（RFC 8628）で、エンタープライズの範囲（ADR 0089、[scope.md](../scope.md)）の M9 に入っている。
端末は device_code を受け取ってトークンエンドポイントをポーリングし、本人は別の端末のブラウザで user_code を入れて承認する。

決めることは、(1) zitadel/oidc の `op.Server` との分担、(2) 途中の状態を EphemeralStore と Storage のどちらに置くか、
(3) user_code の総当たりとフィッシングへの備え、(4) 発行するトークンと、連携先ごとの可否である。

zitadel/oidc の `op.Server` は、`Endpoints.DeviceAuthorization` を登録すると `DeviceAuthorization`（device_authorization
エンドポイント）を、token エンドポイントの `grant_type=urn:ietf:params:oauth:grant-type:device_code` で `DeviceToken` を呼ぶ。
どちらも先に `VerifyClient` で連携先を認証し、token エンドポイントでは連携先の `GrantTypes()` に grant_type が無ければ
`unauthorized_client` で止める。状態の持ち方は実装に任せる（`LegacyServer` の場合だけ zitadel/oidc の Storage を使う）。

## 決定

- フィーチャー `device_flow`（依存なし、既定でオフ）。オフなら Discovery に出さず、device_authorization エンドポイントと承認の画面は
  404、連携先に許可も付けられない（`400 invalid_client_metadata`）。管理 API も許可の有無を返さない
- 分担は ADR 0066 と同じ。要求の解析・連携先の認証・grant_type の可否は `op.Server` に任せ、状態（端末の要求・user_code・承認）と
  トークンの発行は `authn/provider` で行う（zitadel/oidc の Storage は使わない）
- エンドポイント（役割は `oidc`。ADR 0091）
  - `POST /oauth2/device_authorization`：連携先の認証は token エンドポイントと同じ（client_secret・private_key_jwt・none）。
    `openid` スコープが要る（`invalid_scope`）。スコープは認可要求と同じく対応するものだけ残す。接続元ごとにレートリミット
  - `GET /oauth2/device`（`verification_uri`）：ホスト型の画面。`verification_uri_complete` は `?user_code=` を付けたもの
  - `POST /oauth2/token`（`grant_type=urn:ietf:params:oauth:grant-type:device_code`）
  - Discovery に `device_authorization_endpoint` と `grant_types_supported` の device_code を足す
- 連携先ごとの可否：`authn_clients.device_grant`（管理 API の `device_authorization_grant`）。許した連携先だけが `GrantTypes()` に
  device_code を持ち、許していなければ device_authorization は `unauthorized_client`。許した連携先は戻り先を持たなくてよい（CLI など）
- 値
  - device_code：256 bit の乱数（認可コードと同じ）。キーには SHA-256 だけを使う
  - user_code：子音 20 文字（`BCDFGHJKLMNPQRSTVWXZ`）の 8 桁、`XXXX-XXXX` で見せる（RFC 8628 6.1。約 34.5 bit）。
    大文字・小文字・ハイフン・空白は問わない。使われているものと重なれば作り直す
  - 期限は `oidc.device_code_ttl`（既定 10 分、30 分まで）、間隔は `oidc.device_poll_interval`（既定 5 秒）
- 状態は EphemeralStore に封をして置く（Crypter。キーは秘密の値の SHA-256）
  - 端末の要求（device_code）：期限の 2 倍の間残し、期限の後のポーリングに `expired_token` を返す
  - user_code から要求へ：承認でも拒否でも `Take` で1回だけ使う
  - 本人の判断（device_code）：ポーリングで `Take` して1回だけ答え、要求も消す（その後は `invalid_grant`）
  - 最後のポーリングの時刻と間隔：間隔より速いポーリングには `slow_down` を返し、間隔を 5 秒延ばす（1 分まで）
- ポーリングの答え：知らない・別の連携先の device_code は `invalid_grant`、期限切れは `expired_token`、速すぎれば `slow_down`、
  未決は `authorization_pending`、拒否は `access_denied`、承認ならトークン
- 承認の画面（フィッシングの対策）
  - ログインしていなければ、既存のホスト型ログインに `return_to=/oauth2/device?user_code=…` で送る（戻り先の検査は今までどおり）
  - user_code を照合したら、連携先の名前・コード・スコープと「自分で始めたときだけ続ける」の注意を見せ、本人が「許可する」か
    「拒否する」を押したときだけ記録する。`verification_uri_complete` で開いても、確認を省かない
  - 承認は POST で、CrossOriginProtection で別オリジンからの送信を拒む（Cookie も SameSite=Lax）。画面のスクリプトは無い
  - 照合の前に連携先が消えた・許可を外したなら、そのコードは使えない。active な Org が使えないセッションの承認は拒否として記録する
    （認可要求の access_denied と同じ。4.7）
  - 失敗の理由は区別しない（形の違い・知らない・期限切れ・使用済みは同じ表示。ADR 0022）
- user_code の総当たりの対策：照合（画面の GET と POST）を、ログインした本人と接続元ごとに `per_account`、本人ごとに
  `per_account_total`、接続元ごとに `per_ip` で数える（`security.login.rate_limit`）。超えたら 429 を返し、窓ごとに1回
  `rate_limit.triggered` を残す。ログインを求めるので、照合できるのはアカウントを持つ者だけ
- トークン：承認した本人・Org・ログインの系列（`sid`）・`auth_time`・`amr` から、認可コードの交換と同じ `Tokens.Exchange` で発行する
  （不透明なアクセストークン、ID トークン、系列に結び付いたリフレッシュトークン。ADR 0066）。ID トークンに `nonce` は無い。
  系列が終わっていれば `invalid_grant`
- 監査ログ：承認で `oidc.device_approved`、拒否で `oidc.device_denied`（client_id・スコープ）。トークンの発行は `oidc.authorized` で、
  `grant_type` に device_code を入れる。device_code・user_code は残さない
- フィーチャーの無効化：連携先の許可を外して片付ける（Count / Purge）。途中の要求は EphemeralStore の期限で消える

## 結果

- 状態を EphemeralStore に置くので、複数インスタンスでは共有できる EphemeralStore（redis など）が要る（`server.multi_instance` の
  検査で守る。認可コードと同じ）。memory の EphemeralStore で再起動すると、途中の要求は消え、端末は `invalid_grant` を受けて
  最初からやり直す。期限は最長 30 分なので、失って困る量ではない
- Storage に置かないので、ポーリングのたびの書き込みが DB に来ない。ユーザーの消去・統合・Org の削除でも追う行は無い
  （承認から交換までの間に本人が消されても、交換で系列を確かめて `invalid_grant` になる）
- user_code の 34.5 bit は、照合の回数の上限と期限（既定 10 分）があれば総当たりに十分である。それでも同時に発行中の
  要求が多いほど当たりやすいので、device_authorization にも接続元ごとの上限をかける
- 連携先の名前を見せて確認を求めても、攻撃者が自分の端末のコードを本人に入れさせる手口（ソーシャルエンジニアリング）は防げない。
  画面の注意書きと、承認の監査ログで追えるようにするに留める

## 検討した代替案

- 状態を Storage の表に置く：再起動に耐えるが、短命で1回限りの値のために表・マイグレーション・消去と統合の扱いが増え、
  ポーリングが DB に書き込む。認可コードを EphemeralStore に置いた判断（ADR 0066）と揃える
- zitadel/oidc の `LegacyServer` と Storage のインターフェースで実装する：状態と署名を IAM が持つ方針（ADR 0040、0066）に合わない
- user_code を数字だけにする：入力は楽だが、同じ桁数でエントロピーが小さい（8 桁で 26.6 bit）。RFC 8628 6.1 の例に従う
- ログインの前に user_code を入れさせる：未ログインの照合が総当たりの口になる。ログインを先にし、本人ごとに数える
- `verification_uri_complete` で開いたら確認なしに承認する：フィッシングに弱い。必ず確認の画面を挟む
