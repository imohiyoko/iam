# 0117. FAPI 2.0 Security Profile は連携先と realm の単位のプロファイルにし、PAR・送信者制約・認証方式・アルゴリズムを登録と実行の両方で強いる

- 状態: 承認
- 日付: 2026-11-03
- 関連: [design.md](../design.md) 5.1、5.5、5.10、5.11、5.12、11.12、[0005](0005-crypto-no-rsa-pqc.md)、
  [0066](0066-oidc-authorization-code-flow.md)、[0073](0073-build-and-feature-toggle.md)、[0083](0083-multi-realm.md)、
  [0089](0089-enterprise-full-scope.md)、[0112](0112-par-and-resource-indicators.md)、[0113](0113-sender-constrained-tokens.md)、
  [0114](0114-ciba.md)

## 背景

金融・公共の API では、認可サーバーに FAPI 2.0 Security Profile（OpenID FAPI 2.0 Security Profile、2025 年の Final）への適合が求められる
（[scope.md](../scope.md) の「FAPI 2.0」。S C）。部品はすでにある。

- PAR（RFC 9126。フィーチャー `par`。ADR 0112）
- 送信者制約トークン（DPoP・OAuth の mTLS。フィーチャー `dpop`・`mtls_client_auth`。ADR 0113）
- PKCE S256 の必須、`response_type=code` だけ、`response_mode=query` だけ（ADR 0066。implicit・hybrid は持たない）
- private_key_jwt・`tls_client_auth`・`self_signed_tls_client_auth` の連携先の認証、認可コードの既定の寿命 1 分

足りないのは、(1) これらを「この連携先（realm）では必ず使う」と強いる仕組み、(2) 認可応答の `iss`（RFC 9207）、(3) 署名の
アルゴリズムを PS256・ES256・EdDSA に絞ること、(4) リフレッシュトークンの扱い（FAPI 2.0 はローテーションを例外の扱いにする）。
決めることは、プロファイルを有効にする単位、確かめる場所（登録と実行）、強いる中身、メッセージ署名（JAR・JARM）を入れるか。

## 決定

### フィーチャーと単位

- フィーチャー `fapi2`（既定オフ。登録は `features/fapi2`、実装は `authn/provider` と `server/app/fapi2.go`）。前提の `par` と、
  `dpop` か `mtls_client_auth` は依存（`Requires`）に書かず、連携先と realm の設定に入れるときに確かめる（依存は AND しか書けない。
  前提のフィーチャーを後から止めても、PAR を受けられない・送信者制約を付けられない連携先は実行で拒まれる。fail-closed）
- 単位は連携先（`fapi2_security_profile`。`authn_clients` の列。SQLite 00072、PostgreSQL 00055）と realm（realm の設定
  `fapi2_security_profile`、既定の realm は設定ファイルの `realm.fapi2_security_profile`）。どちらかが真ならその連携先を
  FAPI 2.0 の連携先として扱う
- 連携先に入れるとき（作成・変更）、フィーチャー `fapi2` が止まっている・`par` が止まっている・`dpop` も `mtls_client_auth` も止まっている
  なら `invalid_client_metadata`（今の値のままの変更と外すのは受ける）。realm の設定も同じ条件で `invalid_realm_settings`
- realm で有効にすると、その realm の連携先は登録のときにプロファイルの条件（下記）を満たさなければならない。既にある連携先が
  満たさなければ、実行のときに認証で拒む（fail-closed。リソースサーバーとしてイントロスペクションを呼ぶ連携先も含む）

### 連携先の条件（登録で確かめ、実行でも確かめ直す）

`provider.CheckFAPI2` が 1 か所で確かめる。登録では `invalid_client_metadata`、実行（realm の単位で後から有効にしたときと、
フィーチャーの無効化で送信者制約が外れたとき）では `invalid_client`。

- 機密の連携先だけ：`private_key_jwt`・`tls_client_auth`・`self_signed_tls_client_auth`（`client_secret`・`none` は拒む。FAPI 2.0 5.3.2.1）
- 送信者制約：`dpop_bound_access_tokens` か `tls_client_certificate_bound_access_tokens` のどちらか（5.3.2.1。トークンエンドポイントで
  結び付けの無いトークンを出さない）
- `id_token_signed_response_alg` は ES256（FAPI 2.0 5.4 の PS256・ES256・EdDSA のうち iam が署名できるもの。ML-DSA-65 は FAPI の外）
- `private_key_jwt` の JWKS の鍵は、RSA（2048 bit 以上、`alg` は無いか PS256）、EC の P-256（無いか ES256）、OKP の Ed25519
  （無いか EdDSA）だけ
- 戻り先は https だけ（ループバックの http も受けない）
- Device Authorization Grant は許さない（FAPI 2.0 は認可コードフローのプロファイルで、端末のフローの守りを定めていない）。
  CIBA は許す（FAPI-CIBA は後回し。トークンの送信者制約は同じく強いる）

### 実行で強いること

- PAR の必須：FAPI 2.0 の連携先には `require_pushed_authorization_requests` と同じく PAR を求める（PAR を通らない認可要求は戻り先に
  転送せずに拒む）。PAR の要求の連携先の認証も下記の規則
- 連携先の認証：上の条件を満たさなければ `invalid_client`。`private_key_jwt` の `client_assertion` の `alg` は PS256・ES256・EdDSA だけ
  （RS256・ES384 は拒む）。`aud` は今までどおり issuer かエンドポイントの URL
- token エンドポイント（認可コード・リフレッシュ・CIBA・Token Exchange）：DPoP の証明か、結び付けたクライアント証明書が無ければ拒む。
  DPoP の証明の `alg` も PS256・ES256・EdDSA だけ（`invalid_dpop_proof`）。PAR の要求の DPoP の証明も同じ
- 認可コードの寿命は 60 秒以下（設定の `oidc.code_ttl` が長くても、FAPI 2.0 の連携先には 60 秒で切る。5.3.2.1）
- リフレッシュトークンはローテーションしない（FAPI 2.0 5.3.2.1 は、応答を受け取り損ねた連携先が前のトークンでやり直せない
  ローテーションを使わないよう求める）。同じリフレッシュトークンを認可の期限まで使え、応答に `refresh_token` を入れない。機密の連携先で、
  アクセストークンは送信者制約付きなので、使い回しの検知（ファミリーの失効）が無くても盗んだリフレッシュトークンだけでは使えない。
  認可の失効・ログインの系列の終わり・RFC 7009 の失効は今までどおり効く
- PKCE S256・`response_type=code`・`response_mode=query`・`request`（JAR）を受けないことは、今までどおりどの連携先にも求める

### 認可応答の `iss`（RFC 9207）

- 認可応答（成功とエラー）に `iss` を付ける。FAPI 2.0 の連携先に限らず全部の連携先に付ける（RFC 9207 は付けてよく、知らない
  連携先は無視する）。op の転送（`op.WithEncoder`）と iam が作る転送の両方で同じエンコーダーを使う
- Discovery に `authorization_response_iss_parameter_supported: true`

### Discovery

- `authorization_response_iss_parameter_supported` は常に出す
- realm で有効なら、その realm の Discovery は強いるものだけを出す：`token_endpoint_auth_methods_supported`（イントロスペクション・失効も）は
  `private_key_jwt` と（mTLS が動いていれば）`tls_client_auth`・`self_signed_tls_client_auth`、`*_auth_signing_alg_values_supported` と
  `dpop_signing_alg_values_supported` は PS256・ES256・EdDSA、`id_token_signing_alg_values_supported` は ES256、
  `require_pushed_authorization_requests: true`
- 連携先の単位で有効にしたときは Discovery を変えない（Discovery は realm に 1 つ）

### 監査と無効化

- 連携先の作成・変更の監査ログ（`client.created`・`client.updated`）に `fapi2_security_profile` を残す
- 無効化（11.12）：連携先と realm の `fapi2_security_profile` を外して完了。外した後の連携先は今までの規則に戻る
  （PAR の必須・送信者制約の設定は連携先に残したもののまま）

### メッセージ署名（FAPI 2.0 Message Signing）

- 今回は入れない。JAR（署名した認可要求。PAR と組み合わせる）と JARM（署名した認可応答）、HTTP Message Signatures は、
  要求の JWS の検証・応答の JWT の発行・Discovery の項目が新しく要り、小さくない。後に回す（roadmap の M11）

### 適合試験（OpenID Foundation conformance suite の FAPI 2.0 Security Profile Final の試験計画）

想定する構成は「openid_connect・private_key_jwt・dpop（か mtls）・plain_fapi」。通ると見込むもの：

- 正常系（PAR → authorize → token。`iss` の付いた認可応答、DPoP・mTLS に結び付いたトークン、UserInfo、リフレッシュ）
- PAR を通らない認可要求・PKCE の無い要求・`code_challenge_method=plain`・別の連携先の `request_uri`・使用済みの `request_uri` の拒否
- 認可コードの再利用・別の戻り先・期限切れの拒否、RS256 の client assertion・`aud` の違う assertion・使い回した `jti` の拒否
- DPoP の証明の無い・別の鍵・`ath` の無い・再送の拒否と `DPoP-Nonce`
- `response_type=code id_token`（hybrid）の拒否

残るもの（失敗か対象外と見込む）：

- Message Signing の試験計画（JAR・JARM・HTTP Message Signatures）は全部対象外
- RSA の ID トークン（PS256）を求める構成：iam は RSA で署名しない（ADR 0005）。ES256 を選べる構成でだけ通る
- `client_secret` の拒否は登録で行うので、suite の「間違った認証方式」の一部の試験は登録の段で止まる
- TLS の暗号スイートの試験は運営者の TLS の終端の設定による

## 結果

- 連携先か realm の単位で、FAPI 2.0 の求めるものを設定 1 つで強いられる。足りない前提（PAR・DPoP か mTLS）は登録・設定の変更の時点で分かる
- 全部の連携先の認可応答に `iss` が付く（mix-up 攻撃への備え）。連携先が知らなければ無視するだけ
- realm で有効にすると、条件を満たさない既存の連携先は認証できなくなる（リソースサーバーの連携先も）。先に連携先を直してから有効にする
- FAPI 2.0 の連携先のリフレッシュトークンは使い回せる（使い回しの検知は無い）。送信者制約と連携先の認証が代わりに守る
- メッセージ署名が無いので、「FAPI 2.0 Message Signing」を求める相手には足りない

## 検討した代替案

- **フィーチャーを動かすと realm の全部の連携先に強いる**：FAPI の連携先と、そうでない連携先（社内の SPA など）を同じ realm に置けない。
  連携先と realm の 2 つの単位にする
- **登録では確かめず、実行のときだけ拒む**：設定の誤りが利用者のログインの失敗として初めて見える。登録で拒み、realm の後からの有効化と
  無効化の後だけ実行で拒む
- **リフレッシュトークンのローテーションを FAPI 2.0 の連携先でも続ける**：応答を受け取り損ねた連携先が前のトークンでやり直すと、
  使い回しとして認可ごと失効し、FAPI 2.0 の求めに反する。猶予期間を付ける方法もあるが、送信者制約と機密の連携先の認証で足りるので持たない
- **`iss` を FAPI 2.0 の連携先にだけ付ける**：mix-up はどの連携先にも起こり、付けても害が無い。全部に付ける
- **JAR・JARM も同時に入れる**：FAPI 2.0 Security Profile は求めない（Message Signing は別の仕様）。範囲を分ける
- **ID トークンの PS256 を足す**：RSA の署名を持たない方針（ADR 0005）。ES256 で FAPI 2.0 の条件を満たす
