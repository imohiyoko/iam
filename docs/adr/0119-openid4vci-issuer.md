# 0119. OpenID4VCI の発行者は realm の issuer と同じ認可サーバーにし、SD-JWT VC を realm の ES256 の鍵で署名して、Token Status List で失効させる

- 状態: 承認
- 日付: 2026-11-03
- 関連: [design.md](../design.md) 5.12、9.3、11.0、[scope.md](../scope.md) 4 章、[0005](0005-crypto-no-rsa-pqc.md)、[0014](0014-pii-encryption-minimization.md)、
  [0022](0022-deny-reason-disclosure.md)、[0026](0026-first-party-clients.md)、[0066](0066-oidc-authorization-code-flow.md)、[0073](0073-build-and-feature-toggle.md)、
  [0080](0080-custom-attributes.md)、[0083](0083-multi-realm.md)、[0084](0084-auth-context-and-risk-in-authz.md)、[0089](0089-enterprise-full-scope.md)、
  [0108](0108-openid4vp-verifier.md)、[0112](0112-par-and-resource-indicators.md)、[0113](0113-sender-constrained-tokens.md)

## 背景

0108 で、ウォレットが提示する SD-JWT VC を確かめてログインさせる側（検証者。OpenID4VP）を持った。逆向き、つまり iam が持つ本人の属性
（確認済みのメールアドレス、カスタム属性。0080）を資格情報（Verifiable Credential）にしてウォレットへ渡す側（発行者）が無い。
社員証・会員証のような資格情報を、iam のアカウントから発行したいという要望は、EU のデジタル ID ウォレット（EUDI Wallet）の普及とともに増えている
（scope.md 4 章の「OpenID4VCI」。出どころ S）。

OpenID for Verifiable Credential Issuance 1.0（以下 OpenID4VCI）は、発行者のメタデータ、資格情報の申し出（Credential Offer）、
OAuth 2.0 の 2 つのフロー（事前に認可したコードの Pre-Authorized Code Flow と、Authorization Code Flow）、nonce エンドポイント、
鍵の所持の証明（proof）付きの credential エンドポイントを決めている。資格情報の形は 0108 と同じ SD-JWT VC（`dc+sd-jwt`）と、mdoc（`mso_mdoc`）が主。

決めることは、(1) 発行者と認可サーバーの関係と、既存の OIDC Provider（zitadel/oidc の `op.Server`）との分担、(2) 発行する資格情報の定義の置き場所と、
本人の属性からクレームへの対応、(3) 申し出とフローの状態の置き場所、(4) 鍵の所持の証明の確かめ方、(5) 発行した資格情報の失効、である。

## 決定

### フィーチャーと形

- フィーチャー `openid4vci`（依存なし、既定オフ）。実装は `authn/vci`。`server.public_url`（issuer）が無ければ動かない。
  オフなら発行者のメタデータ・エンドポイント・本人の API は 404、管理 API は `404 openid4vci_disabled`、token エンドポイントは
  Pre-Authorized Code の grant を `unsupported_grant_type` にし、AS メタデータにも出さない
- **発行者の識別子（Credential Issuer Identifier）は realm の issuer**（0083 の realm ごとの URL）。認可サーバーも同じ issuer
  （メタデータに `authorization_servers` を書かない）。発行者のメタデータは `/.well-known/openid-credential-issuer`（パスのある issuer には
  RFC 8414 と同じく `/.well-known/openid-credential-issuer/realms/{slug}` でも答える。0112）。署名したメタデータ（`signed_metadata`）は後続
- エンドポイント（`/oauth2/` の下。OIDC Provider のハンドラが受ける）
  - `POST /oauth2/vci/nonce`：nonce エンドポイント
  - `POST /oauth2/vci/credential`：credential エンドポイント
  - `GET /oauth2/vci/offers/{id}`：参照で渡す申し出（`credential_offer_uri`）
  - `GET /oauth2/vci/status-list`：Token Status List の status list token
  - `GET /.well-known/jwt-vc-issuer`：SD-JWT VC の JWT VC Issuer Metadata（発行者の公開鍵。`jwks` を値で載せる）
- 資格情報の形は **`dc+sd-jwt` だけ**。mdoc（`mso_mdoc`。COSE・CBOR の MSO とデバイスの鍵）は SD-JWT VC と同じ定義の形に別の形式として足せるが、
  この ADR では作らない（管理 API は `400 unsupported_format`）

### 資格情報の定義（Credential Configuration）

- 管理 API（`/v1/admin/vci/credential-configurations`、`clients:manage`）で realm ごとに登録する。表は `vci_credential_configurations`
  （設定の残りは JSON。0115 の SP の登録と同じ形）
- 項目
  - `configuration_id`：メタデータの `credential_configurations_supported` のキー（realm の中で一意。英数字と `._:-`、128 文字まで）
  - `format`：`dc+sd-jwt`。`vct`：資格情報の種類（URI か文字列。256 文字まで）
  - `scope`：Authorization Code Flow で要求するスコープ（任意。realm の中で一意。OIDC のスコープの名前と、自前の API のスコープ（0112）と重ならないこと）
  - `display`：名前と言語（メタデータの `credential_metadata.display`）
  - `claims`：クレームの名前（最上位だけ。入れ子は後続）・出どころ・選択的に開示できるか（既定は真）・必須か・表示名。出どころは
    `user_id`（公開のユーザー ID）、`email`・`email_verified`（primary のメールアドレス。index_only の realm では無い）、`attribute:<key>`
    （カスタム属性。フィーチャー `custom_attributes`。トークンに載せる指定（`in_token`）は問わない。定義ごとに運営者が選ぶため）、`const`（固定の値）。
    `iss`・`nbf`・`exp`・`iat`・`cnf`・`vct`・`vct#integrity`・`status`・`_sd`・`_sd_alg`・`...` は名前にできない
  - `validity`：資格情報の有効期間（秒。既定 90 日、1 時間〜5 年）
  - `require_tx_code`：Pre-Authorized Code Flow で tx_code を必ず求める
- 必須の値が無い（メールアドレスが無い、属性が未設定）ときは発行しない（`credential_request_denied`）。任意の値は載せない

### 申し出と Pre-Authorized Code Flow

- 本人の API `POST /v1/me/verifiable-credentials/offers`（`credential_configuration_ids`、`tx_code`）で、ログインしたセッションの本人に申し出を作る。
  直近の認証（0084 の `me:verifiable_credentials`）を求める。資格情報の束をウォレットへ持ち出す操作で、セッションの乗っ取りの影響が大きいため
- `pre-authorized_code` は 256 bit の乱数。EphemeralStore に、ハッシュをキーに封をして置く（期限 10 分）。中身は realm・本人・セッションの系列（`sid`）・
  定義の ID・tx_code。**1 回だけ使える**（`Take`）
- tx_code は 6 桁の数字（`input_mode: numeric`）。本人が求めたか、定義の 1 つでも `require_tx_code` なら作り、作成の応答にだけ返す（ほかには残さない）。
  画面の QR を盗み見た第三者が先に引き換えることへの備え。誤りは 5 回で申し出を消す
- 応答は申し出の値（`credential_offer`）、値で渡す URI（`openid-credential-offer://?credential_offer=…`）、参照で渡す URI
  （`openid-credential-offer://?credential_offer_uri=…/oauth2/vci/offers/{id}`。ID は別の 256 bit の乱数）、tx_code、期限。
  参照の申し出は期限まで何度でも取れる（中身は値の申し出と同じ）。クライアントはどちらかを QR にするか、同じ端末のウォレットへ遷移する
- token エンドポイントの `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` は `op.Server` の前で受ける（CIBA と同じ。0114）。
  ウォレットの認証は求めない（`pre-authorized_grant_anonymous_access_supported: true`）。`client_id` があれば記録し、proof の `iss` と比べる
  - 知らない・期限切れ・使用済みのコード、誤った tx_code は `invalid_grant`。tx_code が要るのに無い・要らないのにあるは `invalid_request`
  - アクセストークンは `vci_` で始まる不透明な値（256 bit）。EphemeralStore に封をして置き、期限は `oidc.access_token_ttl`。`token_type` は `Bearer`。
    DPoP への結び付けは後続（このトークンは credential エンドポイントにしか使えず、発行する資格情報は proof の鍵に結び付く）
- 発行のときに、申し出を作ったセッションの系列がまだ使えること（ログアウト・停止・有効期間の終わり・削除で止まる。5.3）を確かめる

### Authorization Code Flow

- 定義の `scope` を、登録した連携先（ウォレット。公開クライアントなら PKCE）が authorize で要求する。`openid` が無くても、定義のスコープを含む
  認可要求は受ける（OpenID4VCI のウォレットは `openid` を送らない）。トークンは今までどおり（ID トークンも出る）
- credential エンドポイントは UserInfo と同じ規則でアクセストークンを確かめる（ログインの系列、自前の API に向けたトークンは使えない、
  DPoP・mTLS の結び付け。0112・0113）。認可のスコープに定義のスコープがあるものだけ発行する。proof の `iss` は連携先の `client_id`（あれば比べる）
- `authorization_details`（`type: openid_credential`）と `issuer_state`、`credential_identifier` は後続（スコープで足りる）。同意の画面は持たない（0026）

### nonce と鍵の所持の証明（fail-closed）

- `c_nonce` は**状態を持たない**：realm と期限（5 分）を Crypter で封をした値（base64url）。nonce エンドポイントは認証の無い `POST` なので、
  呼ばれても EphemeralStore を使わない。使うときに EphemeralStore の `Incr` で印を付け、**2 回目は `invalid_nonce`**
- 要求は `proofs.jwt` の配列で、ちょうど 1 つ（バッチの発行は後続。メタデータに `batch_credential_issuance` を出さない）。単数の `proof` は受けない
- proof の JWT（`authn/vci/proof.go`。ファジングのテストがある）
  - `typ` は `openid4vci-proof+jwt`、`alg` は `ES256`・`ES384`・`ES512`・`EdDSA`（0108 と同じ。`none`・HMAC・RSA は受けない）
  - 鍵はヘッダーの `jwk`（公開鍵だけ。秘密の項目や対称鍵は拒む）。`kid`（DID）・`x5c`・`key_attestation` は受けない（後続）
  - `aud` が発行者の識別子、`nonce` が今の realm の封をした `c_nonce`（期限内・未使用）、`iat` が 5 分以内（未来は 1 分まで）。
    `iss` があればアクセストークンの連携先の `client_id` と一致すること
  - 署名をその `jwk` で確かめる。大きさ（8 KiB）と JSON の重複した名前・入れ子に上限を置く（0108 の厳しい JSON の読み方を使う）
- 誤りは OpenID4VCI 8.3.1.2 のエラー：`invalid_proof`、`invalid_nonce`、`invalid_credential_request`、`unknown_credential_configuration`、
  `credential_request_denied`、`invalid_encryption_parameters`（応答の暗号化は持たない）。理由の詳細は返さず監査ログに残す（0022）

### SD-JWT VC の発行

- 発行者の JWT は `typ: dc+sd-jwt`、realm の ES256 の鍵（ID トークンと同じ。`kid`。9.3）で署名する。ML-DSA はウォレットが読めないので使わない
- 中身は `iss`（issuer）、`vct`、`iat`、`exp`（`validity`）、`cnf.jwk`（proof の鍵）、`status`（下記）、`_sd_alg: sha-256`。
  選択的に開示するクレームは開示（`[salt, 名前, 値]`、128 bit の salt）にし、ダイジェストを `_sd` に並べる。数を隠すため 1〜4 個のデコイを足して並べ替える。
  SD-JWT の組み立ては 0108 の `sdjwt` パッケージに足し（`Build`）、0108 の検証に通ることをテストで確かめる
- 発行者の鍵は `/.well-known/jwt-vc-issuer`（`issuer` と ES256 の `jwks`）で配る。`x5c` の証明書の連鎖は後続
- 発行の記録を `vci_issued_credentials`（realm・ID・本人・定義・status の番号・失効の時刻・期限・鍵の JWK Thumbprint）に残す。
  クレームの値は残さない（0014）。期限を過ぎた記録は次の発行のときに消す

### 失効（Token Status List）

- realm に 1 つの status list（1 bit、131072 個）。発行のたびに空いた番号を乱数で選ぶ（番号から発行の順を読めないように）。8 回選んでも空かなければ発行しない
  （期限の過ぎた記録は消すので、有効な資格情報が 13 万近くにならない限り起きない。複数の list は後続）
- 資格情報の `status.status_list` は `{"idx": 番号, "uri": "<issuer>/oauth2/vci/status-list"}`。status list token は `typ: statuslist+jwt`、
  `sub`・`iat`・`exp`・`ttl`（5 分）・`status_list`（`bits: 1`、`lst` は ZLIB の DEFLATE を base64url）を realm の ES256 の鍵で署名して返す
  （`Content-Type: application/statuslist+jwt`、`Cache-Control: max-age=300`）
- 失効（値 1 = INVALID）：管理 API（`POST /v1/admin/vci/credentials/{id}:revoke`、`credentials:revoke`）、本人の API
  （`POST /v1/me/verifiable-credentials/{id}:revoke`）、アカウントの消去（4.10）。元に戻す操作は持たない。停止（SUSPENDED = 2）は後続
- フィーチャーを止めると status list も 404 になる。検証者は確かめられない資格情報を拒むので、止めると発行済みのものは使えなくなる（fail-closed）

### 監査ログ・無効化

- `vci.configuration_created`・`vci.configuration_updated`・`vci.configuration_deleted`、`vci.offer_created`（定義・tx_code の有無）、
  `vci.token_issued`・`vci.token_rejected`（理由）、`vci.credential_issued`（定義・発行の記録の ID・フロー・`client_id`）、
  `vci.credential_rejected`（理由）、`vci.credential_revoked`。コード・tx_code・nonce・クレームの値は残さない
- フィーチャーの無効化は、定義と発行の記録を消して完了（Count / Purge）。途中の申し出とアクセストークンは EphemeralStore の期限で消える
- EphemeralStore を使うので、複数インスタンスでは共有できるもの（`server.multi_instance` の検査）

### この ADR の外（後続）

- mdoc（`mso_mdoc`）、バッチの発行、Deferred・Notification エンドポイント、応答と要求の暗号化、`authorization_details`・`issuer_state`、
  Wallet Attestation による連携先の認証、Key Attestation、proof の `kid`（DID）・`x5c`、Pre-Authorized Code のトークンの DPoP、
  署名したメタデータ、`x5c` 付きの発行者の JWT、入れ子のクレームと配列の要素の選択的な開示、表示の画像、status の SUSPENDED、複数の status list、
  管理者による本人の代わりの申し出、ホスト型の画面

## 結果

- iam のアカウントから、EUDI Wallet などの OpenID4VCI 1.0 のウォレットへ、本人の確認済みの属性を SD-JWT VC として渡せる。発行した資格情報は
  0108 の検証者で確かめられ、Token Status List で失効させられる
- 発行者は認可サーバーと同じなので、既存の OIDC の連携先・セッションの系列・DPoP がそのまま使える。代わりに、外部の認可サーバーを使う構成は持たない
- Pre-Authorized Code Flow は QR を見た誰でも引き換えられうる（OpenID4VCI 13.6）。期限は 10 分、1 回限り、tx_code を選べる。
  発行した資格情報は proof の鍵に結び付くので、引き換えた者だけが提示できる
- status list は 1 つで 13 万件まで。番号は乱数で選ぶので、検証者が status list から読めるのは失効したかどうかだけ
- 資格情報の有効期間はトークンより長い（既定 90 日）。アカウントの消去は失効させるが、停止は status に反映しない（後続）。停止を急ぐ運営者は管理 API で失効させる

## 検討した代替案

- **外部の認可サーバー（`authorization_servers`）を許す**：iam 自身が認可サーバーなので要らない。トークンの確かめ方が増える
- **Pre-Authorized Code のアクセストークンを OIDC の認可（`oidc_grants`）にする**：連携先の無いトークンになり、リフレッシュ・イントロスペクションの
  前提（連携先と系列）に例外が要る。credential エンドポイントでしか使えない短命の値なので EphemeralStore に置く
- **`c_nonce` を EphemeralStore に作る**：認証の無いエンドポイントで書き込みが増える（DoS）。封をした値なら作るときに状態が要らず、使うときの印だけでよい
- **資格情報の定義を設定ファイルに書く**：realm ごとに運営者が変えるもので、0115 の SP の登録と同じく管理 API にする
- **status の番号を順に振る**：番号から発行の順と数が分かる（status list の仕様の 12 章の注意）
- **SD-JWT のライブラリを入れる**：0108 と同じ理由で、検証と同じパッケージに組み立てを足し、自前の検証とファジングで確かめる
- **mdoc を同時に作る**：COSE の署名・CBOR の MSO・デバイスの鍵の扱いが別に要り、SD-JWT VC の流れが固まってから足す方が確かめやすい
