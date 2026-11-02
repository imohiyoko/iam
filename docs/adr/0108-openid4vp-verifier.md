# 0108. OpenID4VP の検証者は認証方式のプラグインにし、SD-JWT VC を信じる発行者の鍵だけで確かめて、本人の結び付けで利用者を引く

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.1、9.5、11.0、13.2、[0005](0005-crypto-no-rsa-pqc.md)、[0014](0014-pii-encryption-minimization.md)、
  [0022](0022-deny-reason-disclosure.md)、[0038](0038-library-selection.md)、[0073](0073-build-and-feature-toggle.md)、[0083](0083-multi-realm.md)、
  [0089](0089-enterprise-full-scope.md)、[0090](0090-authenticator-plugins.md)、[0092](0092-authenticator-port-implementation.md)、
  [0093](0093-acr-aal-step-up.md)、[0101](0101-port-totp-and-password.md)、[0103](0103-x509-client-certificates.md)、[0104](0104-sms-voice-otp-and-push-approval.md)

## 背景

0089 で Verifiable Credentials（OpenID4VP、mdoc）を範囲に入れた（[scope.md](../scope.md) 1 章。S）。EU のデジタル ID ウォレット（EUDI Wallet）や
各国のモバイル運転免許証のように、本人がウォレットに持つ資格情報（クレデンシャル）を提示させてログインさせたい、という要望が出てきている。
OpenID for Verifiable Presentations 1.0（以下 OpenID4VP）は、検証者（iam）がウォレットに提示を求め、ウォレットが提示を返す手順を決めている。
資格情報の形は、IETF の SD-JWT（RFC 9901）の上の SD-JWT VC と、ISO の mdoc（ISO/IEC 18013-5）が主に使われる。

0090・0092 の認証方式のポートの上に載せるには、次を決める必要がある。

- ウォレットとの間の HTTP の形は OpenID4VP が決めている（要求の取得は `GET` で `application/oauth-authz-req+jwt`、応答は
  `application/x-www-form-urlencoded` の `POST`）。今のポートの汎用のパスは JSON の `{"payload": …}` だけで、ウォレットはこれを話せない。
  ウォレットはブラウザでなく、別オリジン（CSRF の保護）にもセッションにも合わない
- 同じ端末（ブラウザとウォレットが同じスマートフォン）と別の端末（PC の画面の QR をスマートフォンで読む）の 2 つの流れ。別の端末では、
  応答がブラウザでなくウォレットから届く（0104 の別の経路からの応答と同じ形）。登録（本人の結び付け）も別の端末で行うことが多い
- 何を信じるか：資格情報の発行者（realm ごと）、発行者の鍵の手に入れ方（ネットワークを使うか）、失効（Token Status List）
- 資格情報のどの値で利用者を引くか。0103 と同じく、方式は Storage を触らない
- SD-JWT の解析は攻撃者の入力をそのまま読む。開示（disclosure）の扱いを誤ると、署名されていない値を信じてしまう

## 決定

### フィーチャーと方式

- フィーチャー `openid4vp`（依存なし、既定オフ）。方式は `authn/method/openid4vp`、名前は `openid4vp`、所持の要素（ウォレットの鍵の所持を
  key binding で確かめる）、1要素目と2要素目に使える。amr は `swk`、AAL の上限は 2。ウォレットの鍵がハードウェアにあるか（WSCD）と、
  ウォレットが本人の PIN・生体を確かめたかは、検証者からは確かめられないので数えない（0093）
- 設定は `methods.openid4vp.realms.<realm の slug>`（0103 と同じ `port.ConfigurableAuthenticator`）。realm の設定が無ければ方式を動かさない（404）。
  設定の誤り（読めない鍵・発行者、知らない項目）は起動を止める
- 認証情報（本人の結び付け）は 0092 の `authn_credentials` に置く。新しい表もマイグレーションも足さない。消去・統合・書き出しと読み込み・
  フィーチャーの無効化（データを消す）は 0092 のまま効く
- 応答は別の経路（ウォレット）から届くので `OutOfBand`（0104）。届くまで `complete` は `202 pending`

### ポートの拡張（0092・0104 への追加）

- **方式のエンドポイント**（任意のインターフェース `port.EndpointAuthenticator`）：HTTP の形を外部の仕様が決める方式のために、
  `GET`・`POST /v1/login/methods/{method}/endpoints/{endpoint}`（`/realms/{slug}` の接頭辞を含む）を方式に渡す。
  コアはクエリと、`application/x-www-form-urlencoded` の本文（256 KiB まで）だけを読んで `MethodHTTPRequest` にし、方式が返す
  状態コード・Content-Type・本文をそのまま返す（`Cache-Control: no-store`）。セッションを要さず、CrossOriginProtection の外に置く
  （ウォレットはブラウザでない。SAML の ACS と同じ）。`/v1/login/` の下なので、`POST` には接続元ごとのレートリミットと応答時間の下限が効く。
  方式の監査ログ（0104）はコアが記録する。方式のエラーは、照合の失敗・入力の誤り・見つからないは `400 invalid_request`、それ以外は 500
- **`MethodSetup.BaseURL`**：realm の公開の URL（`server.public_url`。realm のパスの接頭辞を含む）。ウォレットに渡す `response_uri`・`request_uri` を作る。
  空なら `openid4vp` は起動を止める
- **登録の完了の `202 pending`**：別の経路から応答が届く方式の `EnrollComplete` が `port.ErrMethodPending` を返したら、コアはフローを
  回数を数えずに置き直し、`POST /v1/me/credentials/{method}:enroll-complete` は `202`（`status: pending`）を返す（トランザクションは巻き戻す）

### 要求（OpenID4VP 1.0）

- `begin`（`enroll-begin`）で、方式がトランザクション（`state`。256 bit のランダム）と `nonce`（256 bit）を作り、本文に
  `authorization_request`（ウォレットを開く URL。既定 `openid4vp://`）と流れ（`same_device`・`cross_device`）を返す。
  クライアントは同じ端末ならその URL に遷移し、別の端末なら QR にする。流れは本文の `flow` で選び、設定の `flows` にあるものだけを許す
- `response_type=vp_token`、`response_mode=direct_post`、`response_uri` は `<BaseURL>/v1/login/methods/openid4vp/endpoints/response`。
  `direct_post.jwt`（応答の暗号化）は後続
- クライアント ID の接頭辞（`client_id_prefix`）
  - `redirect_uri`（既定）：`client_id` は `redirect_uri:<response_uri>`。仕様のとおり要求に署名できないので、要求は URL に値で載せる（`client_metadata` を含む）
  - `x509_san_dns`・`x509_hash`：設定の鍵（ECDSA P-256 と ES256。0005 の範囲）と証明書の連鎖（`x5c`）で要求のオブジェクト（JAR。
    `typ: oauth-authz-req+jwt`、`aud: https://self-issued.me/v2`）に署名し、`request_uri`（`…/endpoints/request?id=…`。ランダムな ID）で渡す。
    `x509_san_dns` は証明書の DNS の SAN と `response_uri` のホストが合わなければ起動を止める。`x509_hash` は証明書の SHA-256
  - `openid_federation`・`decentralized_identifier`・`verifier_attestation` は後続
- 求める資格情報は DCQL で 1 つだけ（`id: credential`、`format: dc+sd-jwt`、`meta.vct_values`、`claims` は結び付けと属性に使う値の `path`）。
  `claim_sets` を使わないので、書いた値は全部必須になる。`require_cryptographic_holder_binding` は既定（true）のまま
- トランザクションは方式の EphemeralStore（0104）に、`state` のハッシュをキーに置く（期限 `request_ttl`、既定 5 分、10 分以下）。
  中身は `nonce`、流れ、用途、応答を暗号化する鍵（下記）。要求のオブジェクトは要求の ID のハッシュをキーに置き、期限まで何度でも取れる

### 応答（direct_post）

- ウォレットの `POST`（`state`、`vp_token` か `error`）で、`state` のトランザクションを**取り出す**（1 回だけ）。`vp_token` は JSON の
  オブジェクトで、キーは `credential` だけ、値は提示 1 つの配列に限る（それ以外は拒む）
- 提示（SD-JWT VC）を確かめ（下記）、結果を方式の EphemeralStore に置いてブラウザの `complete` を待つ。結果（確かめた値は個人情報）は、
  `begin` で作ってコアの封をしたフローの状態にだけ持つ鍵で AES-256-GCM で暗号化する（EphemeralStore には平文の値も鍵も残らない。
  トランザクションの中の鍵は応答で取り出して消える）
- 同じ端末：応答に `redirect_uri`（設定の `same_device_redirect_uri` に `#response_code=…`）を返す。`complete` には `response_code` を
  求め、合わなければ通さない（OpenID4VP 13.3 のセッションの固定への備え。応答を受けたブラウザだけが完了できる）
- 別の端末：応答は `{}`。ブラウザは `complete` を `202 pending` の間呼び直す。QR を別人に見せて提示させる中継（フィッシング）は、
  別の端末の流れに固有の危険として受け入れる（OpenID4VP 14 章）。止めたい realm は `flows: [same_device]` にする
- 失敗（確かめられない・`error` の応答）も結果として置き、ブラウザの `complete` を失敗で終わらせる。ウォレットには `400 invalid_request`。
  理由はウォレットにもブラウザにも返さず、監査ログ（`method.openid4vp.presentation_rejected` と `login.failed`）に残す（0022）

### 提示の確かめ（fail-closed）

- **SD-JWT の解析は自前で書く**（`authn/method/openid4vp/sdjwt`）。JWS の署名の確認は既に使っている `go-jose/v4` に任せ、受ける alg を
  `ES256`・`ES384`・`ES512`・`EdDSA` に限る（`none`・HMAC を受けない）。開示の処理は RFC 9901 7.1 のとおり：
  - `_sd_alg` は `sha-256` だけ。ダイジェストの重複、どこからも指されない開示、2 回指される開示、`_sd`・`...` を名前に持つ開示、
    既にある名前を上書きする開示、`{"...": …}` に別の項目がある配列の要素を拒む。指す開示の無いダイジェスト（デコイ）は捨てる
  - SD-JWT VC で選択的に開示してはならない値（`iss`・`nbf`・`exp`・`cnf`・`vct`・`vct#integrity`・`status`）を開示で出すものを拒む
  - 大きさ（提示 64 KiB、開示 256 個、入れ子 32 段）に上限を置く。解析と開示の処理にファジングのテストを置く
- 発行者の JWT：`typ` は `dc+sd-jwt`（旧 `vc+sd-jwt` も受ける）、`iss` が realm の**信じる発行者**（`issuers`）のどれかと一致し、
  その発行者の鍵で署名を確かめる。鍵は設定の JWKS（`kid` で選ぶ）か、`x5c` の連鎖を設定のトラストアンカー（発行者ごと）まで確かめた
  証明書の鍵。JWT VC Issuer Metadata（`/.well-known/jwt-vc-issuer`）をネットワークで取りに行くことはしない（後続）
- `vct` が realm の `vct_values` にあり、発行者に `vct_values` があればそれにもあること。`exp`・`nbf`・`iat` を時刻の許容幅（1 分）で確かめる
- **key binding は必須**：`cnf.jwk`（公開鍵だけ）の鍵で KB-JWT（`typ: kb+jwt`）の署名を確かめ、`aud` がクライアント ID、`nonce` が
  トランザクションの `nonce`、`sd_hash` が提示の SHA-256、`iat` が `kb_max_age`（既定 5 分）以内であることを確かめる
- 失効：Token Status List（`status`）はこの ADR では確かめない。分からないときは拒む（fail-closed）ので、`status` を持つ資格情報は既定で拒む。
  運営者が `status: ignore` を書いた realm だけが、確かめずに受ける（危険を運用文書に書く）
- 求めた `claims` が全部開示されていること（無ければ拒む）

### 利用者との結び付け

- realm の `subject_claim`（`path`。例 `["sub"]`・`["personal_administrative_number"]`）の値を、発行者（`iss`）と `path` と合わせて
  検索キー（ブラインドインデックス。0090）にする。値は文字列か数だけを受ける。1要素目は、この値で**本人が登録した結び付け**を引く（0103 と同じ）
- **確かめた値の一致でのログイン**：発行者に `link_by_email: true` を書くと、結び付けが無いときに、開示された `email_claim`（既定 `["email"]`）
  の値を、確認済みのメールアドレスとしてログインできる本人の引き当て（0101 の `MethodUsers`。メールごとの回数の上限とロックアウトが効く）に渡し、
  見つかればその本人に結び付けを作ってログインさせる。発行者がメールアドレスの持ち主を確かめていると運営者が保証するときだけ書く。既定はオフ
- **確かめた属性として持つ**：realm の `attributes`（名前と `path`）の値を、結び付けのデータ（ユーザーのデータ鍵で暗号化。9.5）に、発行者・
  `vct`・確かめた時刻と一緒に持つ。登録の応答で本人に返し、ログインのたびに新しい提示の値で置き換える（比較と交換）。
  ID トークンのクレームやカスタム属性（ADR 0080）への反映は後続
- 登録：本人がログインしたセッションで `enroll-begin` を呼び、提示させる（同じ端末・別の端末）。同じ値が誰かに結び付いていれば
  `409 credential_exists`、1 人 5 個まで（`max_credentials`）。無効化は 0092 の汎用の無効化。方式の外に片付けるものは無い
- 2要素目は、本人の結び付けに限る

### 監査ログ・無効化・ファジング

- 汎用のもの（`login.succeeded`・`login.failed`・`credential.registered`・`credential.revoked`）に加えて、
  `method.openid4vp.presentation_received`（発行者・`vct`・流れ）と `method.openid4vp.presentation_rejected`（理由）。詳細に開示された値を入れない
- フィーチャーの無効化は 0092 の汎用の片付け（`openid4vp` の認証情報を消して完了）
- ファジング：SD-JWT の解析と開示の処理（`FuzzParse`・`FuzzDisclose`）、`vp_token` の解析（`FuzzParseVPToken`）

### この ADR の外（後続）

- **mdoc**（ISO/IEC 18013-5、`mso_mdoc`。COSE と CBOR の検証、デバイスの署名、セッションの転写）。0103 の X.509 の検証と `fxamacker/cbor` の上に、
  同じ方式の別の形式として足す。DCQL の `format` と結び付けの規則は、この ADR の形のまま増やせる
- Digital Credentials API（ブラウザの `navigator.credentials.get`、`origin` の接頭辞）、`direct_post.jwt`（応答の暗号化）、`request_uri_method=post`、
  `openid_federation` などの接頭辞、`transaction_data`
- Token Status List による失効の確認、JWT VC Issuer Metadata による発行者の鍵の取得、信頼リスト（EU の Trusted Lists・LoTE）の読み込み
- ホスト型のログイン画面への表示（0092 と同じく、汎用の方式はまだ出さない）

## 結果

- EUDI Wallet などの SD-JWT VC で、ログイン・2要素目・本人の結び付けができる。realm ごとに発行者・資格情報の種類・結び付けの値を変えられる
- 提示の確かめはネットワークを使わない（発行者の鍵は設定から）。発行者の鍵の更新は設定の更新（再起動）になる
- 応答はウォレットから届くので、方式に HTTP の口が要る。方式のエンドポイントは汎用にしたので、ウォレットや外部の承認（CIBA など）を待つ
  別の方式も同じ形で足せる。CSRF の保護の外に出るので、方式は入力を全部疑う
- `status` を持つ資格情報は、失効を確かめるまで既定で受けない。EUDI の PID は `status` を持つことが多く、運営者は `status: ignore` か
  後続の失効の確認を待つかを選ぶ
- 別の端末の流れは、QR の中継による誤ったログインを防げない。同じ端末だけにする選択を残す

## 検討した代替案

- **SD-JWT のライブラリを入れる**：Go の SD-JWT の実装は、どれも利用者が少なく、保守と SD-JWT VC・KB-JWT の最新の版への追従が見えない（0038 の基準に届かない）。
  危ない部分（署名の確認）は go-jose に任せ、開示の処理は数百行の自前のコードとファジングで持つ方が確かめやすい
- **汎用の `:callback`（JSON）にウォレットを合わせる**：ウォレットは OpenID4VP の形（フォームの `POST`、JWT の `GET`）しか話さない
- **ウォレットの応答で直接セッションを発行する**：ブラウザに結び付かず、同じ端末でもセッションの固定を防げない。応答は結果を置くだけにし、
  セッションはブラウザのフロー（コアの封をした状態と `response_code`）で発行する
- **確かめた値を EphemeralStore に平文で置く**：個人情報が EphemeralStore（Redis など）に残る（0014）。フローの状態にだけある鍵で暗号化する
- **発行者の鍵を JWT VC Issuer Metadata で取りに行く**：ネットワークの障害と、`iss` の URL を信じることの扱いが要る。まずは設定に固定し、後で足す
- **`status` を確かめずに受ける**：失効した資格情報でログインできる。既定は拒み、運営者の明示でだけ緩める
- **確認済みのメールでいつでも結び付ける**：発行者がメールアドレスを確かめていなければ、他人のアカウントに入れる。発行者ごとの明示に限る
