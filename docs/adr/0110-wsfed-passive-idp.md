# 0110. WS-Federation のパッシブ要求者プロファイルを IdP として持ち、トークンは realm の ES256 の鍵で XML 署名する

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.5、5.8、9.3、11.0、[scope.md](../scope.md) 4 章、[0005](0005-crypto-no-rsa-pqc.md)、[0040](0040-spike-mldsa-opaque-signer.md)、
  [0066](0066-oidc-authorization-code-flow.md)、[0089](0089-enterprise-full-scope.md)、[0094](0094-oidc-rp-initiated-and-front-channel-logout.md)、
  [0098](0098-saml-sp.md)

## 背景

SharePoint（オンプレミス）、古い ASP.NET の Windows Identity Foundation（WIF）のアプリ、一部の業務パッケージは、IdP とのつなぎ方に
WS-Federation のパッシブ要求者プロファイル（WS-Federation 1.2 の 13 章。ブラウザの転送と自動の POST で SAML のトークンを渡す）しか持たない。
ADFS から移るときに、これが無いと移れない（scope.md 4 章の「WS-Federation、CAS」。出どころ P）。0089 で範囲に含めた。

WS-Federation は iam が IdP（セキュリティトークンサービス。STS）になる側で、SAML 2.0 の SP（0098。iam が受ける側）とは向きが逆になる。
受け取った XML を検証するのではなく、iam が XML を組み立てて署名する。

## 調査結果（2026-11-02 時点）

- 要求は `wa=wsignin1.0`（`wtrealm`・`wreply`・`wctx`・`wfresh`・`wct`・`whr`・`wauth`・`wreq`・`wreqptr`）と `wa=wsignout1.0`
  （`wreply`）。応答は、`wreply` へ自動で POST するフォームに `wa`・`wresult`（`RequestSecurityTokenResponse`。WS-Trust 2005/02）・`wctx` を入れる
- トークンは SAML 1.1 か SAML 2.0 の Assertion。WIF と SharePoint の既定は SAML 1.1。属性の名前は、SAML 1.1 では
  `AttributeNamespace` と `AttributeName` に分けたクレームの種類の URI（最後の `/` で分ける）、SAML 2.0 では `Name` に URI をそのまま入れる
- メタデータは `/FederationMetadata/2007-06/FederationMetadata.xml`（ADFS と同じパス）の SAML 2.0 メタデータに、
  `fed:SecurityTokenServiceType` の RoleDescriptor（`PassiveRequestorEndpoint` と署名の証明書）を入れたもの
- XML 署名は 0098 と同じ russellhaering/goxmldsig（`SigningContext`。`crypto.Signer` を受ける）と beevik/etree で作れる。新しい依存は要らない。
  ただし goxmldsig は ECDSA の署名の値を DER で書く。XML 署名（RFC 4050、XML Signature 1.1 の 6.4.3）の ECDSA の値は `r||s` の固定長なので、
  `crypto.Signer` を包んで `r||s` にする（.NET の `SignedXml` と Apache Santuario は `r||s` を読む）
- .NET Framework の WIF（SharePoint のオンプレミス）は、トークンの署名に RSA を前提にしているものが多い。ECDSA を読めるかは RP の実装による

## 決定

- フィーチャー `wsfed`（既定オフ）。実装は `authn/wsfed`（プロトコルの組み立て・RP の登録・署名の証明書）と `server/app/wsfed.go`（HTTP）。
  認証方式ではない（OIDC Provider と同じ、ログインした後に連携先へ渡す側）ので `authn/method/` には置かない
- エンドポイント（realm ごと。複数 realm では realm の issuer の下）
  - `GET /wsfed`：パッシブ要求者のエンドポイント。`wsignin1.0` と `wsignout1.0` だけを受ける
  - `GET /wsfed/resume`：ログイン画面から戻ってトークンを渡す（OIDC の `/oauth2/authorize/resume` と同じ形）
  - `GET /FederationMetadata/2007-06/FederationMetadata.xml`：メタデータ（署名付き）
  - フィーチャーがオフならどれも 404
- RP の登録は管理 API `/v1/admin/wsfed/relying-parties`（一覧・作成・取得・置き換え・削除。権限 `clients:manage`。realm ごと）
  - `realm`：`wtrealm`（絶対 URI、1024 バイトまで、realm の中で一意。比べるのは完全一致）
  - `reply_urls`：`wreply` の許可リスト（1〜10 個。https の絶対 URL でフラグメントなし。完全一致）。`wreply` が無ければ最初のものに返す
  - `token_type`：`saml11`（既定）か `saml20`
  - `claims`：クレームの対応（32 個まで）。`source` は `user_id`・`email`・`org_id`・`amr`・`attribute:<キー>`（フィーチャー `custom_attributes`）、
    `type` はクレームの種類の絶対 URI（SAML 1.1 では最後の `/` の後ろが空でないこと）。省略したら `email` を
    `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` に出す
  - `token_lifetime`：Assertion の有効期間（秒。300〜86400、既定 3600）
- **知らないものは受けない（fail closed）**。どれも RP に戻さず、画面に 400 を出す（エラーで知らない `wreply` へ転送しない）
  - `wtrealm` が無い・登録に無い、`wreply` が登録の完全一致でない、`wa` が上の 2 つ以外
  - 応えられない要求の引数（`wreq`・`wreqptr`・`wauth`）があるとき。`wfresh` が 0 以上の整数でないとき、`wctx` が 2048 バイトを超えるとき
  - `whr`（ホームレルムの指定）と `wct` は読まない
- サインイン
  - セッション（制限の無いもの）があり、`wfresh` を満たし（`0` は今からのログイン、正の値は分）、active な Org が使えるときだけトークンを渡す。
    無ければ要求を封をして EphemeralStore に預け（10 分、キーは秘密の ID のハッシュ）、ログイン画面に回す。戻ったときに RP と `wreply` を確かめ直す
  - Assertion は bearer。主体は `NameIdentifier`（ユーザーの公開 ID。OIDC の `sub` と同じ。形式は unspecified）、Audience は `wtrealm`、
    発行者は realm の issuer、時刻は Clock の今から `token_lifetime` まで。SAML 2.0 は `SubjectConfirmationData` の `Recipient` に `wreply` を入れる。
    認証の時刻は本人確認の時刻。`AuthenticationMethod`（SAML 1.1）・`AuthnContextClassRef`（SAML 2.0）は、amr に `pwd` があれば password、
    無ければ unspecified
  - メールは確認済みで、保存しているもの（`index_only` でない）だけを出す。WS-Federation には `email_verified` が無く、RP はメールを本人の
    識別子に使うことが多いため、確認していないアドレスは出さない。Org の文脈では OIDC と同じく Membership に結び付けたメール
  - 応答は自動で POST する画面（スクリプトは同じオリジンのファイル、無効なら送信のボタン）。CSP の `form-action` は `wreply` のオリジンだけ
  - フロー フックの `pre_token`（ADR 0081）は通さない（クレームは RP の登録の対応だけで決まる。後続）
- 署名
  - realm の ES256 の署名鍵（OIDC の ID トークンと同じ鍵。0040）で、ECDSA-SHA256・ダイジェスト SHA-256・Exclusive C14N・enveloped-signature。
    署名の値は `r||s`。Assertion（SAML 1.1 は `AssertionID`、SAML 2.0 は `ID`）とメタデータ（`EntityDescriptor` の `ID`）に署名する。RSTR 全体には署名しない
  - KeyInfo とメタデータには、鍵ごとの自己署名の証明書（10 年）を載せる。ECDSA の署名は毎回変わるので、証明書は作ったものを
    `authn_wsfed_certificates` に置き、同じ鍵には同じ証明書を返す（RP が指紋で登録するため）。鍵が JWKS から消えたら証明書も消す
  - 鍵の切り替え（`POST /v1/admin/signing-keys:rotate` の ES256）で証明書も変わる。退役した鍵の証明書はメタデータに残るので、
    メタデータを読み直す RP は続けて使える。指紋を手で登録した RP は登録し直す
  - ML-DSA-65 は使わない（XML 署名の識別子が無い）。RSA は使わない（0005）。0089 の RS256 のフィーチャーができたら、RP ごとに
    RSA-SHA256 を選べるようにする（後続）
- サインアウト（`wsignout1.0`）：`wtrealm` が登録にあり、`wreply` が無いか登録と完全一致のときだけ、確かめずにブラウザのセッションを
  失効させ（`POST /v1/logout` と同じ。Back-Channel Logout も送る）、`wreply` に戻す（無ければ完了の文言）。ほかの RP への
  サインアウトの伝播（`wsignoutcleanup1.0` を iframe で開く）はしない
- 新しいテーブル：`authn_wsfed_relying_parties`（sqlite 00058、postgres 00041）と `authn_wsfed_certificates`（sqlite 00059、postgres 00042）。
  RP は本人の認証情報ではないので `authn_credentials` には置かない。OIDC の連携先（`authn_clients`）とは形（client_id・秘密・戻り先の扱い）が違い、
  混ぜると OIDC の検証を間違えるため分ける
- 監査ログ：`wsfed.token_issued`（RP・`wtrealm`・トークンの種類・Assertion の ID）、`wsfed.signed_out`、
  `wsfed.relying_party.created`・`updated`・`deleted`。知らない `wtrealm`・`wreply` の拒否は未ログインでも起こせるので、アプリケーションログにだけ出す
- フィーチャーの無効化で、RP と証明書を消す
- ファジング：要求の引数の解析（`FuzzParseRequest`）と RP の入力の確認（`FuzzValidateInput`）。署名は goxmldsig の検証で確かめるテストを持つ

## 結果

- ADFS から WS-Federation の RP を、登録（`wtrealm`・`wreply`・クレーム）を移すだけで iam に向けられる
- 署名は ECDSA だけなので、RSA しか読めない RP（.NET Framework の WIF の多く。SharePoint のオンプレミスを含む）は、RS256 のフィーチャー（0089）
  ができるまでつながらない。ECDSA を読める RP（.NET の `System.IdentityModel.Tokens.Saml`、Java、Shibboleth など）はつながる
- サインアウトは確かめずに行う（WS-Federation の RP は確認の画面を前提にしない）ので、登録済みの `wtrealm` を知るページは、トップレベルの遷移で
  利用者をログアウトさせられる（ログアウトの CSRF）。セッションを終えるだけで、ほかの影響は無い
- トークンの再利用（同じ RSTR を 2 度送る）は RP が防ぐ（bearer の Assertion。WIF は既定で再生を検出する）。iam は期限を短くできるようにする

## 検討した代替案

- 認証方式のディレクトリ（`authn/method/wsfed`）に置く：WS-Federation は本人確認の方式ではなく、ログインの結果を RP に渡すプロトコル。OIDC Provider と同じ場所に置く
- crewjam/saml の IdP を使う：SAML 2.0 の Web SSO の IdP で、WS-Federation の RSTR と SAML 1.1 を作れない。Clock を渡せない理由（0098）も同じ
- 証明書を毎回作る：ECDSA の署名は乱数を使うので、毎回違う証明書になり、指紋で登録した RP が使えない
- RP の登録を OIDC の連携先の表に足す：戻り先の確かめ方（OIDC は登録の完全一致と PKCE、WS-Federation は `wtrealm` と `wreply`）と項目が違い、
  OIDC の検証に WS-Federation の行が混ざる
- サインアウトを確認の画面にする（0094 と同じ）：WS-Federation の RP はサインアウトで画面が止まることを前提にしていない。影響はセッションの終了だけなので、確かめずに行う
