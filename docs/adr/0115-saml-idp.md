# 0115. SAML 2.0 の IdP を持ち、要求は登録した SP の完全一致と署名で確かめ、応答は realm の ES256 の鍵で XML 署名する

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.9、9.3、11.0、[scope.md](../scope.md) 4 章、[0005](0005-crypto-no-rsa-pqc.md)、[0040](0040-spike-mldsa-opaque-signer.md)、
  [0089](0089-enterprise-full-scope.md)、[0093](0093-acr-aal-step-up.md)、[0098](0098-saml-sp.md)、[0110](0110-wsfed-passive-idp.md)

## 背景

業務 SaaS（Salesforce、ServiceNow、Workday、AWS IAM Identity Center、Atlassian など）と社内の古いアプリの多くは、IdP とのつなぎ方に
SAML 2.0 の Web Browser SSO しか持たないか、SAML を前提にしている。ADFS・Okta・Entra ID から移るときに、iam が SAML の IdP になれないと
移れない（scope.md 4 章の「SAML 2.0 IdP」。出どころ S P C）。0089 で範囲に含めた。

iam は SAML の SP（0098。外部の IdP から受ける側）と WS-Federation の IdP（0110。SAML の Assertion を組み立てて署名する側）を持っている。
SAML の IdP は両方にまたがる：SP からの AuthnRequest・LogoutRequest を検証し（署名は SP の鍵）、Response・LogoutResponse を組み立てて署名する（iam の鍵）。

## 調査結果（2026-11-02 時点）

- SAML 2.0 の Web Browser SSO Profile（Profiles 4.1）：SP-initiated（AuthnRequest を HTTP-Redirect か HTTP-POST で受け、Response を ACS へ
  HTTP-POST で返す）と IdP-initiated（AuthnRequest なしで Response を送る）。Single Logout Profile（4.4）は LogoutRequest と LogoutResponse
- AuthnRequest の HTTP-Redirect は DEFLATE と base64 で、署名はクエリの `SAMLRequest=…&RelayState=…&SigAlg=…` を、受け取ったとおりの
  URL エンコードのまま署名する（Bindings 3.4.4.1）。XML の中の署名は外す。HTTP-POST は base64 の XML で、根の要素に enveloped の署名を入れる
- XML Signature Wrapping（XSW）：署名した要求を `Extensions` などに隠し、外側を書き換える。署名した要素の ID を外側に付け直す、Reference が
  中の要素を指す、などの形がある。対策は 0098 と同じく、署名を確かめたバイト列から作り直した要素（goxmldsig の `Validate` の戻り値）からだけ読むこと
- 0098 の検証（`authn/saml/verify.go`）は、字句の確認（コメント・処理命令・DOCTYPE を拒む、深さと要素の数を限る、encoding/xml の往復の確認）、
  アルゴリズムの制限（SHA-1 を拒む、Exclusive C14N だけ）、goxmldsig の enveloped の検証を持つ。0110 の署名（`authn/wsfed/sign.go`）は
  realm の ES256 の鍵で、署名の値を `r||s` にする crypto.Signer と、鍵ごとの自己署名の証明書を持つ。どちらも SAML の IdP がそのまま使える
- goxmldsig は ECDSA の署名の値を DER で読む。XML 署名の ECDSA は `r||s`（RFC 4050、XML Signature 1.1 の 6.4.3）なので、iam の SP は iam の IdP や
  仕様どおりの ECDSA の SP・IdP を確かめられなかった（0098 の後続の「ECDSA の署名の値の互換」）。SignatureValue は SignedInfo の外にあり、
  検証の前に `r||s` を DER に直しても署名の範囲は変わらない
- Assertion の暗号化（XML Encryption）：SP の多く（Shibboleth、crewjam/saml、OpenSAML、SimpleSAMLphp）は鍵の運搬に RSA-OAEP
  （`rsa-oaep-mgf1p`）、内容に AES-CBC か AES-GCM を読む。crewjam/saml の SP は `xmlenc11#aes128-gcm` を読み、`aes256-gcm` を読まない。
  `rsa-oaep-mgf1p` で DigestMethod を SHA-256 にすると、MGF1 のハッシュ（仕様では SHA-1 に固定）を SHA-256 で扱う実装があり、互換が崩れる
- RequestedAuthnContext の値：`PasswordProtectedTransport`・`Password`・`unspecified`（SAML 2.0 の Authentication Context）、REFEDS の
  `https://refeds.org/profile/mfa`、Entra ID・ADFS の `http://schemas.microsoft.com/claims/multipleauthn`。比べ方は exact（既定）・minimum・maximum・better
- HTTP-POST の AuthnRequest は別のサイトからの POST なので、SameSite=Lax のセッションの Cookie が付かない

## 決定

- フィーチャー `saml_idp`（既定オフ）。実装は `authn/samlidp`（SP の登録・要求の解析と検証・応答の組み立てと署名と暗号化・メタデータ）と
  `server/app/samlidp.go`（HTTP）。認証方式ではなく、ログインした後に連携先へ渡す側なので `authn/method/` には置かない（OIDC Provider・0110 と同じ）
- 0098 の XML の扱いと 0110 の署名を `authn/samlxml` に移し、SAML の SP・SAML の IdP・WS-Federation が共通に使う（動きは変えない）。
  加えて、ECDSA の証明書で確かめるとき、SignatureValue が `r||s` なら DER に直してから goxmldsig に渡す（SP の側の互換も直る）
- エンドポイント（realm ごと。複数 realm では realm の issuer の下）。IdP の Entity ID は realm の issuer
  - `GET /saml/idp/sso`（HTTP-Redirect）・`POST /saml/idp/sso`（HTTP-POST）：AuthnRequest
  - `GET /saml/idp/sso/resume`：ログイン画面から（と HTTP-POST の要求から）戻って Response を渡す
  - `GET /saml/idp/init?sp=<Entity ID>&RelayState=…`：IdP-initiated（SP ごとに許したときだけ）
  - `GET /saml/idp/slo`（HTTP-Redirect）・`POST /saml/idp/slo`（HTTP-POST）：LogoutRequest。`GET /saml/idp/slo/resume` は HTTP-POST の続き
  - `GET /saml/idp/metadata`：IDPSSODescriptor（署名付き。SSO と SLO の 2 つのバインディング、NameID の形式、署名の証明書）
  - 別のオリジンの SP からのトップレベルの遷移なので CrossOriginProtection の外に置く。POST は確かめて封をして預け（EphemeralStore。10 分）、
    同じオリジンの GET へ 303 で回し、セッションを見る処理は GET で行う（Lax の Cookie が届く）。フィーチャーがオフならどれも 404
- SP の登録は管理 API `/v1/admin/saml/service-providers`（一覧・作成・取得・置き換え・削除。権限 `clients:manage`。realm ごと）
  - `entity_id`（絶対 URI。realm の中で一意。完全一致）、`name`
  - `acs`：1〜10 個。https の絶対 URL（フラグメント・利用者情報なし）、バインディングは HTTP-POST だけ、番号（`index`）と既定（`default`）
  - `slo`：0〜2 個（HTTP-Redirect・HTTP-POST を 1 つずつ）。登録するには署名の証明書が要る
  - `signing_certificates`：AuthnRequest・LogoutRequest を確かめる SP の証明書（3 つまで。PEM か base64 の DER。RSA 2048 bit 以上か
    ECDSA P-256・P-384・P-521。期限切れは登録しない）と `require_signed_requests`（署名の無い AuthnRequest を受けない）
  - `encryption_certificate`：あれば Assertion を必ず暗号化する（RSA 2048 bit 以上）
  - `name_id_format`（persistent（既定）・emailAddress・unspecified・transient）と `name_id_source`（`user_id`（既定）・`email`・
    `attribute:<キー>`。emailAddress の既定は `email`）
  - `attributes`：属性の対応（32 個まで）。`source` は 0110 と同じ（`user_id`・確認済みの `email`・`org_id`・`amr`・`attribute:<キー>`）、
    `name`・`name_format`（uri（既定）・basic・unspecified）・`friendly_name`
  - `sign_assertion`（既定 true）・`sign_response`（既定 false）。どちらも false は受けない。`allow_idp_initiated`（既定 false）。
    `assertion_lifetime`（秒。60〜3600、既定 300）
  - 設定は `authn_saml_service_providers` の `config`（JSON）にまとめて置く（列を増やさずに項目を足せる）
- **知らないものは受けない（fail closed）**。次は SP に戻さずに画面に 400 を出す（確かめていない戻り先へ転送しない）
  - Issuer が無い・登録に無い SP、ACS が登録と完全一致しない（URL・番号・HTTP-POST 以外の ProtocolBinding・URL と番号の両方）
  - 署名が確かめられない（鍵が違う、書き換えた、SHA-1、SP の証明書が無いのに署名がある、`require_signed_requests` で署名が無い、
    HTTP-Redirect の XML に署名がある、HTTP-Redirect の署名と XML の署名の両方がある）
  - 字句・形の誤り：コメント・処理命令・DOCTYPE、深さ 32・要素 4096・64 KiB を超えるもの、根の直下以外の署名・2 つ以上の署名、
    ID の重なり、Assertion・暗号化された要素を含むもの。Version が 2.0 でない、ID が xs:ID らしくない
  - Destination が SSO（SLO）の URL と完全一致しない（署名した要求では Destination を必須にする）。IssueInstant が 10 分（とずれ 3 分）より古い・
    3 分より先。同じ SP の同じ要求の ID を 2 度（EphemeralStore の `Incr`。受け付ける期間だけ覚える）
  - 署名を確かめた後は、署名を確かめた要素からだけ値を読み、その Issuer が引いた SP の Entity ID と一致することを確かめ直す（XSW を防ぐ）
- SP と ACS を確かめた後の、応えられない要求は ACS へ失敗の Response（Assertion なし。いつも署名する）で返す
  - `Subject` の指定：Requester / RequestUnsupported。登録と違う NameIDPolicy の Format・他の SP の SPNameQualifier：Requester / InvalidNameIDPolicy
  - RequestedAuthnContext：`AuthnContextDeclRef`、比べ方 `better`、知っている値が 1 つも無い：Requester / NoAuthnContext
  - IsPassive でログイン画面が要る：Responder / NoPassive。ログインし直しても要求の acr に届かない：Responder / NoAuthnContext
  - active な Org が使えないセッション：Responder / RequestDenied（4.7。OIDC と同じ）。NameID の値が無い（確認済みのメールが無いなど）：Responder / InvalidNameIDPolicy
- サインイン
  - セッション（制限の無いもの）が ForceAuthn（要求を受けた時刻より後の本人確認）と RequestedAuthnContext を満たせば Response を渡す。
    無ければ要求を預けてログイン画面へ回し、戻ったときに SP の登録（Entity ID・ACS・IdP-initiated の許可）を確かめ直す。預けた要求は Response を渡したら消す
  - RequestedAuthnContext は acr（0093）に対応させる：`PasswordProtectedTransport`・`Password` は AAL1、REFEDS MFA と `multipleauthn` は AAL2、
    acr の値（`urn:iam:aal1`〜`3`・`phr`・`phrh`。AAL3・phrh はハードウェアの方式が動くときだけ）はそのまま、`unspecified` はどれでも満たす。
    exact・minimum・maximum は、要求の値のうちセッションが満たす最初のものを AuthnContextClassRef に入れる（AAL は「以上」で比べる）。
    満たさなければ step-up（ここから後のログイン）を求める。要求が無ければ、amr に `pwd` があれば `PasswordProtectedTransport`、無ければ `unspecified`
  - Assertion は bearer。Issuer は realm の issuer、Audience は SP の Entity ID、SubjectConfirmationData の Recipient は ACS、InResponseTo は要求の ID
    （IdP-initiated では付けない）、時刻は Clock の今から `assertion_lifetime` まで。AuthnStatement の SessionIndex は SP とログインの系列（sid）から
    作る値（SP ごとに違う）
  - NameID：persistent・unspecified は公開のユーザー ID（OIDC の `sub`）か設定の出どころ、emailAddress は確認済みで保存しているメール
    （Org の文脈では Membership に結び付けたもの。0110 と同じ理由で、確認していないアドレスは出さない）、transient は毎回の乱数
  - 応答は ACS へ自動で POST する画面（スクリプトは同じオリジンのファイル、無効なら送信のボタン）。CSP の `form-action` は ACS のオリジンだけ
  - フロー フックの `pre_token`（ADR 0081）は通さない（属性は SP の登録の対応だけで決まる。0110 と同じ。後続）
- 署名と暗号化
  - 0110 と同じく realm の ES256 の使っている鍵で、ECDSA-SHA256・SHA-256・Exclusive C14N・enveloped-signature、署名の値は `r||s`。
    Assertion（`sign_assertion`）と Response（`sign_response`）の Issuer の後に入れる。両方なら Assertion に署名してから Response に署名する
  - 鍵ごとの自己署名の証明書（10 年）を `authn_saml_idp_certificates` に置き、同じ鍵には同じ証明書を返す（SP が証明書・指紋で登録するため）。
    JWKS から消えた鍵の証明書は消す。WS-Federation の証明書とは表を分ける（どちらかのフィーチャーを無効にしても、もう片方の証明書が変わらないように）
  - HTTP-Redirect の LogoutResponse はクエリに ECDSA-SHA256 で署名する（値は `r||s`）。HTTP-POST の LogoutResponse は XML に署名する
  - 暗号化は、署名した Assertion を AES-128-GCM（`xmlenc11#aes128-gcm`。CipherValue は IV・暗号文・タグ）で暗号化し、その鍵を
    RSA-OAEP（`rsa-oaep-mgf1p`、DigestMethod と MGF1 は SHA-1）で SP の証明書へ運ぶ。CBC は使わない（パディングオラクル）。
    OAEP の SHA-1 は衝突への強さに依らないので弱くならず、MGF1 のハッシュの解釈が実装で揃うのはこの組だけ
  - ML-DSA-65 は使わない（XML 署名の識別子が無い）。iam の鍵では RSA を使わない（0005）。RSA を使うのは SP の公開鍵の検証と暗号化だけ
- Single Logout（IdP が受ける側）
  - LogoutRequest はいつも署名を求める（署名の無いものでは、どの SP の要求か確かめられず、ログアウトの CSRF になる）。形・Destination・
    IssueInstant・`NotOnOrAfter`・ID の再利用は AuthnRequest と同じに確かめる。NameID は必須、`BaseID`・`EncryptedID` は受けない。SLO の登録が無い SP は 400
  - ブラウザのセッションの本人が LogoutRequest の本人（SessionIndex があれば、その SP にこのセッションで渡した値を含むこと。NameID は
    transient でなければ、この SP に渡す値と一致すること。transient は SessionIndex で決める）なら、セッションを失効させ（`POST /v1/logout` と同じ。
    Back-Channel Logout も送る）、Success を返す。セッションが無ければ Success、別の本人ならセッションを残して Requester / UnknownPrincipal
  - LogoutResponse は SP の SLO の、受け取ったのと同じバインディングのもの（無ければ登録した方）へ返す
  - ほかの SP への伝播（IdP が LogoutRequest を送る）と、IdP から始める SLO はしない（後続）
- 新しいテーブル：`authn_saml_service_providers`（sqlite 00068、postgres 00051）と `authn_saml_idp_certificates`（sqlite 00069、postgres 00052）。
  SP は本人の認証情報ではないので `authn_credentials` には置かない。OIDC の連携先・WS-Federation の RP とは項目と戻り先の確かめ方が違うので分ける
- 監査ログ：`saml_idp.assertion_issued`（SP・Entity ID・Assertion と Response の ID・InResponseTo・IdP-initiated か・NameID の形式・
  AuthnContextClassRef・暗号化したか）、`saml_idp.logged_out`、`saml_idp.service_provider.created`・`updated`・`deleted`。
  拒んだ要求と失敗の Response は未ログインでも起こせるので、アプリケーションログにだけ出す
- フィーチャーの無効化で、SP の登録と証明書を消す（預けた要求は EphemeralStore の期限で消える）
- ファジング：AuthnRequest の解析（`FuzzParseAuthnRequest`）、HTTP-Redirect のクエリの読み取り（`FuzzDecodeRedirect`）、LogoutRequest の解析
  （`FuzzParseLogoutRequest`）。XSW の 3 つの形（同じ ID で外側を書き換える、外側の署名が中を指す、外側に署名が無い）を拒むテスト、
  発行した Response が iam の SP の検証（0098）に通るテストを持つ

## 結果

- ADFS・Okta などから SAML の SP を、登録（Entity ID・ACS・証明書・属性）を移すだけで iam に向けられる
- 署名は ECDSA だけなので、RSA の署名しか読めない SP は、RS256 のフィーチャー（0089）ができるまでつながらない。多くの SaaS は IdP の
  メタデータの証明書の鍵の種類に従うが、RSA を前提にするものがある。運用の手引きで、SP が ECDSA を読めるかを確かめるように書く
- iam の SP（0098）が `r||s` の ECDSA の署名を確かめられるようになり、iam の IdP と iam の SP がつながる
- IdP-initiated は `InResponseTo` が無く、別のサイトが利用者を `/saml/idp/init` に送れば、利用者は本人のアカウントで SP にログインさせられる（ログインの CSRF）。
  RelayState もそのまま SP に渡る（SP の側のオープンリダイレクトに注意）。そのため SP ごとの opt-in にした
- Single Logout は IdP が受けて自分のセッションを終えるところまでで、ほかの SP のセッションは残る
- RelayState は 1024 バイトまで受ける（Bindings 3.4.3 は 80 バイトとするが、超える SP が多い）

## 検討した代替案

- crewjam/saml の `IdentityProvider` を使う：Clock を渡せない、状態を自前で持つ、SHA-1 を拒めない（0098 と同じ理由）。署名の鍵も crypto.Signer で
  `r||s` にできない
- 署名の検証と組み立てを `authn/samlidp` に複製する：0098 と 0110 の危険な部分（字句の確認・goxmldsig の使い方・`r||s`）が 3 か所に分かれ、
  直し漏れが起きる。共通の `authn/samlxml` に移した
- AuthnRequest の署名を必須にする：多くの SP は署名しない。ACS を登録の完全一致に限れば、署名が無くても Assertion は登録した ACS にしか届かない
  （SAML の通常の安全の前提）。署名を求めたい SP には `require_signed_requests` を用意した
- HTTP-POST の AuthnRequest をその場で処理する：Lax の Cookie が届かず、ログインしていてもログイン画面に回り、IsPassive では誤って NoPassive になる
- Assertion の暗号化に AES-256-GCM や `xmlenc11#rsa-oaep`（SHA-256）を使う：読めない SP がある（調査結果）。AES-128-GCM と `rsa-oaep-mgf1p` で十分に強い
- SP の設定を列に分けて持つ：項目が多く、足すたびにマイグレーションと 3 つの Storage の変更が要る。検索に使うのは Entity ID だけなので、残りは JSON にした
