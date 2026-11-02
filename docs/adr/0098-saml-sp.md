# 0098. 外部 IdP としての SAML 2.0 は goxmldsig で署名を確かめ、プロトコルの確認は自前の薄い層で行う

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.1、11.3、13.2、13.4、[0005](0005-crypto-no-rsa-pqc.md)、[0030](0030-security-assurance.md)、
  [0038](0038-library-selection.md)、[0077](0077-org-sso.md)、[0089](0089-enterprise-full-scope.md)

## 背景

企業の IdP（ADFS、Entra ID、Okta、Shibboleth など）は SAML 2.0 しか出せないことが多い。Org 専用 SSO（ADR 0077）は OIDC だけで、
SAML は「別に決める」としていた。0089 で SAML（iam が SP になる側）を含めることにし、XML 署名のような危険な部分は、
ライブラリの選定とファジングを実装の前に決めることにした。

XML 署名には次のよく知られた攻撃がある。

- XML Signature Wrapping（XSW）：署名した要素を残したまま、別の位置に書き換えた要素を置き、検証する要素と読む要素をすり替える
- コメントの挿入：`<NameID>user@a.example<!---->.evil.example</NameID>` のように、正規化（コメントを除く）では一続きの文字列が、
  読み方によっては前半だけになる
- 複数の Assertion：署名した Assertion と署名していない Assertion を並べ、後者を読ませる
- 弱いアルゴリズム：SHA-1 の署名とダイジェスト

## 調査結果（2026-11-02 時点。各モジュールのソースを確かめた）

| ライブラリ | 確かめたこと |
|---|---|
| crewjam/saml v0.5.1 | SP と IdP の全体。時刻は `saml.TimeNow`・`saml.Clock` のパッケージ変数で、サービスごとに Clock を渡せない。要求の状態（Cookie・要求の追跡）を自前で持ち、iam のフロー（EphemeralStore に封をした状態、フロー ID）と二重になる。SHA-1 を拒む設定が無い。過去に署名の迂回（CVE-2020-27846）と複数 Assertion（CVE-2022-41912）の脆弱性があった（修正済み） |
| russellhaering/goxmldsig v1.6.1 | XML 署名の検証と正規化。crewjam/saml もこれを使う。`Validate` は、**署名を確かめたバイト列から作り直した要素**を返す（読む要素を検証した要素に限れる）。`Signature` の子の数を確かめる（`validateShape`）。証明書は登録したものと一致するものだけを使い、期限を `Clock` で確かめる。ファジングのテストを持つ。過去に、検証した要素と違う要素を返す脆弱性（CVE-2020-15216、1.1.0 で修正）があった。SHA-1 の署名を `x509.Certificate.CheckSignature` で受け付ける（拒むのは使う側） |
| beevik/etree v1.7.0 | goxmldsig が使う DOM。名前空間の URI を `NamespaceURI` で取れる |
| mattermost/xml-roundtrip-validator v0.1.0 | `encoding/xml` の往復で意味が変わる入力（名前空間の扱いの不具合。CVE-2020-29509 など）を拒む |

脆弱性データベース（vuln.go.dev・OSV）には、この作業の環境から問い合わせられなかった。上の CVE は既知の勧告として記したもので、
CI の govulncheck（design.md 13.4）で確かめる。

## 決定

- 署名の検証は goxmldsig を使う。SAML のプロトコルの確認（Issuer・Audience など）は `authn/saml` に自前の薄い層を書く。
  crewjam/saml は使わない（Clock を渡せない、状態の持ち方が二重になる、SHA-1 を拒めない）
- 応答（`samlp:Response`）の検証の不変条件
  - **署名を確かめた Assertion だけを受ける**。応答だけの署名は受けない（応答の署名は、あれば確かめる）。
    値は goxmldsig が返す、署名を確かめたバイト列から作り直した要素からだけ読む（XSW を防ぐ）
  - Reference はちょうど 1 つで、署名した要素の `ID` を指す（空の URI で文書全体を指すものは受けない）。Assertion の中の署名はちょうど 1 つ
  - 文書全体で Assertion はちょうど 1 つ（Advice・Extensions の中も数える）。`ID` が重なる文書は受けない
  - 署名は RSA・ECDSA の SHA-256 / 384 / 512、ダイジェストは SHA-256 / 384 / 512。SHA-1 は受けない
  - 正規化と変換は Exclusive C14N（コメントを含まないもの）と enveloped-signature だけ
  - コメント・処理命令（XML 宣言を除く）・DOCTYPE を含む文書は受けない。深さ（32）・要素の数（4096）・大きさ（256 KiB）を限る。
    文字列は、子の要素やコメントを含まない要素からだけ読む（コメントの挿入を防ぐ）
  - `Destination` と bearer の `SubjectConfirmationData` の `Recipient` は ACS の URL、`InResponseTo` は送った AuthnRequest の `ID`、
    `Audience` は SP の Entity ID、`Issuer` は IdP の Entity ID。時刻（`NotBefore`・`NotOnOrAfter`・`SessionNotOnOrAfter`・`IssueInstant`）は
    Clock で確かめ、ずれは 3 分まで許す。未知の Condition は受けない
  - 暗号化された Assertion・NameID・属性（`EncryptedAssertion` など）は受けない。SP のメタデータに暗号の鍵を載せず、IdP に暗号化させない
  - `transient` の NameID は受けない（同じ人を見分けられない）
- フローは OAuth（ADR 0066 の外部プロバイダ）と同じ形にする
  - `POST /v1/login/saml/{connection}:start` が AuthnRequest（HTTP-Redirect。設定で ECDSA-SHA256 の署名を付ける）の URL を返す。
    フローの状態（connection、AuthnRequest の ID、フロー ID のハッシュ、期限、連携先のユーザー）は封をして EphemeralStore に置き、
    鍵は RelayState のハッシュにする。フロー ID は要求した側（`__Host-iam_saml` Cookie と応答）にだけ渡す
  - IdP はホスト型ログイン画面の ACS（`/login/saml/acs`、HTTP-POST）に応答を送る。ACS は別サイトからの POST なので CrossOriginProtection の外に置き、
    値を画面に渡すだけにする（状態を変えない）。画面が同じオリジンから `POST /v1/login/saml:complete` を呼ぶ（Lax の Cookie が届く）
  - 完了の API は、状態を `Take` で 1 回だけ取り出し、フロー ID と結び付いているか、ログインと連携のどちらのフローか（RelayState が `link.` で始まるものは連携）を確かめる。
    IdP からの一方的な応答（IdP-initiated）は受けない
  - Assertion の `ID` は connection ごとに 1 回だけ受ける（EphemeralStore の `Incr`。期限は Assertion の期限まで、最長 24 時間）。
    `InResponseTo` を 1 回限りの状態に結び付けているので、重ねての防御になる
- ログイン・登録・連携は OIDC と同じコード（`oauth.LoginFederated`・`LinkFederated`）を通る。外部 ID は (connection, NameID)。
  Org 専用の connection では、その Org の管理ユーザーだけがログイン・連携でき、ログインはその Org に入る。登録は Org が証明したドメインのアドレスに限り、
  管理ユーザーとメンバーとして作る（Quota を確かめる）。既存のユーザーのアドレスなら自動リンクしない。`require_sso` は SAML の connection の外部 ID でも満たす
- メールは設定の属性（`email_attribute`）か、既定の名前（`email`・`mail`・`emailaddress`・`urn:oid:0.9.2342.19200300.100.1.3`・Microsoft のクレーム名）の、値が 1 つのもの。
  無ければ emailAddress 形式の NameID。SAML には `email_verified` が無いので、確認済みとみなすのは、Org 専用の connection（証明済みドメインに限る）と、
  運営者が `trust_email` にした realm 共通の connection だけにする
- connection の登録
  - Org：`POST /v1/me/orgs/{id}/connections:saml`（`org:settings`）。OIDC と同じ上限（5）・個人 Org の禁止。フィーチャー `org_managed_users` も要る
  - realm：管理 API の `POST /v1/admin/connections:saml`（`connections:manage`）。slug は運営者が決める
  - IdP のメタデータは XML か URL で渡す。URL は https に限り、登録のときに一度だけ、ADR 0077 と同じ SSRF の対策（公開のアドレスに限り、解決したアドレスに直接つなぐ。
    リダイレクトを追わない）で取得する。メタデータの署名は確かめない（渡す人が内容に責任を持つ）。署名の証明書は 5 つまで、期限切れは登録しない
  - SP の Entity ID は `{公開の URL}/login/saml/metadata/{slug}`（SP のメタデータの URL を兼ねる）、ACS は `{公開の URL}/login/saml/acs`。Org は選べない
  - SP の署名鍵は connection ごとの ECDSA P-256（ADR 0005）。PKCS#8 を封をして connections.config に置き、自己署名の証明書（10 年）をメタデータに載せる
- 新しいテーブルは作らない（connections の `type = saml`、identities、EphemeralStore）。割り当てたマイグレーションの番号は使わない
- フィーチャー `saml`（既定オフ）。無効にするときは SAML の connection を消し、紐付けた外部 ID を無効化する。フィーチャーがオフなら、
  開始・完了・ACS・メタデータは 404、ホスト型の画面とホームレルム発見には出さない
- ファジング：応答の検証（`FuzzVerify`）と IdP のメタデータの解析（`FuzzParseIdPMetadata`）
- 監査ログ：OIDC と同じ（`login.succeeded`・`login.failed` の `method` が `saml`、`identity.linked`、`connection.created`、`org.connection.added`・`removed`）
- 後続：Single Logout（SLO。IdP からの LogoutRequest と、iam からの LogoutRequest）、暗号化された Assertion（RSA-OAEP と AES-GCM に限る。CBC の
  パディングオラクルの攻撃があるため）、メタデータの定期的な取り直しと証明書の切り替え、IdP-initiated、HTTP-POST バインディングの AuthnRequest、
  ECDSA の署名の値（XML 署名の r||s。goxmldsig は DER で扱う）の IdP の互換

## 結果

- 危険な部分（署名の検証と正規化）は広く使われているライブラリに任せ、受け付ける形を狭くして攻撃面を減らす
- 署名の無い Assertion（応答だけに署名する IdP）、SHA-1 の IdP、コメントの入った応答、暗号化だけの IdP、期限切れの証明書の IdP とはつながらない。
  運用の手引きで、Assertion の署名（SHA-256）を IdP で有効にするように書く
- Org の owner は、登録のたびに iam から公開のアドレスへ GET を 1 回起こせる（OIDC のトークンエンドポイントと同じ程度）
- `/login/saml/acs` は CrossOriginProtection の外にあるが、画面を返すだけで状態を変えない

## 検討した代替案

- crewjam/saml の `ServiceProvider` を使う：プロトコルを自前で書かずに済むが、Clock と状態の持ち方が合わず、SHA-1 を拒めない。
  使う部分（応答の解析）だけでも、確認の順序と範囲を自分で確かめる必要があり、薄い層を書くのと変わらない
- 応答の署名だけでも受ける（SAML の仕様では許される）：署名した応答の中の Assertion を読むことになり、範囲の取り違えの余地が増える
- IdP-initiated を受ける：`InResponseTo` が無く、ログインの CSRF とリプレイの対策が Assertion の ID の記録だけになる
- ACS で完了まで行う（サーバー側で Cookie を発行する）：2 要素目・登録の続き・戻り先の扱いを ACS に別に書くことになる。画面に渡して公開 API で完了すれば、OAuth と同じ扱いになる
