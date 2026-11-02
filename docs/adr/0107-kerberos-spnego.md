# 0107. Kerberos / SPNEGO は realm ごとの keytab で AP-REQ を確かめる認証方式のプラグインにし、プリンシパルは登録・メール・LDAP の規則でユーザーに結び付ける

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.1、9.5、13.2、[0038](0038-library-selection.md)、[0083](0083-multi-realm.md)、
  [0089](0089-enterprise-full-scope.md)、[0090](0090-authenticator-plugins.md)、[0092](0092-authenticator-port-implementation.md)、
  [0093](0093-acr-aal-step-up.md)、[0101](0101-port-totp-and-password.md)、[0102](0102-ldap.md)、[0103](0103-x509-client-certificates.md)、
  [0104](0104-sms-voice-otp-and-push-approval.md)

## 背景

Active Directory のドメインに参加した Windows の端末（と、Kerberos のチケットを持つ macOS・Linux）では、利用者はサインインしたまま
ブラウザで社内のサービスに入れる（統合 Windows 認証、デスクトップ SSO）。HTTP では Negotiate（RFC 4559）で、サーバーが 401 と
`WWW-Authenticate: Negotiate` を返すと、ブラウザが `Authorization: Negotiate <SPNEGO のトークン>` を付けて送り直す。トークンの中身は
Kerberos の AP-REQ（RFC 4120、4121）で、サービスの鍵（keytab）で暗号化されたチケットと、セッション鍵で暗号化された認証子を持つ。
scope.md の「Kerberos／SPNEGO」（S P）。0090 で認証方式をプラグインにし、0092・0103 で汎用の認証情報と設定のある方式を作った。
Kerberos を載せるには、次を決める必要がある。

- トークンは JSON の本文ではなく `Authorization` のヘッダーで届き、セッションの Bearer のトークンと同じヘッダーを使う。チャレンジ（401）を誰が返すか
- AP-REQ の確かめをどこまで自分で書くか。SPNEGO・ASN.1・Kerberos の暗号は自前で書くには重い
- プリンシパル（`alice@CORP.EXAMPLE.COM`）と iam のユーザーの結び付け。ディレクトリの人と iam のユーザーはふつう既に結び付いている
- 再送（同じトークンの使い回し）、弱い暗号（DES・RC4）、信頼関係の先の realm、時刻のずれ
- テスト。KDC を立てずに、本物と同じトークンで確かめたい

## 調査結果（2026-11-02 時点。モジュールのソースを確かめた）

| ライブラリ | 確かめたこと |
|---|---|
| jcmturner/gokrb5/v8 v8.4.4 | Go の純粋な Kerberos の実装で、Go で広く使われる（HashiCorp Vault の Kerberos 認証などが使う）。keytab の読み書き、AP-REQ の確かめ（`service.VerifyAPREQ`：チケットの復号、期限、アドレス、認証子の復号と本人の一致、時刻のずれ、プロセスの中の再送のキャッシュ）、SPNEGO と GSS-API のトークンの解析、チケットの作成（`messages.NewTicket`）を持つ。依存は jcmturner の小さなモジュール（aescts・dnsutils・gofork・goidentity・rpc）と hashicorp/go-uuid・x/crypto・x/net |

gokrb5 の SPNEGO の受け手（`SPNEGO.AcceptSecContext`・`SPNEGOKRB5Authenticate`）には次の問題がある。

- `NegTokenInit` の `MechTypes` が空だと添字の範囲外で panic する
- `KRB_ERROR` の Kerberos のトークンを「成功」（`ok = true`、状態 `StatusUnavailable`）として返す
- 時刻は `time.Now()` 固定で、Clock を差し込めない

最後のリリースは 2023 年で、更新は落ち着いている。脆弱性データベース（vuln.go.dev・OSV）には、この作業の環境から問い合わせられなかった。
CI の govulncheck（design.md 13.4）で確かめる。

## 決定

### フィーチャーと方式

- フィーチャー `kerberos`（依存なし、既定オフ）。方式は `authn/method/kerberos`、名前は `kerberos`、**1要素目だけ**
- 方式の設定は設定ファイルの `methods.kerberos.realms.<realm の slug>`（0103・0104 の `port.ConfigurableAuthenticator`）。realm の設定が
  無ければ、その realm では方式を動かさない（404）。設定の誤り（読めない keytab、keytab にサービスの鍵が無い、未知の規則など）は
  起動を止める。他の realm の設定も起動時に確かめる
  - `keytab`（ファイルのパス。起動時に読む）、`service_principal`（`HTTP/<ホスト名>[@REALM]`）、`accepted_realms`（受け付ける本人の
    realm。既定はサービスの realm。信頼関係の先は明示する）、`max_clock_skew`（既定 5 分、最大 10 分）、`case_insensitive_names`
    （AD 向け。名前を小文字にそろえる）、`allow_rc4`（既定 false）、`mapping`、`max_credentials`（既定 5）
- amr は `wia`（RFC 8176 の Windows 統合認証）。iam は KDC での本人確認の手段（パスワード・スマートカード・Windows Hello）を
  知らないので、0093 の対応表で外部 ID（`fed`）と同じ「分類の分からない 1 要素」にする。単独で AAL1、所持の 2要素目と合わせて AAL2。
  方式が宣言する AAL の上限は 2。2要素目が要る realm では、Kerberos の後に passkey・TOTP などを求める
- 要素の種類は所持（チケットのセッション鍵の所持の証明）。2要素目と step-up には使わない（同じ端末のサインインの使い回しで、
  別の要素にならない）

### トークンの受け取りとチャレンジ（コア）

- コアは `Authorization` が Negotiate の方式のときは**どのパスでもヘッダーを消し**、汎用のログインの完了
  （`POST /v1/login/methods/{method}:complete`）と登録（`/v1/me/credentials/{method}:enroll-begin`・`:enroll-complete`）でだけ
  Base64 を戻して `MethodEnv.Negotiate` で方式に渡す（大きさは 64 KiB まで。形の誤りは空のトークンとして方式が拒む）。
  ヘッダーを消すのは、Negotiate を Bearer のセッションと取り違えず、登録で Cookie のセッションを読めるようにするため
- 方式がトークンを求めたら（`port.ErrNegotiate`）、コアは 401 と `{"error":"negotiate"}`、`WWW-Authenticate: Negotiate` を返す。
  ログインの完了では、フローを**回数を数えずに**置き直し、失敗の監査ログにも残さない（照合していない）。ブラウザは同じ要求を
  トークン付きで送り直す。照合に失敗したら、チャレンジを付けない 401（ブラウザが繰り返さない）
- 確かめはネットワークを使わない（KDC に問い合わせない。CPU だけ）。ログインの完了はトランザクションの外（0101）
- 相互認証（AP-REP を `WWW-Authenticate` で返す）はしない。ブラウザは無くても進む

### 確かめること（方式）

- 解析は gokrb5 の SPNEGO の受け手を使わず、自分の薄い層で行う：SPNEGO の `NegTokenInit`（`MechTypes` の**先頭**が Kerberos か
  MS の Kerberos のときだけ。楽観的なトークンは先頭の方式のもの。RFC 4178 4.2.1）か、SPNEGO で包まない GSS-API の Kerberos の
  トークン（RFC 4121 4.1）から、AP-REQ だけを取り出す。NTLM・`NegTokenResp`・AP-REP・KRB-ERROR は拒む。外部のコードの panic は拒否にする
- チケット：暗号の種類は AES（17・18・19・20）だけ（`allow_rc4` で 23 を足せる。DES・3DES は拒む）。宛先（realm と名前）は設定の
  サービスのプリンシパルと同じ。keytab の鍵で復号し、gokrb5 の `service.VerifyAPREQ` で期限・認証子の本人の一致・時刻のずれを確かめる。
  PAC は読まない（使わない。解析する面を減らす）。チケットにアドレスがあれば接続元と合うときだけ通す。セッション鍵の種類も同じ制限。
  invalid の印のあるチケットを拒む
- 本人：`accepted_realms` の realm の、要素が 1 つの名前（`host/pc1` のようなサービスのプリンシパルと、`@`・`/`・`\`・制御文字を含む
  名前を拒む。AD の名前は空白を含みうるので、空白は前後のものだけを拒む）。プリンシパルは `名前@REALM`
- 再送：gokrb5 のプロセスの中のキャッシュに加え、EphemeralStore（方式と realm で前置きしたもの）の `Incr` で、サービス・本人・
  認証子の時刻の組をインスタンスをまたいで 1 回にする（時刻のずれの 2 倍で消える）
- 時刻は gokrb5 がシステムの時計で確かめる（Kerberos はもともと時計に頼る。テストは今の時刻でチケットを作る）

### プリンシパルとユーザーの結び付け（`mapping.rule`）

- `enrollment`（既定）：本人がログインしたセッション（直近の認証）で、Negotiate 付きで `enroll-begin`（トークンを確かめて
  プリンシパルを返す）と `enroll-complete`（登録）を呼ぶ。汎用の認証情報（`authn_credentials`）に、プリンシパルを検索キー
  （ブラインドインデックス）にして置く。同じプリンシパルが誰かに登録されていれば `409 credential_exists`、1 人 5 個まで
- `email`：プリンシパル `name@REALM` を、メールアドレス `name@<email_domains[REALM]>`（既定は realm を小文字にしたもの）にし、
  確認済みのメールのユーザーに結び付ける
- `ldap`：realm 共通の LDAP の connection（0102。フィーチャー `ldap`）で、サービスアカウントで `(&{user_filter}({attribute}={値}))`
  （値はエスケープ）をちょうど 1 件探し、その外部 ID（`entryUUID`・`objectGUID`）を紐付けたユーザーに結び付ける。`attribute` の既定は
  `userPrincipalName`、値は `principal`（`name@REALM`。既定）か `name`（`sAMAccountName`・`uid`。受け付ける realm が 1 つのときだけ）。
  AD で無効のアカウントと、iam に紐付いていない人は拒む（自動の登録はしない）。Org 専用の connection は使わない（Org の owner が書いた
  ディレクトリで realm の本人を決めさせない）。ディレクトリに届かない・フィーチャー `ldap` が動いていなければ 503（`directory_unavailable`）
- `email` と `ldap` は方式が Storage を触らないよう、コアが `MethodEnv.Principals`（`port.MethodPrincipals`。1要素目の完了でだけ渡す）
  で引く。どれも、ログインできる状態のユーザーだけを返し、それ以外は理由を区別しない。結び付けは**毎回引き直し**、そのユーザーの
  Kerberos の認証情報（検索キーはプリンシパル）を使う（無ければ作る）。前に作ったものが別のユーザーのものなら無効化して作り直す
  （メールの付け替え・ディレクトリの変更に追従する）。セッションはその認証情報に結び付く
- 規則 `email`・`ldap` での `enroll-begin` は `400 enrollment_not_supported`。`enrollment` に戻したときは、自動で作った認証情報を
  本人の登録として使わない（登録し直す）
- `email`・`ldap` は、KDC とディレクトリの運営者がその realm のどのアカウントにも入れることを意味する（0102 の `trust_email` と同じ
  信頼）。運営者が設定で明示する

### 監査ログ・無効化・ファジング

- 監査ログは汎用のもの（`login.succeeded`・`login.failed`（`method: kerberos`、理由に realm と規則。名前は残さない）・
  `credential.registered`（`enrollment`）・`credential.revoked`）。チャレンジ（トークンの無い 1 回目）は残さない。規則 `email`・`ldap` で
  ログインのときに作った認証情報は `credential.registered` を残さない（`login.succeeded` の `credential_id` で追える）
- フィーチャーの無効化は 0092 の汎用の片付け（`kerberos` の認証情報を消して完了）。方式の外に片付けるものは無い
- ファジング：トークンの解析と確かめ（`FuzzVerify`。panic せず、鍵を知らない入力を通さない）とヘッダーの解析（`FuzzNegotiateToken`）
- テストは同じプロセスの KDC の代わり（`authn/method/kerberos/kerberostest`）：keytab を作り、`messages.NewTicket` で本物と同じ
  チケットを作って AP-REQ と SPNEGO で包む。方式からは KDC が発行したものと区別できない

### この ADR の外

- ホスト型のログイン画面への表示（0092・0103 と同じく、汎用の方式はまだ出さない）。画面を開いたときに自動で Negotiate を試す流れ
- keytab の再読み込み（今は再起動）、PAC のグループの取り込み、相互認証（AP-REP）、チャネルバインディング、NTLM（受けない）
- カスタム属性（0080）での結び付け（属性の値の索引が無い。必要になれば索引を足す）

## 結果

- AD に参加した端末から、パスワードを打たずにログインできる。realm ごとに keytab・受け付ける realm・結び付けを変えられる
- ブラウザは iam のホスト名を統合認証の許可リスト（Chrome の `AuthServerAllowlist`、Firefox の `network.negotiate-auth.trusted-uris`、
  Windows のイントラネットのゾーン）に入れておく必要がある
- 確かめは CPU だけで、KDC が落ちてもチケットを持つ人は入れる（チケットの期限まで）
- `wia` は AAL1 で、AAL2 が要る realm では 2要素目を求める

## 検討した代替案

- **gokrb5 の SPNEGO の受け手・HTTP のミドルウェアを使う**：上の panic と KRB-ERROR の扱い、Cookie のセッション（gorilla/sessions）を
  前提にした作りで、realm ごとの設定と監査ログに合わない。AP-REQ の確かめだけを使う
- **SPNEGO・Kerberos を自前で書く**：ASN.1・暗号（AES-CTS・鍵の導出）・チケットの構造は重く、誤りやすい。広く使われる gokrb5 に任せる
- **Kerberos を外部 ID の connection（0102 の LDAP と同じ）にして、自動で登録する**：チケットには名前と realm しか無く、メールも
  安定した ID も分からないので、新しいユーザーを作る材料が無い。結び付けの規則で既存のユーザー（とその外部 ID）を引き、認証方式の
  ポートの汎用の認証情報に載せる方が、無効化・統合・監査ログが共通になる
- **常にプロキシ（mod_auth_gssapi など）で Negotiate を終えてヘッダーで渡す**：0103 の証明書と違い、Kerberos はアプリケーションの層で
  確かめられる。プロキシとヘッダーの信頼の設定を増やさない
- **2要素目に使う**：同じ端末のサインインから得たチケットで、1要素目と同じ本人確認を数え直すことになる
- **RC4 を既定で受ける**：RC4-HMAC は弱く、AD でも AES に移っている。必要なら運営者が明示する
