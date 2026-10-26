# IAM Design Doc

- Status: Draft / Last updated: 2026-10-25
- このドキュメントは「今どうなっているか」だけを書く。判断の理由は [ADR](adr/README.md)、フェーズごとのゴールは [roadmap.md](roadmap.md)

## 1. 目的

セルフホストできる認証・認可基盤。

- **最低限**：個人識別。1ユーザーに複数のメールアドレス・複数の OAuth を紐付ける
- **ゴール**：ユーザーと Group の多対多。ログインに使った手がかり（メール、passkey、IP など）で Org を選ぶ
- **当面やらない**：SCIM、ReBAC、管理画面の作り込み（必要になれば M7 で検討。Org 専用 SSO は拡張フィーチャーとして後から）

## 2. 基本方針

### 2.1 認証と認可の分離

| | 認証 (authn) | 認可 (authz) |
|---|---|---|
| 問い | 誰か、どの Org の文脈か | 何ができるか |
| 概念 | User、認証手段、Org、Membership（所属の有無）、Session | Group、Role、Permission |

authn は Group を知らない。

### 2.2 リポジトリ構成

同一リポジトリで、モジュール境界を強制する（ADR 0001）。

```
iam/
├── authn/      # User、認証手段、Org、Membership、Session（ポートを定義）
├── authz/      # Group、Role、Permission、判定（ポートを定義）
├── shared/     # ID 型、エラー型、監査ログなど最小限
├── adapters/   # ポートの実装：storage/{sqlite,postgres,mysql} ephemeral/{memory,redis} notifier/{webhook,dev} keystore/{file,env}
├── server/     # HTTP（authn/authz を組み立てるだけ）、設定ファイル
├── cmd/iam/    # 設定を読みアダプタを選んで起動
├── api/        # OpenAPI の定義（公開 API・管理 API の契約の正）
├── internal/archtest/  # モジュール境界の違反の検出
└── spikes/     # 前提の検証（ADR 0040〜0043）
```

- Go モジュールは、本体（ルート）、DB の Storage アダプタごと（`adapters/storage/sqlite` など）、`cmd/iam`、`spikes` に分ける（ADR 0015）。開発時は `go.work` で束ねる
- テーブル名は `authn_`・`authz_`・`shared_` の接頭辞でモジュールを分ける（スキーマを持つ DB ではスキーマで分けてもよい）

- authz が authn から受け取るのは principal の ID と Org の ID だけ。モジュール間の呼び出しは公開インターフェース経由のみ
- DB はスキーマ（または名前空間・テーブル接頭辞）で分け、モジュールをまたぐ JOIN・外部キーは禁止（ID でのみ参照）
- コアは `adapters/` を import しない

### 2.3 標準への準拠

OIDC、WebAuthn に準拠する。認可 API は `check(principal, action, resource, context)`（4.5）。暗号は 9章。

### 2.4 技術スタックと外部依存

| 領域 | 選定 |
|---|---|
| 言語 | Go 1.27 以上（`crypto/mldsa`） |
| HTTP | `net/http`。OpenAPI で定義し oapi-codegen で生成 |
| SQL / マイグレーション | sqlc / goose（Storage アダプタごと） |
| ID | 型付き接頭辞 + 128bit（`usr_`、`org_`、`ses_` …）。内部 ID（既定 UUIDv7）は DB の外に出さず、外に出すのは乱数の外部 ID だけ。採番の方式は設定で差し替える（ADR 0045） |
| ライブラリ | zitadel/oidc、lestrrat-go/jwx、go-webauthn（13.2） |

コアは具体的な製品に依存しない。外部とはポート（Go のインターフェース）でつなぎ、アダプタはホスト先が選ぶ。

| ポート | 役割 | 同梱アダプタ |
|---|---|---|
| Storage（唯一の必須） | 永続データ | SQLite / PostgreSQL / MySQL |
| EphemeralStore | 短命データ・キャッシュ・カウンタ | インメモリ / Redis |
| Notifier | 通知すべき出来事を外部に渡す | Webhook / 開発用 |
| KeyStore | 鍵の保管 | ファイル / 環境変数 |
| Clock | 現在時刻 | システム時計 / テスト用の偽の時計 |
| EventSink | 監査ログ等の外部出力（6.3） | 標準出力 / syslog / OTLP / Webhook |

アダプタは設定で選ぶほか、IAM を Go ライブラリとして import して自作のアダプタを渡せる。Webhook 系は他言語でも実装できる。

#### Storage

- 単一インスタンスなら SQLite（cgo 不要のドライバ）だけで動く。規模が大きくなったら PostgreSQL / MySQL へ移行する前提
- `iam storage export / import` でアダプタ間を移行できる（暗号化済みデータはそのまま移す）
- Repository はドメインの言葉で定義し、**中身は DB ごとに最適化してよい**（JSONB、RETURNING、ltree など。ADR 0004）
- コアが前提にするのは、トランザクション（Unit of Work）、一意性、ID・範囲での取得だけ
- DB 固有の追加機能（LISTEN/NOTIFY など）はオプションのポート。無ければ代替手段に切り替える
- スキーマ・マイグレーションはアダプタごと。振る舞いの一致は契約テスト（12章）で保証する

#### EphemeralStore

正（source of truth）にしない。置くのは、セッション・認可判定のキャッシュ、OAuth の state / PKCE、WebAuthn の challenge、レートリミットのカウンタ。複数インスタンスでは共有できるアダプタが必要（起動時に構成を検査する）。

#### Notifier

IAM は**メールの文面も URL も作らない**。出来事を ID で外部に渡し、文面・リンク・配送は外部が行う（ADR 0031）。

```json
{ "notification_id": "ntf_…", "type": "magic_link", "realm_id": "rlm_…", "user_id": "usr_…",
  "org_id": "org_…", "locale": "ja", "expires_at": "…", "has_secret": true }
```

- `user_id` は未登録のアドレス宛てなら無し、`org_id` は関係する場合のみ、`locale` は任意。`suspended` には種別を添える
- 種類：`email_verification` `magic_link` `account_exists` `recovery` `new_device_login` `credential_added` `credential_revoked` `suspended` `membership_invited` `deletion_scheduled` など
- **秘密（トークン・コード）と宛先はペイロードに入れない**。外部の配信側が `POST /v1/admin/notifications/{id}:claim` で**1回だけ**取り出す（`notifications:claim` 権限を持つ**配信用のサービスアカウント**が必要。これはサービスアカウントのフィーチャー（11.2）のオン・オフにかかわらず使え、権限は `notifications:claim` に固定）
  - 返すのは `to`・`token`・`expires_at`。利用者が入力した宛先は EphemeralStore に一時保持して返す（9.6 の最小化モードでも可）
  - IAM はトークンのハッシュだけを持つ。リンク先のアプリが公開 API（`/v1/magic-links:verify` など）で検証する
- 送出は outbox 経由（少なくとも1回。`notification_id` で重複排除）。Webhook には署名を付ける。期限内に取り出されなければ監査ログに残す
- 開発用アダプタ（開発ビルドのみ）：設定した URL の形式でリンクを組み立てて表示する

### 2.5 提供形態

セルフホスト型。ライセンスは Apache-2.0。単一バイナリ + コンテナイメージ + Go ライブラリ。

- **ログインは2本立て**：ホスト型ログイン画面（OIDC）と公開 API（ヘッドレス）。画面も公開 API の上に作る。画面は作り込まない（テンプレート差し替えと多言語化のみ）
- **公開 API**：`/v1` でバージョニング。OpenAPI で定義し SDK も生成。管理 API とはパス・ポートを分ける。CSRF・CORS・レートリミットに対応
- **管理 API**：運営者・管理者のセッション（強い認証、4.11）か、サービスアカウントのクライアント認証（client credentials）で保護する
- **別ドメインでの passkey**：RP ID を設定可能にし、Related Origin Requests（`/.well-known/webauthn`）に対応。主要ブラウザは対応済み（Chrome/Edge 128+、Safari 18+、Firefox 152+）。関連付けられるドメインは実質5種類まで
- **OAuth を API で行う場合**：プロバイダからの戻り先をアプリ側に向けられる（許可リスト）
- **運用**：必須の外部依存なし。危険な構成は起動時に警告・拒否。マイグレーションは前進のみ（自動適用か明示コマンドかを選べる）。最初の運営者は CLI で作る

### 2.6 拡張性と機能の取捨選択

- 機能はフィーチャー単位で、ビルド時（11.11）と起動時の2段階でオン・オフする
- オフの機能はコストゼロ。処理経路は起動時に組み立て、リクエストごとに分岐しない
- データモデルは最初から全機能に対応した形にし、オフでも既定値が入るだけ
- フィーチャーごとにレイテンシを計測し、遅いものは捨てられるようにする
- ホットパス（トークン検証・認可判定）に同期の外部呼び出しを置かない（どうしても必要ならオプトインのフィーチャーにし、タイムアウトを必須にする）

### 2.7 時刻

- 保存と API の値はすべて UTC（RFC 3339）。表示の変換はホスト先・クライアントが行う
- realm の既定タイムゾーン（既定 UTC）を初期設定で決め、Org で上書きできる。使うのは**日付だけの入力**の変換時のみ（その日の0時として、その日付時点のオフセットで変換し、使ったタイムゾーンを記録）
- 時刻の取得は Clock ポートに統一。DB との時刻のずれを監視する（既定 1秒で警告）

### 2.8 セキュリティ設定の階層

どこまで厳しくするかはホスト先と Org が決める（ADR 0033）。

```
ホスト先（設定ファイル）：既定値と、realm・Org が設定できる範囲。項目ごとに Org が緩められるか
  └ realm：範囲内で上書き
      └ Org：範囲内で上書き（既定は厳しくする方向のみ）
```

- 効く値は、そのリクエストの realm と active な Org で決まる（個人 Org は realm に従う）
- 対象：警告のアクション（10章）、セッションの寿命（5.4）、使える認証手段と登録方法、パスワードの要件、2段階認証の要否、bot 対策（`pre_registration` フックを求めるか）、リカバリーコードの発行、復旧の経路と待機期間（4.12）、ログインポリシー（4.4）
- 設定の変更は監査ログに残す
- 13.5 の不変条件は設定で外せない
- 起動時に決まるもの（アダプタ、フィーチャー、サーバーの既定値）は設定ファイル、実行中に変わるもの（realm、IdP 接続、Org のポリシー、属性定義）は Storage に置き管理 API で変更する

## 3. ドメインモデル

- すべてのデータは realm に属する。`realm_id` を直接持つか、`realm_id` を持つ親（user、org、group など）を通じて属する。一意制約は realm 内で効かせる（親を通じて属する表は、親の ID を含めて一意にする）
- 認可の主体は principal（user / service_account / group）
- 個人情報の列は暗号化して保存する（9.5）

### 3.1 認証側 (authn)

```
realms               id, slug UNIQUE, settings（タイムゾーン、寿命、メールの保持モードなど）

users                id, realm_id
                     owner_org_id          NULL=個人ユーザー / 値=Org 管理ユーザー（11.3）
                     display_name          任意。既定では持たない（9.6）
                     status                active / deleted / merged（停止は suspensions）
                     merged_into           統合先（11.6）
                     valid_from, valid_until（4.8）
                     deletion_scheduled_at, legal_hold（4.10）
                     created_at, updated_at

user_data_keys       user_id PK, wrapped_key, key_id, created_at
                     ユーザーごとのデータ鍵。削除で個人情報が復号不能になる（9.5）

user_emails          id, realm_id, user_id
                     email_ciphertext, email_index（HMAC）, domain_index, key_id
                     verified_at, verified_via（code / oauth_provider / sso / invitation / admin）
                     is_primary, created_at
                     UNIQUE (realm_id, email_index)

user_identities      id, realm_id, user_id, connection_id, provider_subject
                     email_at_link（既定では持たない）, created_at, revoked_*
                     UNIQUE (connection_id, provider_subject)

connections          id, realm_id, owner_org_id（NULL=realm 共通 / 値=Org 専用 SSO）, type（oauth2 / oidc / saml）, config

password_credentials id, user_id, hash（argon2id）, created_at, revoked_*
totp_credentials     id, user_id, secret_ciphertext, key_id, created_at, last_used_step, revoked_*
recovery_codes       user_id, code_hash（argon2id）, used_at, created_at
passkeys             id, user_id, credential_id, public_key, alg（ES256 / EdDSA / RS256）
                     sign_count, transports, name, preferred_org_id（4.4）, created_at, last_used_at, revoked_*
                     UNIQUE (realm_id, credential_id)（realm_id は user から引く）
revoked_passkey_credentials  realm_id, credential_id, revoked_at（再登録の拒否）, PK (realm_id, credential_id)

service_accounts     id, realm_id, org_id, name, valid_from, valid_until, created_at
service_account_credentials  id, service_account_id, type（client_secret / private_key_jwt / api_key）
                     secret_hash or public_key, expires_at, revoked_*

orgs                 id, realm_id, kind（personal / shared）, personal_owner_id, parent_org_id（11.4）
                     slug, name, valid_from, valid_until, timezone（NULL=realm の既定）, session_settings, created_at
                     UNIQUE (realm_id, slug)
memberships          id, user_id, org_id, status（invited / active / ended）
                     org_role（owner / admin / member）, email_id（この Org で使うメール。4.4）
                     valid_from, valid_until, ended_reason（self_leave / removed / expired / org_deleted / user_deleted）
                     created_at, UNIQUE (user_id, org_id)
invitations          id, realm_id, org_id, email_index, email_ciphertext, org_role
                     valid_from, valid_until, invited_by, expires_at, status（pending / accepted / revoked / expired）, created_at
org_domains          org_id, domain, verified_at（11.3）
org_login_policies   org_id, type（require_passkey / ip_allowlist / membership_email_domain / require_sso …）, config
org_quota_grants     id, realm_id, org_id, quota_key, kind（base / addon / override）, quantity
                     starts_at, ends_at（NULL=無期限）, source（manual / external）, external_ref, created_by, created_at
                     UNIQUE (org_id, quota_key, external_ref)

sessions             id, realm_id, principal_type（user / service_account）, principal_id
                     active_org_id         Org オンなら常に値あり / オフなら常に NULL
                     auth_methods（amr）, auth_credential_ids, warnings
                     ip, user_agent, created_at, last_seen_at, expires_at, revoked_at
suspensions          id, realm_id, target_type（user / org / service_account / membership）, target_id
                     category（tos_violation / customer_request / security_risk / billing …）
                     reason（内部向け）, external_ref, starts_at, ends_at（NULL=無期限）
                     created_by, created_at, lifted_at, lifted_by
clients              id, realm_id, name, trust_level（first_party / third_party。当面は first_party のみ）, redirect_uris
                     auth_method（private_key_jwt / client_secret / none）, id_token_signed_response_alg（ML-DSA-65 / ES256）, created_at

user_attributes      user_id, key, value, PK (user_id, key)（11.7 の汎用形。アダプタが別の持ち方を選んでもよい）

scheduled_events     id, fire_at, event_type, payload, fired_at（4.8）
installed_features   feature, state（enabling / active / disabling）, data_version, updated_at（11.12）
```

`revoked_*` は `revoked_at, revoked_by, revoke_reason`。

### 3.2 認可側 (authz)

```
groups         id, realm_id, org_id（NULL=realm 全体）, name, UNIQUE (realm_id, org_id, name)（org_id が NULL の場合も一意になるよう、アダプタが DB に応じて実現する）
group_members  group_id, member_type（user / service_account / group）, member_id, PK (group_id, member_type, member_id)
roles          id, realm_id, org_id（NULL=realm 共通）, name
role_permissions  role_id, permission（"project:read" など）
role_bindings  role_id, principal_type, principal_id
               org_id（NULL=realm 全体）, resource_type, resource_id（NULL=Org 全体）
```

Group に入れるのは、その Org の active な Membership を持つユーザーか、その Org のサービスアカウントのみ（authz は authn の公開 API で確認する）。

## 4. 主要フロー

### 4.1 登録とログイン

ログインの識別子はメールアドレス、passkey、OAuth / SSO の外部 ID。**ユーザー名は持たない**（ADR 0037）。

| 要素 | 外部への送信 | 位置づけ |
|---|---|---|
| passkey | 不要 | 1要素目・2要素目。最も推奨 |
| TOTP | 不要 | 2要素目 |
| OAuth / SSO | 不要 | 識別は `(connection, provider_subject)` |
| メールのコード・マジックリンク | 必要（Notifier） | 所有確認、パスワードなしのログイン、復旧 |
| メール + パスワード | 不要 | フィーチャー（`password`） |
| SMS | ― | 対応しない |

- 2段階認証は passkey / TOTP。要否は設定（2.8）。1要素目がメールなら、メールのコードは2要素目にしない（設定で外せない。13.5）

#### メールアドレスは1つ以上必須

- 全ユーザーが確認済みのメールを1つ以上持つ。アカウントは所有確認の完了時に作る（それまでの登録内容はフローの期限内（既定10分）だけ保持）
- 最後の確認済みメールは削除できない。最小化モード（9.6）でも満たす。サービスアカウントは対象外
- 「確認済み」とみなす経路を realm で選ぶ。メールを送れない環境では `code` を無効にして OAuth と運営者による登録で運用する（この場合メールによる復旧は使えず、起動時と設定変更時に警告）

| 経路 | 送信 | 既定 |
|---|---|---|
| `code`（確認コード・リンク） | 必要 | 有効 |
| `oauth_provider`（プロバイダが確認済み） | 不要 | 有効 |
| `sso`（Org 専用 SSO の IdP） | 不要 | 有効 |
| `invitation`（招待リンクの受け入れ） | 不要 | 無効 |
| `admin`（運営者が登録） | 不要 | 有効 |

Org のポリシーで受け入れる経路を絞れる。

#### パスワード

| 設定 | 既定 |
|---|---|
| 最低長 | 15文字（2段階認証が必須なら 8文字）。文字種の組み合わせは強制しない |
| 漏洩済みパスワード | 登録・変更時に拒否、ログイン時に警告（k-匿名 API。使わない設定も可） |
| 2段階認証 | 任意（Org で必須にできる） |
| リカバリーコード | 発行する |

argon2id。パスワードのみのログインには警告 `single_factor`。レートリミットはアカウント単位と IP 単位。

#### メールのコード・リンクの安全策

- **要求したフローに結び付ける**：要求した側だけが持つフロー ID と組み合わせたときだけ有効。フロー ID は要求側の Cookie（API ならレスポンス）にだけ渡し、通知には含めない。別端末での確認は、realm で許す場合のみ元の端末で承認する方式
- 有効期限 10分（既定）、1回限り、試行回数に上限。IAM にはハッシュだけを持つ

### 4.2 認証手段の追加と連携

- 連携はログイン済みの状態からのみ。**未ログインでメールが一致しても自動リンクしない**
- 1つのメールアドレスは1ユーザーにだけ紐付く
- メールの追加時は所有確認が必須。未確認のメールではログインできない

### 4.3 認証手段の削除

最後の認証手段と、最後の確認済みメールは削除できない。primary を消す前に別のメールを primary にする。

### 4.4 Org の決定と切り替え

Org フィーチャー（11.13）がオンのときだけ行う。

1. ユーザーを認証する
2. 候補：active な Membership を持ち、ログインポリシーを満たし、警告が `deny` にならない Org
3. 選ぶ順：明示的な指定（画面での選択、連携先の `org` パラメータ）→ ログインの手がかりに結び付いた Org（複数あればその中の前回の Org、無ければ選択させる）→ 前回の Org → 個人 Org
   - 候補が空の場合（個人 Org の利用を禁止された Org 管理ユーザーで、入れる Org が無いなど）はログインを拒否する（`no_available_org`。本人確認後なので理由を返す）
4. `sessions.active_org_id` を更新する（切り替え時はセッション ID を入れ替える。必要なら step-up 認証）

| 手がかり | 結び付け |
|---|---|
| メールアドレス | Membership に結び付けたメール |
| OAuth / SSO | プロバイダが返したメールが結び付けたメールと一致（その場で HMAC を計算）。Org 専用 SSO ならその Org |
| passkey | `passkeys.preferred_org_id` |
| IP | Org の `ip_allowlist`（将来） |

手がかりは優先度にすぎず、入れるかはポリシーで決まる。

#### Membership に結び付けるメールアドレス

- Membership ごとに、その Org で使う確認済みのメールを1つ結び付けられる（未設定なら primary）。1つのメールを複数の Org に結び付けてもよい
- 招待では招待したアドレスが結び付く（受け入れに所有確認が必要）。本人も切り替えられる。Org のポリシーで所有ドメインに限定・切り替え禁止にできる
- **Org とその文脈の連携先に見えるのは結び付けたメールだけ**（ID トークンの `email`、通知の宛先）
- 結び付いたメールを消すには結び付け直しが必要。できなければ `email_bound_to_membership` で拒否

### 4.5 認可の判定

```
check(principal, action, resource, context) -> allow / deny
  resource: (type, id)。Org 全体なら (org, org_id) / context: active_org_id、IP、時刻
```

- 直接のロール + 所属 Group（ネスト有効時は祖先も）のロールのうち、範囲（Org 全体 / リソース / Org 階層有効時は親 Org）が合うものを合算する
- Org オフなら realm 全体の RBAC。実装は有効なフィーチャーに応じて起動時に組み立てる
- 将来 OpenFGA / Cedar 等に同じシグネチャで差し替えられる

### 4.6 認証情報の無効化

| 対象 | 個別 | 一括 |
|---|---|---|
| セッション | 指定を失効 | 全部 / 指定以外 |
| リフレッシュトークン | ファミリー単位 | ユーザー・クライアント単位 |
| passkey / 外部 ID 連携 | 指定 | 全部 |
| パスワード | 無効化し再設定を必須に | ― |
| サービスアカウントの認証情報 | 指定 | 全部 |

- 侵害時の初動用に「全認証情報と全セッションを一括で無効化」も用意する
- 削除ではなく無効化（`revoked_*` を記録）。取り消し不可。passkey は credential_id の再登録も拒否する
- その認証情報で認証したセッションも失効させ、Back-Channel Logout で通知する
- 本人は最後の1つを無効化できない。管理者はできる（以後は復旧手順で戻る）。Org 管理者は管理ユーザーとサービスアカウントのみ

### 4.7 停止

ユーザー・Org・サービスアカウント・Membership を、無期限または期間指定で止める。

- `starts_at`（省略で即時、未来なら予約）、`ends_at`（省略で無期限）。複数を重ねられ、1つでも有効なら停止中
- 停止中かは**判定時に時刻から計算**する（スケジューラ不要）。セッション検証でも判定する（5.3）

| 種別 | 解除できる人 | 本人への表示 |
|---|---|---|
| `tos_violation` | 運営者 | 規約違反による停止と問い合わせ先 |
| `customer_request` | Org の管理者と運営者 | 管理者による停止 |
| `security_risk` | セキュリティ担当（自動停止は期限付き） | 一時停止と復旧手順。**根拠は見せない** |
| `billing` | 課金システム（`external_ref` で冪等）と運営者 | 契約・支払いの確認 |

- 種別は realm で追加できる。別種別が重なれば全部解除されるまで止まる。本人にはコードだけを返し `reason` は見せない。監査ログ・SIEM には種別と `reason` の両方を出す
- 影響
  - ユーザー：ログイン不可。既存のセッション・リフレッシュトークンも無効。Back-Channel Logout で通知
  - Org：メンバーが入れない。その Org を active にしているセッションは、個人 Org に切り替えるまで Org の操作ができない。その Org のサービスアカウントも無効。管理ユーザーも止めるかは停止時に選ぶ（既定は止める）
  - サービスアカウント：認証不可。発行済みのトークンも無効
  - Membership：その Org にだけ入れない
- 停止できる人：運営者はすべて。Org の管理者はその Org の Membership・管理ユーザー・サービスアカウント
- 個人 Org は個別に停止できない。本人は自分の停止を解除できない

### 4.8 有効期間

ユーザー・Membership・サービスアカウント・Org に `valid_from`（省略時は作成時から）/ `valid_until`（省略時は無期限）を持たせる（入社日から、契約終了日まで、など）。

- 使えるのは「有効期間内」かつ「停止中でない」とき。判定は停止と同じく時刻から計算する
- 停止との違い：有効期間は本来使える期間で対象ごとに1つ。停止は措置で重ねられる
- 時刻の境界でのイベント（有効化、期限切れ、停止の開始、Quota の付与の開始・終了など）は `scheduled_events` に予約し、outbox 経由で出す。**アクセスの可否はこの処理の遅れに左右されない**

### 4.9 Org の制約と拒否理由

| 段階 | 問い | 制約 | 判定のタイミング |
|---|---|---|---|
| 所属の前提条件 | この人をこの期間所属させてよいか | Quota（11.14）、ドメイン（11.3）、管理ユーザーの制約、有効期間 | Membership の作成・変更時 |
| 入場の条件 | 今この方法で入ってよいか | ログインポリシー、停止、警告 | ログイン・切り替え時 |

どちらの前にも、操作する人の権限判定（例：`org:invite`）がある。

| 拒否理由コード | 意味 |
|---|---|
| `suspended.<category>` | 停止中 |
| `outside_validity` | 有効期間外 |
| `quota_exceeded` | 上限超過（不足する期間と人数を添える） |
| `policy.<type>` | ログインポリシーを満たさない |
| `warning_denied.<code>` | 警告が deny |
| `permission_denied` | 権限なし |
| `no_available_org` | 入れる Org が無い（4.4） |
| `last_owner` / `managed_user` / `email_bound_to_membership` / `leave_blocked_by_hook` | 4.10、4.4 |

複数該当すればすべて返す。コードは公開の契約（11.10）。

#### 開示のルール（ADR 0022）

| 段階 | 返すもの |
|---|---|
| 本人確認の前 | `authentication_failed` のみ。存在しない・違う・停止中などで**応答も応答時間も変えない** |
| 本人確認の後 | 本人に拒否理由のコード |
| 管理 API | 権限の範囲で詳細 |

招待・Membership の操作は、認証済みで権限のある呼び出しなので理由（`quota_exceeded` など）をそのまま返す。マジックリンクの要求は常に「送信しました」。登録済みアドレスでの新規登録は画面で区別せず `account_exists` 通知を出す。事情（停止など）は通知で伝える。

### 4.10 退会と削除

#### Org からの退会

| ユーザー | 本人による退会 |
|---|---|
| 個人ユーザー（共有 Org から） | **常に許可**（Org は恒久的には止められない） |
| Org 管理ユーザー（所有元から） | 不可 |
| Org 管理ユーザー（ゲスト参加先から） | 許可（所有元が制限できる） |
| 個人 Org | 不可 |

- Org には常に1人以上の `owner`。最後のオーナーは譲るか Org を削除するまで抜けられない
- ホスト側の事情による一時的な保留はフック `pre_membership_end` で行う
- 退会は `valid_until` の設定（予約可）と `ended_reason` の記録で表す。その Org の Group 所属とロール付与を外し、active にしているセッションは個人 Org に切り替える。Quota の枠は退会の時刻から空く。再参加は新しい招待で
- Org の管理者による除名も同じ処理で、`ended_reason = removed`

#### アカウントの削除

- 本人による削除は個人ユーザーのみ。共有 Org の最後のオーナーの間は不可
- 猶予期間（既定30日）の間はログイン不可、本人確認で取り消せる
- 猶予後：Membership 終了、個人 Org 削除、認証情報・セッション削除、**データ鍵の削除（crypto-shredding）**、メールのインデックス削除（再登録可能に）、ID は墓標として残す、`user.deleted` と Back-Channel Logout
- 運営者は `legal_hold` で消去を保留できる
- 運営者による削除も同じ流れで、猶予期間の有無は運営者が選ぶ

#### Org の削除

オーナーか運営者が行う（猶予期間あり）。全 Membership を `org_deleted` で終了し、サービスアカウント・Group・ロール・Quota・ポリシーを削除する。管理ユーザーは削除するか個人ユーザーとして解放するかを選ぶ（既定は削除）。

### 4.11 管理権限

管理権限も authz のロールで表す（専用の判定は作らない）。

| realm の運営者ロール | できること |
|---|---|
| `realm:owner` | すべて。運営者ロールの付与 |
| `realm:admin` | ユーザー・Org の管理、`tos_violation` の停止・解除 |
| `realm:security` | `security_risk` の停止・解除、無効化、監査ログ閲覧 |
| `realm:support` | 状態の閲覧、復旧手続き（個人情報の復号は不可） |
| `realm:billing` | Quota の付与、`billing` の停止・解除（課金連携用のサービスアカウント向け） |

- 運営者ロールは `org_id` が NULL のロール付与で表し、ホスト先が独自のロールを追加できる。停止の種別ごとの解除権限は、これらのロールの permission として定義する
- Org のロール：`org_role` を Org 範囲の既定ロールに対応させる。`owner`（削除・譲渡・全設定）、`admin`（招待・除名・Group とロール、`customer_request` の停止）、`member`
- 個人情報の復号は独立した権限 `pii:read`
- 管理操作には強い認証と直近の認証（`max_auth_age`）を求める。管理者のセッションは短くする
- 緊急時は Storage と KeyStore に直接触れる CLI を使う（実行は重要イベントとして全運営者に通知）。常設の緊急用アカウントは作らない
- Org を作れる人：`anyone`（既定）/ `operators_only` / `invite_only`

### 4.12 アカウント復旧

| 経路 | 対象 |
|---|---|
| リカバリーコード（最初の強い認証手段の登録時に10個発行、表示は1回、argon2id） | 全員 |
| 確認済みメール | 個人ユーザー |
| Org 管理者が発行する復旧リンク | Org 管理ユーザー |
| 運営者が IAM の外で本人確認して発行する復旧リンク | 上記で戻れない人 |

- realm で有効な経路を選び、Org は弱い経路を禁止できる
- メールによる復旧には待機期間（既定なし、Org で設定。期間中は本人が取り消せる）・全連絡先への通知・警告 `recovered_via_email` を組み合わせる
- `security_risk` で停止されたユーザーは、この流れで認証手段を入れ替えた後、セキュリティ担当が停止を解除する
- 本人確認後は**新しい認証手段の登録しかできない復旧専用のセッション**を出す。登録後は全セッションを失効、古い手段の無効化を勧め、新しいリカバリーコードを出す
- 復旧の要求への応答も開示のルール（4.9）に従う

### 4.13 管理 API（概要）

```
POST   /v1/admin/users/{id}/sessions:revoke
POST   /v1/admin/users/{id}/credentials/{cred_id}:revoke | credentials:revoke-all
POST   /v1/admin/service-accounts/{id}/credentials/{cred_id}:revoke
POST   /v1/admin/{users|orgs|service-accounts|memberships}/{id}/suspensions   {category, reason, starts_at, ends_at}
GET    /v1/admin/{users|orgs|service-accounts|memberships}/{id}/suspensions
POST   /v1/admin/suspensions/{id}:lift
PATCH  /v1/admin/{users|orgs|service-accounts|memberships}/{id}               {valid_from, valid_until}
GET    /v1/admin/orgs/{id}/quotas
POST   /v1/admin/orgs/{id}/quota-grants | PUT …/quota-grants/external/{ref} | DELETE …/quota-grants/{grant_id}
POST   /v1/admin/notifications/{id}:claim
POST   /v1/me/sessions/{id}:revoke | /v1/me/credentials/{id}:revoke
```

管理操作は理由の入力を必須にし、すべて監査ログに出す。

## 5. トークンとセッション

### 5.1 トークン

- ブラウザ：サーバーサイドセッション（Cookie）
- 連携先：**ID トークンは JWT**（9.3）。**アクセストークンは不透明**で、イントロスペクション（RFC 7662）で確認する（ADR 0021）。リソースサーバーは結果を 5.3 の上限以内でキャッシュしてよい
- ID トークンのクレーム：`sub`、`org_id`（Org オンのみ）、`amr`、`sid`、`email`（4.4）。Group / Role は載せない
- リフレッシュトークンはローテーションし、再利用を検知したらファミリーごと失効

### 5.2 セッション ID

| 値 | 形 | 用途 |
|---|---|---|
| セッション ID（公開） | `ses_…` | 一覧・失効の指定、ログの相関、`sid` |
| トークン（秘密） | `<ID>.<256bit 乱数（crypto/rand）>` | Cookie / Bearer。DB には秘密部分の SHA-256 のみ。定数時間で照合 |

- ログには公開 ID だけを出す。秘密部分はどこにも出さない
- Cookie：`__Host-`、`Secure`、`HttpOnly`、`SameSite=Lax`、`Path=/`、`Domain` なし。別ドメインのアプリには Bearer
- ID の入れ替え：ログイン成功時、step-up 時、Org 切り替え時、一定時間ごと
- 失効の契機：ログアウト、本人・管理者による失効、パスワード・認証手段の変更時（他のセッションを一括失効）
- 失効は Storage に書いてからキャッシュを消す。Back-Channel Logout で `sid` を通知（M5 以降）
- 将来：端末に結び付けたセッション（Device Bound Session Credentials など）

### 5.3 セッション検証とキャッシュ

セッション（とアクセストークン）の検証では、セッションの失効・期限、主体の停止・有効期間、認証に使った認証情報の無効化、active な Org と Membership の状態をすべて確認する。

- 結果を「セッションの有効性」として EphemeralStore にキャッシュする。変更時に即削除（ベストエフォート）し、**TTL を必ず付ける**
- **保証値：変更が検証に反映されるまでの遅れは最大 N 秒**（既定30秒、ホスト先が設定）
- 次に状態が変わる時刻もキャッシュに持たせ、過ぎたら再検証する

### 5.4 セッションの寿命

| 項目 | 既定 |
|---|---|
| `absolute_lifetime` | 30日 |
| `idle_timeout` | 7日 |
| `remember_me_lifetime` | 90日（無効化可） |
| `max_auth_age` | 15分 |
| `refresh_token_lifetime` | 30日 |
| `access_token_lifetime` | 15分 |

- 2.8 の階層で設定する。管理者とサービスアカウントは短い既定値
- 切り替え先の Org の寿命を超えていれば再認証を求める。設定の変更は既存セッションにも 5.3 の上限内で反映する

### 5.5 連携先

- 当面はホスト先が管理 API で登録したファーストパーティのみ。同意画面なし、動的クライアント登録なし
- 将来のサードパーティ開放に備え `clients.trust_level` を持つ

## 6. 監査ログとイベント出力

### 6.1 記録するもの

ログイン成否（失敗理由の種別を含む）、セッションの発行・入れ替え・失効、認証手段の追加・削除・無効化、警告、メールの確認、Org の切り替え、Membership・Group・Role の変更、停止・有効期間、管理操作、フィーチャーの変更、鍵のローテーション、レートリミットの発動、リフレッシュトークンの再利用。

### 6.2 形式

イベント ID、時刻、種類、結果、主体、realm、Org、公開セッション ID、IP、User-Agent、リクエスト ID、詳細。バージョン付きの契約（11.10）。

### 6.3 外部出力

- EventSink で出す（標準出力 JSON Lines / syslog RFC 5424 / OTLP / Webhook）。独自 JSON か OCSF を選べる
- outbox 経由（少なくとも1回。イベント ID で重複排除）
- 個人情報の出し方を出力先ごとに選ぶ：そのまま / 仮名化（既定）/ 出さない
- Storage の監査ログはハッシュチェーンにする

### 6.4 アプリケーションログ

監査ログとは別に出す。個人情報と秘密は出さず、相関にはリクエスト ID と公開セッション ID を使う。

### 6.5 保持期間

- 監査ログはホスト先の保持期間（既定90日）を過ぎたら削除する。長期保管は SIEM に任せる
- チェーンは先頭から切り詰め、最後に消したハッシュをチェックポイントとして残し SIEM にも送る
- その他のデータの保持期間は 9.6

## 7. ロードマップ

[roadmap.md](roadmap.md) を参照。

## 8. 未決事項

- 後回し：ログ・メトリクス基盤

## 9. 暗号

### 9.1 原則

- 自前の鍵で RSA を使わない。現行の最低ラインは ECC
- ECC も量子計算機で破られるため、耐量子性は ML-KEM / ML-DSA で確保する
- 鍵とアルゴリズムは `kid` で管理し、コード変更なしで切り替えられる

### 9.2 用途別

| 用途 | 方式 |
|---|---|
| TLS | 1.3 のみ。鍵交換 X25519MLKEM768、証明書 ECDSA P-256 |
| トークン署名 | ML-DSA-65 と ES256（9.3） |
| 保存データ | AES-256-GCM のエンベロープ暗号化 |
| 検索用インデックス | HMAC-SHA-256 |
| パスワード・リカバリーコード | argon2id |
| 不透明トークン類、メールのコード・マジックリンク | 256bit 乱数（コードは短い乱数）。DB には SHA-256 などのハッシュのみ |

### 9.3 トークン署名

- JWKS に ML-DSA-65（`kty: AKP`、RFC 9964）と ES256 を公開し、クライアントごとに選ぶ（`id_token_signed_response_alg`）。主要な RP が対応したら ES256 を廃止する
- 実装：zitadel/oidc の go-jose に `OpaqueSigner` で `crypto/mldsa` を差し込む。JWKS の AKP 出力は jwx で組み立てる（ADR 0038）
- RS256 を出さないため、OIDC Discovery には厳密には適合しない（既知の差異）

### 9.4 外部の RSA

- OAuth プロバイダの ID トークン：トークンエンドポイントから TLS で直接受け取り、署名検証は TLS で代替する（OIDC Core 3.1.3.7）
- passkey：ES256 / EdDSA / RS256 を受け入れる（優先順もこの順）。RS256 は警告 `passkey_alg_rsa`。拒否は警告のアクション設定で行う。RS256 は ES256 / EdDSA の後から追加してもよい。ML-DSA の passkey は将来の候補

### 9.5 個人情報の暗号化

常に有効（フィーチャーにしない）。

| データ | 扱い |
|---|---|
| メールアドレス | 暗号化 + ブラインドインデックス（最小化モードではインデックスのみ） |
| 表示名（持つ場合）、TOTP シークレット | 暗号化 |
| IP アドレス | 暗号化。保持期間後は切り詰め |
| カスタム属性 | 定義ごとに指定 |
| `provider_subject` | 暗号化しない |

- 個人情報は**ユーザーごとのデータ鍵**で暗号化し、鍵を KeyStore のマスター鍵で包む。削除時は鍵を消す（crypto-shredding）
- 監査ログの IP と User-Agent は、切り詰めた値を平文で、全文を本人のデータ鍵と realm・日ごとの鍵で二重に暗号化して残す。保持期間の後は日ごとの鍵を消す（ADR 0063）
- ブラインドインデックスは暗号化と別の鍵。メールは小文字化のみで正規化。ドメイン部分にも別のインデックス
- 鍵のローテーションは `key_id` で管理する（インデックスの鍵は全件再計算、その間は新旧両方で検索）
- 部分一致検索はできない。調査は復号できる CLI で行う。鍵を失うと復元できないため、バックアップ手順を運用文書に含める

### 9.6 個人情報の最小化

- 既定で持たない：表示名・プロフィール（ホスト先が持つ）、`email_at_link`、OAuth の名前や写真
- メールの保持モード（realm で選ぶ）

| モード | 保存 | できないこと |
|---|---|---|
| `encrypted`（既定） | 暗号文 + インデックス | ― |
| `index_only` | インデックス（+ 任意で伏せ字） | 操作起点でない通知の宛先解決（外部が user_id から解決する）、アドレスの表示 |

| データ | 保持期間（既定） | 期間後 |
|---|---|---|
| 監査ログ | 90日 | 削除（6.5） |
| IP アドレス | 30日 | IPv4 /24、IPv6 /48 に切り詰め |
| User-Agent | 30日 | ブラウザと OS の大分類のみ |
| 失効・期限切れセッション | 7日 | 削除 |
| 配送済みの outbox・予約イベント | 7日 | 削除 |
| 無効化した認証情報 | 監査ログと同じ | 削除（passkey の拒否リストは残す） |

## 10. 認証の警告

全認証経路で共通の仕組みで警告を出す（ADR 0007）。

```
認証経路 ──Evidence──▶ 警告評価器（経路を知らないルール群）──▶ []Warning ──▶ アクション判定（ignore / warn / deny）
```

- 評価器は `Warning{code, severity, params}` の一覧を返す。ルールは経路を知らず、Evidence の項目だけを見る
- Evidence：`amr`、要素数、IP、User-Agent、TLS の鍵交換方式、passkey の `alg`、OAuth のメール確認状況など
- アクションは 2.8 の階層で決める。Org で `deny` ならログインは成功し、その Org に入れないだけ
- 評価のタイミング：ログイン（`sessions.warnings` に保存）、認証手段の登録・一覧表示、step-up、Org 切り替え
- 届け先：本人（コードで返しクライアントで多言語化）、監査ログ、RP（既定ではトークンに載せず、API で取得）

| コード | 内容 | 既定 |
|---|---|---|
| `passkey_alg_rsa` | RS256 の passkey | warn |
| `tls_no_pq_kex` | 耐量子でない TLS 鍵交換（Go が TLS を終端する場合のみ判定） | warn |
| `single_factor` | 1要素での認証 | ignore（MFA が普及したら warn を検討） |
| `oauth_email_unverified` | プロバイダ側でメール未確認 | warn |
| `password_breached` | 漏洩済みパスワード | warn |
| `recovered_via_email` | メールによる復旧の直後 | warn |
| `new_device` | 初めての端末・IP | ignore（将来 warn） |

## 11. フィーチャー

### 11.0 一覧

| フィーチャー | 既定 | 依存 | オフのとき |
|---|---|---|---|
| Org（11.13） | オン | ― | Org の概念を使わない。認可は realm 範囲 |
| 認証の警告（10章） | オン | ― | 評価器を通さない |
| リソース単位の権限（11.5） | オン | ― | Org・realm 単位の RBAC のみ |
| パスワード（4.1） | オフ | ― | パスワードでの登録・ログインなし |
| Quota（11.14） | オフ | Org | 数えない・判定しない（無制限） |
| Org のログインポリシー（4.4） | オフ | Org | ポリシーの判定をしない |
| 複数 realm（11.1） | オフ | ― | realm は1つ固定。解決処理をしない |
| サービスアカウント（11.2） | オフ | ― | 機械向け認証なし（配信用は別。2.4） |
| Org 管理ユーザー・Org 専用 SSO（11.3） | オフ | Org | `owner_org_id` は常に NULL。ドメイン証明なし |
| Org 階層（11.4） | オフ | Org | 親をたどらない |
| Group のネスト（11.5） | オフ | ― | 展開は1段 |
| アカウント統合（11.6） | オフ | ― | 統合 API なし |
| カスタム属性（11.7） | オフ | ― | 属性の読み書きなし |
| フロー フック（11.8） | オフ | ― | フックを一切呼ばない |

### 11.1 複数 realm

互いに独立したユーザー集合を1インスタンスで持つ。realm はホスト名かパス（`/realms/{slug}/…`）で決める。

### 11.2 サービスアカウント

Org に属する機械の主体。ロール付与・Group 所属はユーザーと同じ principal として扱う。認証は client credentials（`client_secret` / `private_key_jwt`。鍵は ES256 / EdDSA / ML-DSA）と API キー。

### 11.3 Org 管理ユーザーと Org 専用 SSO

- 個人ユーザーは本人が所有し、Org は所属から外すことしかできない。Org 管理ユーザーは Org が所有し、停止・削除・ログイン方法の強制ができる
- Org は DNS の TXT 等でドメインの所有を証明する（`org_domains`）。証明済みドメインで登録した人を管理ユーザーにできる。既存の個人ユーザーの切り替えには本人の同意が要る
- Org 専用 SSO は `connections.owner_org_id` で表す

### 11.4 Org 階層

親 Org のロールを子に効かせる。祖先一覧は書き込み時に計算する（持ち方はアダプタが決める）。深さに上限。

### 11.5 認可の粒度

- `role_bindings` の `resource_type / resource_id` でリソース単位のロールにする
- Group のネストは推移閉包を書き込み時に計算する。深さの上限と循環の禁止
- 判定結果は短期キャッシュし、関係する変更で無効化する

### 11.6 アカウント統合

A にログインした状態で B の所有を証明すると、B のメール・外部 ID・passkey・Membership・ロール・個人 Org のデータを A に移す（Org 管理ユーザーが絡む場合はその Org の許可が必要）。B は `status = merged`、`merged_into = A` になり、セッションとトークンを失効する。`sub` が変わるため `user.merged` イベントを出す。取り消し不可。

### 11.7 カスタム属性

realm ごとに型・検証・本人による編集可否・トークンへの掲載・暗号化の有無を定義する。保存方法はアダプタが決める。

### 11.8 フロー フック

| フック | タイミング |
|---|---|
| `pre_registration` | ユーザー作成の直前（許可リスト、招待制、bot 対策の判定。要否は 2.8） |
| `post_authentication` | 認証後・セッション作成前（10章の警告評価もここで動く） |
| `pre_membership_end` | 退会の直前（一時的な保留のみ） |
| `pre_token` | トークン発行の直前（クレーム追加） |
| 非同期イベント | 各操作の後（EventSink 経由で外部と同期） |

Go インターフェースか Webhook で実装する。タイムアウト必須、失敗時の fail-closed / fail-open はフックごとに設定する。ホットパスには置かない。

### 11.9 （2.8 に統合）

### 11.10 公開する契約

公開 API、Webhook のペイロード（Notifier・フック・イベント）、トークンのクレーム、Go ライブラリのポートにバージョンを付ける。

### 11.11 ビルド時の選択

```yaml
# build.yaml
features: [resource_scoped_authz, warnings]
adapters: { storage: [postgres], ephemeral: [redis], notifier: [webhook], keystore: [file] }
```

- フィーチャーとアダプタは自己登録するパッケージ。`iam build` が選んだものだけを import してビルドする（build tag は使わない）
- 公式イメージは「全部入り」と「最小構成」。依存関係はビルド時に検査する
- **扱えないデータが DB にあれば起動を拒否し、判定中に未知のデータに出会えば拒否する（fail-closed）**
- スキーマはフィーチャーの有無で変えない
- 効果は攻撃面・依存・サイズの削減（レイテンシは起動時の組み立てで既にゼロ）

### 11.12 構成変更の保証

- 追加：バイナリを全台に配ってから有効化。削除：無効化してデータを片付けてからバイナリを配る
- 台帳（`installed_features`）とバイナリに埋め込んだ構成を起動時に突き合わせる

| 台帳 | バイナリ | 起動 |
|---|---|---|
| 記録あり | 含まない | 拒否 |
| 記録なし | 含む | 起動（無効のまま） |
| active | データ形式が古い / 新しすぎる | 拒否 |

- 動くのは「含まれる」「設定で有効」「台帳で active」が揃ったときだけ
- バイナリは自分の構成を埋め込む（`iam version --manifest`）
- 状態は CLI（または管理 API）で明示的に進める：enable → enabling（冪等な準備処理）→ active → disable → disabling（書き込み停止、データ 0 件で完了）
- `iam features plan --build build.yaml` で事前に差分と影響を表示する
- 本体の更新と構成の変更は別のデプロイで行うことを推奨する
- データ形式は前進のみで移行する。互換性の保証は「1つ前のバージョンのバイナリが同じデータで動く」こと

### 11.13 Org と個人 Org

- オフ：Org の決定をせず、トークンに `org_id` を含めず、認可は realm 範囲
- オン：ユーザー作成と同じトランザクションで個人 Org（`kind = personal`）と Membership を作る
- 個人 Org はメンバーが本人のみ、招待不可、ユーザーと一緒に削除。Org 管理ユーザーにも作る（ポリシーで利用を禁止できる）
- 後からオンにする場合は、準備処理で既存ユーザーに個人 Org を作る。既存の realm 範囲のロール付与・Group は realm 範囲のまま残る

### 11.14 Quota

上限は期間つきの付与の合算で求める（`quota_key`：まず `members`）。

| 種類 | 意味 |
|---|---|
| `base` | 基本の上限。同時に有効なのは1つ（新しい方が優先） |
| `addon` | 足し算 |
| `override` | 有効な間は base と addon を無視 |

```
時刻 t の上限 = override があればその値、なければ base + Σ addon。付与が無ければ無制限
```

- 外部の課金システムとは直接連携しない。ホスト先が管理 API で登録し、`external_ref` で冪等に上書きする。`source` で手動の付与を守る
- 数えるもの（realm で設定）：active（必ず）、招待中・将来有効・停止中（既定は数える）。個人 Org には適用しない
- **判定**：追加・招待・有効期間の変更・付与の削除や短縮のときに行い、足りなければエラーで拒否する（待機列は持たない）
  - 新しいメンバーの有効期間の**すべての時点**で「その時点の人数 + 1 ≤ 上限」を満たすこと（区切りの時刻だけを調べる）。期間が重ならない人同士は枠を共有できる
  - 件数の確認と追加は同じトランザクションで行う。エラーには不足する期間と人数を含める
  - 付与の削除・短縮で既存の予約が成り立たなくなる場合は、その操作を拒否する
- IAM が拒否できない経路で上限を下回った場合：既存メンバーは外さず、新規を止めて `org.quota.exceeded` を出す
- ホットパスでは判定しない

## 12. テスト

- **フィーチャーのテスト**：インメモリの参照実装に対して行う。CI の構成は全部入り・最小構成・最小構成 + 各フィーチャー1つ
- **DB のテスト**：Repository の契約テスト（公開パッケージ `storagetest`）を各アダプタに対して実 DB（コンテナ）で回す。各アダプタは別の Go モジュールで、CI は変更時と nightly。参照実装も同じ契約テストを通す
- 契約テストに必須：CRUD と検索、**一意性と並行性**（同時登録、リフレッシュトークンの同時使用、`sign_count`、Quota）、トランザクション、**realm の分離**（全メソッドで自動検査）、フィーチャーごとの契約
- そのほか：マイグレーション（1つ前から）、フィーチャーの有効化・無効化、アダプタごとのベンチマーク
- E2E：SQLite + インメモリ、PostgreSQL + Redis の2構成

## 13. セキュリティの保証

第三者のレビュー不足を、機械による検証・外部の基準・報告窓口で補う（ADR 0030）。

### 13.1 （13 章の冒頭に統合）

### 13.2 自前で書く範囲を減らす

- 暗号は Go 標準ライブラリのみ
- OIDC：zitadel/oidc（v3 で開始し v4 を追う）。自前で補うのは ML-DSA の署名と JWKS、Back-Channel Logout の送信
- JWT / JWK：lestrrat-go/jwx v4。WebAuthn：go-webauthn
- SAML は Org 専用 SSO の実装時に最も慎重に選ぶ
- セキュリティ上重要なコード（トークン、セッション、連携・統合、認可判定、fail-closed 判定）はディレクトリを分けて明示する

### 13.3 適合試験

OpenID Foundation の OIDC 適合試験と FIDO の WebAuthn 適合試験を回す。意図的な差異（RS256 なし）は明記する。

### 13.4 継続的な検査

govulncheck、OSV-Scanner、Dependabot / Renovate、staticcheck、gosec、CodeQL、ファジング（JWT、WebAuthn の応答、OAuth のパラメータ、SAML、設定ファイル）、OpenSSF Scorecard。

### 13.5 脅威モデルと不変条件

`docs/threat-model.md` を設計変更のたびに更新する。次の不変条件はそれぞれテストを持ち、テストを消す・弱める変更は CI で検出してレビュー必須にする。設定でも外せない。

- 未ログインでメールが一致しても自動リンクしない（4.2）
- 最後の認証手段・最後の確認済みメールは本人が削除できない（4.3）
- 全ユーザーが確認済みのメールを1つ以上持つ（4.1）
- メールのコード・リンクは要求したフローの外で通らない。1要素目がメールなら、メールのコードは2要素目にならない（4.1）
- 本人確認の前は、アカウントの有無や状態で応答・応答時間が変わらない（4.9）
- セッショントークンの秘密部分はログ・イベントに出ない（5.2）
- ログイン・権限変更時にセッション ID が入れ替わる（5.2）
- 無効化した認証情報・停止中・有効期間外の対象では認証できず、関連セッションも使えない（4.6〜4.8）
- 変更がセッション検証に反映される遅れは上限を超えない（5.3）
- 復旧専用のセッションでは認証手段の登録しかできない（4.12）
- 共有 Org には常にオーナーがいる。個人ユーザーの退会は恒久的には妨げられない（4.10）
- 削除したユーザーの個人情報はデータ鍵の削除後に復号できない（4.10）
- 別 realm のデータは返らない（12章）
- 内部 ID は Storage の外（API の応答、Cookie、トークン、通知、監査ログの外部出力）に出ない（ADR 0045）
- 扱えないフィーチャーのデータがあれば起動せず、判定は拒否に倒れる（11.11）
- Org の設定はホスト先が許した範囲を超えて緩められない（2.8）

### 13.6 AI が書いたコード

別のエージェントにセキュリティ観点だけでレビューさせる。重要なコードは CODEOWNERS で人のレビューを必須にする。仕様に関わる実装には RFC の節番号を残す。

### 13.7 報告窓口と監査

`SECURITY.md` と GitHub の非公開脆弱性報告。対応期限と公開方針（Advisory、CVE）を明記する。成熟したら第三者監査（OSTIF 等への申請も検討）。

### 13.8 配布物

署名（Sigstore / cosign）、SBOM、SLSA provenance。再現可能ビルドを目指す。

### 13.9 成熟度

第三者監査までは README で「実験段階」と明記する。v1.0 の条件は roadmap.md。
