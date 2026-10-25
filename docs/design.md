# IAM Design Doc

- Status: Draft
- Last updated: 2026-10-25

## 1. 目的

個人開発のサービス群で共通利用する認証・認可基盤を作る。

### 最低限の目標（MVP）

- 個人識別：1人のユーザーを一意に識別できる
- 1ユーザーに対して複数のメールアドレスを紐付けられる
- 1ユーザーに対して複数の OAuth プロバイダ（Google, GitHub など）を紐付けられる

### ゴール

- ユーザーと Group の多対多リレーション
- ログイン時に Org を決定・切り替えできる（passkey、IP など）
  - IP による Org 判定はエンタープライズ向け機能として将来実装。設計上は差し込めるようにしておく

### 非ゴール（当面やらない）

- SAML / OIDC による外部 IdP 連携（エンタープライズ SSO）
- SCIM によるプロビジョニング
- ReBAC（関係ベース認可）
- 管理画面 UI の作り込み

## 2. 基本方針

### 2.1 認証と認可の責務分離

| | 認証 (authn) | 認可 (authz) |
|---|---|---|
| 問い | 誰か？どの Org の文脈か？ | 何ができるか？ |
| 扱う概念 | User, 認証手段, Org, Membership(所属有無), Session | Group, Role, Permission |
| Org | テナント境界として扱う | Org を前提に判定 |
| Group | 扱わない | 扱う |

- **Org は認証側の概念**とする。Org はテナント境界であり、「どの Org としてログインしているか」はセッションの属性になる。
- **Group は認可側の概念**とする。認証は Group を知らない。
- Membership(user, org) は「所属しているか」という事実だけを認証側が持ち、その Membership に紐づく Group / Role は認可側が持つ。

### 2.2 リポジトリ構成：モノレポ + 境界の強制

個人開発なので**同一リポジトリ**で扱う。ただし将来の分離やガラパゴス化を防ぐため、以下を守る。

- `authn` と `authz` は別モジュール（別パッケージ）として実装する
- **authz は authn の内部実装に依存しない**。authz が受け取るのは `user_id` と `org_id`（と必要ならセッション情報）だけ
- authn → authz の呼び出しも公開インターフェース経由に限る
- DB はスキーマ（または名前空間 / テーブル接頭辞）で分け、モジュールをまたぐ JOIN をしない。参照は ID のみ
- 外部インターフェースは標準仕様に寄せる（後述）

これにより、必要になった時点でサービスとして切り出せる状態を保つ。

想定ディレクトリ（言語・FW 未定）:

```
iam/
├── docs/
├── authn/        # ユーザー、認証手段、Org、Membership、Session
├── authz/        # Group、Role、Permission、ポリシー評価
├── shared/       # ID 型、エラー型、監査ログなど最小限の共通部分
└── server/       # HTTP エンドポイント（authn/authz を組み立てるだけ）
```

### 2.3 標準仕様への準拠（ガラパゴス化対策）

- 外部サービスへの認証結果の受け渡しは **OIDC（OpenID Connect）** に準拠する。ID トークンのクレーム名も標準に従う
- passkey は **WebAuthn** 準拠
- 認可 API は当面独自でよいが、`check(subject, action, resource)` の形に寄せ、OpenFGA / Cedar 等へ載せ替えやすくしておく
- 暗号方式は「9. 暗号方針」に従う

### 2.4 技術スタック

| 領域 | 選定 | 備考 |
|---|---|---|
| 言語 | Go 1.27 以上 | 標準ライブラリの `crypto/mldsa` を使うため 1.27 以上 |
| DB | SQL 系（第一候補 PostgreSQL） | 差し替え可能にする（後述） |
| キャッシュ | Redis | 差し替え可能にする（後述） |

#### DB を差し替え可能にする方針

- 各モジュール（authn / authz）は自分の永続化を **Repository インターフェース**として定義し、ドメイン層は SQL を知らない
- 実装は `authn/store/postgres` のようにアダプタとして置く。別 DB に移るときはアダプタを追加する
- SQL はできるだけ標準 SQL に寄せ、方言依存（`RETURNING`、JSONB 演算子など）はアダプタ内に閉じ込める
- マイグレーションはアダプタごとに管理する
- テストは Repository インターフェースに対する共通テストスイートを用意し、全アダプタで同じテストを通す

#### Redis の役割

**Redis は正（source of truth）にしない。** 消えても再ログインや再試行で回復できるものだけを置く。

- セッションのキャッシュ（正は DB の `sessions`。失効は DB に書いてから Redis を消す）
- OAuth の `state` / PKCE `code_verifier`、WebAuthn の challenge（短命・TTL 付き）
- レートリミット、ログイン失敗回数のカウンタ
- 認可判定結果の短期キャッシュ（Membership / Group 変更時に無効化）

Redis もインターフェース越しに使い、テストや小規模運用ではインメモリ実装で代替できるようにする。

## 3. ドメインモデル

### 3.1 認証側 (authn)

```
users
  id (PK)
  display_name
  status            -- active / suspended / deleted
  created_at, updated_at

user_emails
  id (PK)
  user_id (FK users)
  email (UNIQUE, 正規化して保存)
  verified_at       -- NULL なら未検証
  is_primary
  created_at

user_identities     -- OAuth などの外部 ID
  id (PK)
  user_id (FK users)
  provider          -- google / github / ...
  provider_subject  -- プロバイダ側の不変 ID (sub)
  email_at_link     -- 連携時点のメール（参考情報。識別には使わない）
  created_at
  UNIQUE (provider, provider_subject)

passkeys
  id (PK)
  user_id (FK users)
  credential_id (UNIQUE)
  public_key
  alg               -- COSE アルゴリズム (ES256 / EdDSA / RS256)。RS256 は警告対象（9.4）
  sign_count
  transports
  name              -- ユーザーが付ける名前
  created_at, last_used_at

orgs
  id (PK)
  slug (UNIQUE)
  name
  created_at

memberships         -- User と Org の所属関係（所属の有無のみ）
  id (PK)
  user_id (FK users)
  org_id (FK orgs)
  status            -- invited / active / suspended
  created_at
  UNIQUE (user_id, org_id)

sessions
  id (PK)
  user_id (FK users)
  active_org_id (FK orgs, NULL 可)  -- 個人コンテキストなら NULL
  auth_methods      -- どの手段で認証したか (amr)
  ip, user_agent
  created_at, last_seen_at, expires_at, revoked_at

org_login_policies  -- 将来：Org への入り方の制約
  org_id (FK orgs)
  type              -- ip_allowlist / require_passkey / email_domain ...
  config (JSON)
```

### 3.2 認可側 (authz)

```
groups
  id (PK)
  org_id            -- 必ず Org に属する（Org をまたぐ Group は作らない）
  name
  UNIQUE (org_id, name)

group_members       -- User と Group の多対多
  group_id (FK groups)
  user_id           -- authn の users.id を ID として参照するだけ
  PRIMARY KEY (group_id, user_id)

roles
  id (PK)
  org_id (NULL ならシステム共通ロール)
  name

role_permissions
  role_id (FK roles)
  permission        -- "project:read" のような文字列

role_bindings       -- 誰にどのロールを与えるか
  role_id (FK roles)
  subject_type      -- user / group
  subject_id
  org_id
```

- `group_members.user_id` は authn の `users.id` を参照するが、DB の外部キーはモジュール境界をまたいで張らない（アプリ側で整合性を保つ）
- Group に所属できるのは、その Org の Membership が active なユーザーのみ（authz は authn の公開 API で確認する）

## 4. 主要フロー

### 4.1 サインアップ / ログイン

- 手段：メール（マジックリンク or パスワード）、OAuth、passkey
- OAuth のユーザー識別は `(provider, provider_subject)` で行う。メールアドレスでは識別しない

### 4.2 認証手段の追加・アカウント連携

- **連携はログイン済み状態からのみ**行う（「設定 → 認証手段を追加」）
- 未ログイン状態で OAuth のメールが既存ユーザーのメールと一致しても、**自動リンクはしない**（アカウント乗っ取り対策）
  - 既存アカウントにログインしてから連携するよう案内する
- メールアドレス追加時は検証必須。未検証メールではログインできない
- 1つのメールアドレスは1ユーザーにしか紐付かない

### 4.3 認証手段の削除

- 最後の1つの認証手段は削除できない（締め出し防止）
- primary メールを削除する場合は、先に別の検証済みメールを primary にする

### 4.4 Org の決定と切り替え

ログイン（ユーザー確定）と Org 選択は分ける。

1. ユーザーを認証する
2. 入れる Org の候補を求める：active な Membership を持つ Org のうち、`org_login_policies` を満たすもの
3. 候補が1つなら自動選択、複数なら選択させる（前回の Org を記憶しておく）
4. `sessions.active_org_id` を更新する

- Org の切り替え = セッションの `active_org_id` の変更。再ログインは不要（ただしポリシーで passkey が必要な Org なら step-up 認証を要求する）
- ポリシーの例
  - `require_passkey`：passkey で認証したセッションでないと入れない
  - `ip_allowlist`：指定 IP レンジからのみ入れる（エンタープライズ向け、将来）
  - `email_domain`：特定ドメインの検証済みメールを持つユーザーのみ（将来、自動参加にも利用）

### 4.5 認可の判定

```
check(user_id, org_id, permission) -> allow / deny
```

- `org_id` はセッションの `active_org_id` から取る
- user に直接付いたロール + 所属 Group に付いたロールを合算して判定する

## 5. トークン・セッション

- ブラウザ向け：サーバーサイドセッション（Cookie）。失効を即時反映できるようにする
- 他サービス向け：OIDC の ID トークン / アクセストークン（署名方式は 9.3）
  - クレームには `sub`（user_id）, `org_id`（active org）, `amr` を入れる
  - **Group / Role はトークンに載せない**（肥大化と反映遅延を避ける）。必要なら authz の API で引く
- リフレッシュトークンはローテーションし、再利用を検知したらそのファミリーごと失効させる
- ユーザーは自分のセッション一覧を見て個別に失効できる

## 6. 監査ログ

最初から記録する（後付けすると過去分が残らないため）。

- ログイン成功 / 失敗
- 認証手段の追加・削除
- メール検証
- Org 切り替え
- Membership / Group / Role の変更

## 7. マイルストーン

1. **M1 個人識別**：users, user_emails, user_identities, sessions。メールログイン + OAuth 1種
2. **M2 複数認証手段**：OAuth 複数対応、連携・解除、passkey
3. **M3 Org**：orgs, memberships, active_org の切り替え、招待
4. **M4 認可**：groups, roles, check API
5. **M5 OIDC Provider**：他サービスへの ID トークン発行
6. **M6 ポリシー**：require_passkey、ip_allowlist、email_domain
7. 以降：MFA 強制、SSO、SCIM

## 8. 未決事項

- HTTP フレームワーク（標準 `net/http` で足りるか）
- SQL 生成方式（sqlc / 素の `database/sql` など）とマイグレーションツール
- パスワード認証を提供するか（マジックリンク + OAuth + passkey だけで済ませる選択肢もある）
- 個人コンテキスト（Org に属さない状態）を許すか、全ユーザーに個人 Org を自動作成するか
- ID 形式（UUIDv7 / ULID など）

## 9. 暗号方針

### 9.1 原則

- **RSA は自前の鍵では一切使わない**
- 現行の署名・鍵交換は**楕円曲線暗号（ECC）を最低ライン**とする
- **耐量子暗号（PQC）に対応する**。ただし ECC も RSA と同じく量子計算機（Shor のアルゴリズム）で破られるため、**ECC だけでは耐量子にならない**。ECC は互換性のための現行ラインであり、耐量子性は ML-KEM / ML-DSA で確保する
- **暗号アジリティ**：アルゴリズムと鍵は ID（`kid`）付きで管理し、ローテーションや方式の切り替えをコード変更なしで行えるようにする

### 9.2 用途別の方式

| 用途 | 方式 | 耐量子性 |
|---|---|---|
| 通信 (TLS) | TLS 1.3 のみ。鍵交換は X25519MLKEM768 ハイブリッド、証明書は ECDSA P-256 | 鍵交換は耐量子（Go の既定）。証明書署名は ECC |
| トークン署名 (JWT / ID トークン) | ML-DSA-65 と ES256 を併用（9.3） | ML-DSA で耐量子 |
| 保存データの暗号化 | AES-256-GCM（エンベロープ暗号化。鍵は KMS 等で管理） | 256bit 共通鍵は耐量子とみなせる |
| パスワードハッシュ | argon2id | ハッシュ系は影響が小さい |
| 不透明トークン（セッション ID、リフレッシュトークン等） | 256bit 乱数。DB には SHA-256 のハッシュのみ保存 | 同上 |
| メール検証・マジックリンク等の署名 | HMAC-SHA-256 | 同上 |

- 「今のうちに暗号文を集めて将来解読する」攻撃（harvest now, decrypt later）が現実的に効くのは**機密性**。これは TLS のハイブリッド鍵交換と AES-256 で防ぐ
- **署名**は将来の偽造が問題になるので、量子計算機が実用化する前に ML-DSA へ移行できていればよい。そのための併用とアジリティ

### 9.3 トークン署名

- JWKS には **ML-DSA-65（`kty: AKP`、RFC 9964）と ES256 の鍵を両方公開**する
- クライアント（RP）ごとに署名アルゴリズムを選ぶ（OIDC の `id_token_signed_response_alg`）
  - ML-DSA に対応した RP には ML-DSA-65 で署名
  - 未対応の RP には ES256 で署名
- 将来、主要な RP が ML-DSA に対応したら ES256 を廃止する
- **トレードオフ**：OIDC Discovery は `id_token_signing_alg_values_supported` に RS256 を含めることを必須としている。RS256 を出さないため**厳密には仕様に適合しない**。RS256 しか扱えない RP とは連携できないことを受け入れる

### 9.4 外部が使う RSA の扱い

自前の鍵では RSA を使わないが、外部のシステムが RSA を使うケースがある。

- **OAuth プロバイダの ID トークン**（Google 等は RS256 で署名）
  - 認可コードフローで、トークンエンドポイントから TLS 経由で直接受け取る場合、ID トークンの署名検証の代わりに TLS のサーバー検証で代替できる（OIDC Core 3.1.3.7）。この方式を採り、RSA の検証処理を持たない
- **passkey（WebAuthn）**
  - 認証器側が鍵方式を決める。多くは ES256 / EdDSA だが、一部の Windows Hello などは RS256 しか使えない
  - **ES256 / EdDSA / RS256 を受け入れる**。ただし RS256 は「互換性のために許容している方式」として扱い、警告を出せるようにする
    - これは外部の公開鍵の検証であり、自前で RSA 鍵を持つわけではないので 9.1 の原則には反しない
  - 登録時の WebAuthn `pubKeyCredParams` の優先順は ES256 → EdDSA → RS256 とし、RSA は他に選択肢がない認証器でだけ選ばれるようにする
  - `passkeys.alg` に方式を保存し、RS256 の passkey に対して以下を行えるようにする
    - 登録時と passkey 一覧画面で警告を表示し、別の認証器の追加を促す
    - 監査ログに方式を記録する
  - 受け入れ可否はサーバー設定（`passkey.allow_rs256`、既定は true）で切り替えられるようにする
  - 将来、Org のログインポリシーに `disallow_rsa_passkey` を追加し、Org 単位で RS256 の passkey による入場を拒否できるようにする
  - 優先度は低い。M2 では ES256 / EdDSA のみで実装し、RS256 と警告は後から追加してもよい
