# ロードマップ

各フェーズに「ゴール（1文）」「含むもの」「完了条件（テストで確かめられる形）」「含まないもの」を置く。完了条件を満たすまで次のフェーズに進まない。節番号は [design.md](design.md) を指す。

| フェーズ | ゴール |
|---|---|
| M0 土台 | 機能ゼロの IAM が起動し、以降の全機能が載る枠組みと安全装置が動く |
| M1 個人識別 | 1人のユーザーが登録・ログインでき、セッションを安全に扱える（Org なし） |
| M2 認証手段 | 1人が複数のメール・OAuth・passkey などを持ち、失っても戻れる |
| M3 Org | 個人 Org と共有 Org を持ち、ログインの手がかりで入る Org が切り替わる |
| M4 認可 | Org（または realm）の中で、誰が何をできるかを判定できる |
| M5 OIDC Provider | ほかのアプリが標準の OIDC でログインを任せられる |
| M6 本番運用 | ホスト先が本番で運用・監視・移行・構成変更できる |
| M7 拡張 | 必要になったフィーチャーを順に足す |
| M8 認証の土台 | 認証方式をプラグインで足せ、ポリシーを方式の強さ（AAL）で書ける |
| M9 認証方式の拡張 | 社内のディレクトリ・SaaS・企業の端末で使われる認証方式がすべて選べる |
| M10 エンタープライズの運用 | 運用者が管理 API だけでユーザー・Org・セッション・監査ログを調べて操作でき、役割ごとにプロセスを分けられる |
| M11 OAuth / OIDC とプロビジョニングの拡張 | 標準の OAuth / OIDC の拡張と SCIM を、既定オフのフィーチャーとしてすべて選べる |
| M12 認可の拡張 | 認可の標準 API と ReBAC・ポリシーが揃う |
| v1.0 | 外部の基準と第三者の監査で安全性を確かめた状態 |

---

## M0 土台

**ゴール**：機能ゼロの IAM が起動し、以降の全機能が載る枠組みと安全装置が動く。

### 含むもの

- リポジトリ構成とモジュール境界（2.2）。境界違反（コアから `adapters/` の import など）を CI で検出する
- ポートの定義：Storage、EphemeralStore、Notifier、KeyStore、Clock、EventSink（2.4）
- アダプタ：インメモリの参照実装、SQLite、ファイルの KeyStore、標準出力の EventSink、開発用 Notifier
- 契約テストの枠組み（`storagetest`）。realm の分離と並行性の検査の雛形（12章）
- フィーチャーの登録、起動時の組み立て、台帳（`installed_features`）と起動時チェック（11.11、11.12）
- 設定ファイルの読み込みと、ホスト → realm の設定の階層の土台（2.8）
- 暗号の土台：エンベロープ暗号化、ブラインドインデックス、ユーザーごとのデータ鍵（9.5）
- 監査ログ（ハッシュチェーン）と outbox（6章、2.4）。外部出力では個人情報を出さない（仮名化は M6）
- 主要操作（セッション検証、認可判定に使うクエリ）のベンチマークと、レイテンシの基準値の決定
- OpenAPI と oapi-codegen の雛形、sqlc と goose の雛形
- CI：`go test`、govulncheck、staticcheck、gosec。`SECURITY.md`

### 前提の検証（スパイク）

結果は ADR に記録する。

- zitadel/oidc の go-jose に `OpaqueSigner` で ML-DSA-65 を差し込み、ID トークンを署名・検証できるか
- jwx で `AKP` 鍵を含む JWKS を出力し、ほかの実装で読めるか
- SQLite で「件数の確認と追加」を同じトランザクションで並行に行っても、上限を超えないか
- Clock の偽の時計と、TTL 付きキャッシュの組み合わせで時刻の境界をテストできるか

### 完了条件

- [ ] `iam serve` が SQLite + インメモリで起動し、ヘルスチェックに応答する
- [ ] 台帳にあるがバイナリに無いフィーチャーのデータがあると、起動を拒否するテストが通る
- [ ] 契約テストが参照実装と SQLite の両方で通る
- [ ] データ鍵を消すと、そのユーザーの暗号化データが復号できなくなるテストが通る
- [ ] 監査ログの1件を書き換えると、チェーンの検証で検出できるテストが通る
- [ ] スパイク4件の結果が ADR になっている
- [ ] ベンチマークの基準値が決まり、CI で計測されている

### 含まないもの

ログインなどの利用者向けの機能。

---

## M1 個人識別（Org なし）

**ゴール**：1人のユーザーが登録・ログインでき、セッションを安全に扱える。

### 含むもの

- `users`、`user_emails`、`user_identities`、`sessions`（3.1）
- メールは1つ以上必須。確認の経路は `code`、`oauth_provider`、`admin`（4.1）
- メールコード / マジックリンク（要求したフローへの結び付け）（4.1）
- OAuth 1種（Google か GitHub）。認可コード + PKCE、TLS で直接受け取る ID トークン（9.4）
- セッション：公開 ID と秘密トークンの分離、Cookie、ID の入れ替え、寿命（ホストの設定のみ）（5.2、5.4）
- セッションの有効性のキャッシュと反映遅れの上限（5.3）
- 本人によるセッション一覧と失効
- 開示のルール（`authentication_failed` への統一）（4.9）
- 警告の枠組みとルール1〜2個（10章）
- Notifier の Webhook と `:claim`。claim 用の最小限のサービスアカウント（権限は固定）
- レートリミット（インメモリ）
- 最初の運営者を作る CLI、最低限の管理 API
- 最低限のホスト型ログイン画面

### 完了条件

- [x] E2E：OAuth で登録 → ログアウト → メールコードで再ログイン
- [x] E2E：`code` を無効にした構成（メールを送れない環境）で、OAuth と運営者による登録だけで運用できる
- [x] 不変条件のテスト：自動リンクしない、フロー外でコードが通らない、本人確認前の応答と応答時間が同じ、秘密トークンがログに出ない、ログイン時に ID が入れ替わる、確認済みメールが常に1つ以上ある
- [x] セッションの失効が、設定した上限の時間内に検証へ反映される

### 含まないもの

Org、passkey、TOTP、パスワード、認可、OIDC Provider としての機能。

---

## M2 認証手段

**ゴール**：1人が複数のメール・OAuth・passkey などを持ち、失っても戻れる。

### 含むもの

- 複数メール、複数 OAuth、連携と解除（ログイン済みからのみ）（4.2、4.3）
- passkey：ES256 / EdDSA、RP ID の設定、Related Origin Requests（9.4、2.5）。RS256 と警告は後回しにしてもよい
- TOTP、メール + パスワード（フィーチャー）、2段階認証の設定（4.1）
- リカバリーコードとアカウント復旧（4.12）。Org 管理者による復旧は Org 管理ユーザー（M7）と一緒に
- 認証情報の無効化（4.6）。連携先への Back-Channel Logout は M5 から
- ユーザーの停止（種別つき）と有効期間、時刻境界のイベント（4.7、4.8）

### 完了条件

- [x] 最後の認証手段・最後の確認済みメールを本人が消せない
- [x] 無効化した passkey の再登録が拒否される
- [x] 偽の時計で、予約した停止と有効期間の境界が時刻どおりに効く
- [x] 復旧専用のセッションで認証手段の登録以外が拒否される（復旧の完了とログアウトは使える。ADR 0054）
- [x] 無効化した認証情報で作られたセッションが使えなくなる

### 含まないもの

Org、認可。

---

## M3 Org

**ゴール**：個人 Org と共有 Org を持ち、ログインの手がかりで入る Org が切り替わる。

### 含むもの

- Org フィーチャー、個人 Org の自動作成、共有 Org、`org_role`（11.13、4.11）
- 招待（メールの結び付け）、Membership ごとのメール（4.4）
- Org の決定と切り替え（手がかり、ID の入れ替え、step-up）（4.4）
- Org と Membership の停止・有効期間（4.7、4.8）
- 退会、アカウント削除（猶予期間、crypto-shredding、legal hold）、Org の削除（4.10）
- realm の運営者ロールと `org_role` の権限（4.11）。M4 までは**暫定の固定権限**で実装し、M4 で authz のロールに置き換える
- 設定の階層の Org 段（寿命・警告のアクションなど）（2.8、5.4。ADR 0062）
- 後から Org を有効にする準備処理（11.13）

### 完了条件

- [x] 仕事用メールでログインすると会社の Org に入る。passkey の既定 Org も効く
- [x] Org の管理者から、結び付けたメール以外が見えない（連携先は M5 の完了条件）
- [x] 最後のオーナーは抜けられない。個人ユーザーの退会は Org の設定で止められない
- [x] 削除後、監査ログに残った個人情報が復号できない
- [x] Org をオフにした構成で M1・M2 の E2E がそのまま通る

### 含まないもの

Group とロールによる認可（`org_role` の固定の権限のみ）、Quota、Org 専用 SSO。

---

## M4 認可

**ゴール**：Org（または realm）の中で、誰が何をできるかを判定できる。

### 含むもの

- `groups`、`group_members`、`roles`、`role_permissions`、`role_bindings`（3.2）
- `check` API、リソース単位の権限、判定結果のキャッシュ（4.5、11.5）
- 管理 API を authz で保護し、運営者ロール・Org ロールを既定のロールとして完成させる（4.11）

### 完了条件

- [x] Org オン（Org 範囲）とオフ（realm 範囲）の両方で判定が正しい
- [x] ロール・所属の変更が、上限の時間内に判定へ反映される
- [x] `check` のレイテンシが M0 で決めた基準を満たす（ベンチマーク）
- [x] 権限のない管理操作が `permission_denied` で拒否される

### 含まないもの

Group のネスト、Org 階層（M7）。

---

## M5 OIDC Provider

**ゴール**：ほかのアプリが標準の OIDC でログインを任せられる。

### 含むもの

- zitadel/oidc の OP、ファーストパーティのクライアント登録（5.5）
- ID トークン（ML-DSA-65 / ES256 をクライアントごとに）、JWKS（9.3）
- 不透明なアクセストークンとイントロスペクション、リフレッシュのローテーションと再利用検知（5.1）
- Back-Channel Logout（`sid`）（5.2）
- 公開 API の CORS・CSRF の仕上げ

### 完了条件

- [x] [適合性メモ](oidc-conformance.md)の観点を自動テストで確認し、既知の差異（RS256 なし、PKCE 必須、`query` 以外の
  response_mode・request・claims・profile などのスコープ・同意画面・動的登録・offline_access を扱わない）を文書化する
- [x] 停止・無効化がイントロスペクションの結果に上限の時間内で反映される
- [x] ML-DSA と ES256 の両方の RP で E2E が通る
- [x] 連携先から、Membership に結び付けたメール以外が見えない

### 含まないもの

サードパーティへの開放、動的クライアント登録。

---

## M6 本番運用

**ゴール**：ホスト先が本番で運用・監視・移行・構成変更できる。

### 含むもの

- Org のログインポリシー（`require_passkey`、`membership_email_domain`、`ip_allowlist`）（4.4）
- Quota（11.14）
- SIEM 向けの出力（syslog、OTLP、Webhook、OCSF、仮名化）（6.3）
- 保持期間の処理（監査ログの切り詰めとチェックポイント、IP の切り詰め）、メールの最小化モード（6.5、9.6）
- PostgreSQL と Redis のアダプタ、`iam storage export / import`（2.4）
- `iam build`、`iam features plan / enable / disable`、公式イメージ（全部入り・最小構成）と署名・SBOM（11.11、11.12、13.8）
- 運用文書（鍵のバックアップ、アップグレード、障害時の手順）（[operations.md](operations.md)）

### 完了条件

- [x] E2E が2構成（SQLite + インメモリ、PostgreSQL + Redis）で通る
- [x] SQLite から PostgreSQL への移行の E2E が通る
- [x] 各フィーチャーの、データがある状態での有効化・無効化のテストが通る
- [x] Quota の時刻つき判定（期間が重ならない人の枠の共有、将来の減少）のテストが並行実行でも通る
- [ ] OpenID Foundation の適合試験（Basic OP 相当）に、[適合性メモ](oidc-conformance.md)の既知の差異以外で合格
  （公開した環境で実行し、結果を適合性メモに追記する）

---

## M7 拡張

必要になったものから順に足す（順不同）。各フィーチャーは追加時にゴールと完了条件を書き足す。

- サービスアカウント（汎用）、複数 realm（M7 の最後に回す。方式は、1つの App のままリクエストごとに realm を決める形にする。
  realm を実行中に追加でき、接続・キャッシュ・配信の処理を全 realm で共有できるため）

### サービスアカウント（汎用。ADR 0074）

**ゴール**：配信用以外の機械の主体が、ロールの付与に従って管理 API を使える。

- [x] 管理 API で作成・一覧・削除し、認証情報（API キー・client_secret・private_key_jwt）を足し・無効化できる
- [x] client credentials（client_secret_basic / post、ES256・EdDSA・ML-DSA-65 の client assertion）で短命のトークンを発行する。jti の再利用を拒否する
- [x] 停止・有効期間・削除・Org の停止が、発行済みのトークンにも次の要求から効く
- [x] フィーチャーをオフにしても配信用は使え、無効化で汎用のものだけを片付ける
- Org 管理ユーザー、ドメインの所有証明、Org 専用 SSO（SAML / OIDC）

### ドメインの所有証明（ADR 0075）

**ゴール**：Org が DNS の TXT でドメインの所有を証明し、証明済みのドメインを realm で1つの Org だけが持つ。

- [x] Org の owner が公開 API でドメインを登録・一覧・証明・削除できる（個人 Org は不可、1 Org に 20 まで）
- [x] TXT が無い・DNS の障害・別の Org が証明済み、をそれぞれ区別して返す
- [x] フィーチャーの無効化でドメインを片付ける

### Org 管理ユーザー（ADR 0076）

**ゴール**：Org が、証明済みドメインのアドレスを使う人のアカウントを、本人の同意を得て所有する。

- [x] Org の owner が求め、本人が受け入れる・断る。Org が手放す・除名すると個人ユーザーに戻る
- [x] 管理ユーザーはその Org を抜けられず、自分でアカウントを消せない
- [x] 招待から新しく登録した人を最初から管理ユーザーにする。管理する Org に入れなければログインできない（停止・ログインポリシー）
- [x] Org の owner が管理ユーザーのアカウントを消せる（本人は取り消せない）

### Org 専用 SSO（ADR 0077）

**ゴール**：Org が自社の IdP（OIDC）で、証明済みドメインのメンバーをログイン・登録させる。

- [x] Org の owner が公開 API で OIDC の connection を登録・一覧・削除できる（戻り先は固定、1 Org に 5 まで）
- [x] その Org の管理ユーザーだけがログイン・連携でき、未登録なら証明済みドメインのアドレスで管理ユーザーとして作る
- [x] トークンエンドポイントは公開のアドレスに限る（SSRF）
- [x] ログインポリシー `require_sso`、ドメインから connection を探す口
- [x] フィーチャーの無効化・Org の削除で connection を片付ける
- SAML（Org 専用 SSO）

### Org 階層（ADR 0078）

**ゴール**：親 Org の管理者とロールが、子孫の Org の範囲の判定に効く。

- [x] 運営者が親を設定・外せる（循環の禁止、5 段まで、個人 Org は対象外）
- [x] 祖先の付与と org_role が、祖先の使える所属を持つ間、使える子の Org の判定に効く
- [x] 祖先の一覧を書き込み時に計算する（SQL は閉包テーブル）
- [x] Org の削除で子を根にし、フィーチャーの無効化で親子関係を外す
- Org の owner による親の設定（公開 API）

### Group のネスト（ADR 0079）

**ゴール**：Group を Group に入れ、含む Group のロールを入れた Group の所属に効かせる。

- [x] 同じ範囲の Group を Group の所属にできる（循環の禁止、5 段まで）
- [x] 含む Group の一覧を書き込み時に計算し、判定は1回の問い合わせで集める
- [x] Group の削除・所属の変更で計算し直し、フィーチャーの無効化で Group としての所属を外す

### カスタム属性（ADR 0080）

**ゴール**：realm ごとにユーザーの属性を定義し、運営者・本人が書き、連携先がトークンで受け取れる。

- [x] 運営者が型・検証・本人による編集可否・トークンへの掲載・暗号化の有無を定義できる
- [x] 運営者が値を読み書きし、本人は編集できる属性だけを書ける。誤りがあれば何も書かない
- [x] スコープ `attributes` の ID トークン・UserInfo に、掲載する属性だけを載せる
- [x] 暗号化する属性はユーザーのデータ鍵で暗号化し、ユーザーの消去で値を消す。フィーチャーの無効化で値と定義を消す

### フロー フック（ADR 0081）

**ゴール**：登録・ログイン・退会・トークンの発行に、ホスト先の判定とクレームを足せる。

- [x] `pre_registration`・`post_authentication`・`pre_membership_end`・`pre_token` を Go の実装か Webhook（署名付き）で呼ぶ
- [x] フックごとのタイムアウト（5 秒まで）と fail-closed / fail-open
- [x] 止めたときは理由のコードを返し、何も書かない。`pre_token` は IAM が決めるクレームを上書きできない

### アカウント統合（ADR 0082）

**ゴール**：同じ人の2つのアカウントを、両方の所有を証明して1つにできる。

- [x] 統合元で発行した1回限りのトークンを、統合先で使う（どちらも直近の本人確認）
- [x] メール・外部 ID・passkey・TOTP・パスワード・ロールの付与・Group の所属・属性の値・Membership を移す
- [x] 統合元の個人 Org は残し、統合先を owner にした新しい Org に中身（ロールの付与を除く）を移す
- [x] 統合元は merged になり、セッションと連携先の認可を失効し、`user.merged` を出す
- Org 管理ユーザーの統合（Org の許可）、運営者による統合

### 複数 realm（ADR 0083）

**ゴール**：1つのインスタンスで、互いに独立したユーザー集合を実行中に足せる。

- [x] ホスト名か `/realms/{slug}` で realm を決め、realm ごとのサービスの組に渡す。既定の realm は今までどおり root で動く
- [x] 管理 API で realm を作り・変え、最初の運営者を作れる。他のインスタンスにも反映する
- [x] realm ごとの設定・issuer・署名鍵・passkey の RP・Cookie。同じメールでも realm ごとに別のユーザー
- [x] 予約の処理・保持期間の掃除・Back-Channel Logout は全 realm で共有し、出来事の realm で動く
- realm の削除、realm ごとのセキュリティの階層
- SCIM、管理画面（design.md 1章では当面やらないとしている。必要になったら検討）

### 管理 API の一覧・取得・検索（ADR 0097。M10 エンタープライズの運用）

**ゴール**：運営者が管理 API だけでユーザー・Org・セッション・付与と所属・connection・署名鍵を調べ、メールを扱える。

- [x] ユーザーの一覧と検索（メールの完全一致、外部 ID、状態、Org、作成の時刻）と詳細。カーソルのページング
- [x] メールアドレスは `include_pii` と `pii:read` のときだけ復号し、`user.pii_read` を監査ログに残す
- [x] Org の一覧と検索（名前の前方一致、親、種類、状態）
- [x] ユーザーのセッションの一覧と全セッションの失効（認証情報は残す）
- [x] ユーザーとサービスアカウントのロールの付与と Group の所属の逆引き、ユーザーの Membership の一覧
- [x] IdP 接続の一覧・取得・変更・削除（使っている外部 ID があれば既定で断る）、署名鍵の一覧
- [x] 運営者によるメールの追加（確認の経路 `admin`）・削除・primary の変更（outranks と、最後の確認済みメールの不変条件）
- [x] 読み取りの権限を運営者ロールに足す。realm を越えない（契約テストの分離の検査）
- 監査ログの照会 API、運営者による Org への追加

---

## M8〜M12 全部入り（ADR 0089）

範囲は [scope.md](scope.md)。新しいフィーチャーはすべて既定オフにする。認証を最優先にし、M8・M9 を先に進める。
各フェーズは、着手するときにゴールと完了条件を書き足す。

### M8 認証の土台

- 認証方式のプラグイン（ADR 0090）：`Authenticator` のポート、`authn_credentials`、汎用の HTTP、外部 Authenticator のアダプタ
- 既存の方式（passkey・TOTP・パスワード・メール・ログインリンク・OAuth）を 1 方式ずつ移す
- `acr` と AAL、step-up（RFC 9470）、Org のログインポリシーと `acr_values` を強さで書く
- RP-Initiated Logout、Front-Channel Logout（下）

#### RP-Initiated Logout と Front-Channel Logout（ADR 0094）

**ゴール**：連携先の画面でのログアウトで IAM のセッションも終わり、同じブラウザのほかの連携先にも知らせる。

- [x] `end_session_endpoint`（GET と POST）。`id_token_hint`（期限切れも可。署名・`iss`・`aud` を確かめる）、`client_id`、
  登録と完全一致の `post_logout_redirect_uri`、`state`、`ui_locales`、`logout_hint`
- [x] `id_token_hint` がセッションと合わない・無いときはホスト型の確認の画面（1回限り・同じセッションだけ・同一オリジン）
- [x] セッションの失効で Back-Channel Logout を送り、完了の画面で `frontchannel_logout_uri` を iframe で開く（`iss`・`sid`、CSP）
- [x] 連携先の登録と Discovery、フィーチャーの無効化で登録を外す、複数 realm、標準の RP（zitadel/oidc）での E2E
- OpenID Connect Session Management（`check_session_iframe`）

#### acr・AAL と step-up（ADR 0093）

**ゴール**：ポリシーと条件を認証の強さ（AAL）で書け、足りなければ連携先と API が step-up を求められる。

- [x] amr から AAL（SP 800-63B）を求める対応表。amr の値ごとに引け、方式の宣言（ADR 0090）に置き換えられる
- [x] `acr` を ID トークン・UserInfo・イントロスペクションに載せ、Discovery に `acr_values_supported`
- [x] authorize の `acr_values` と `claims` の `id_token.acr`。満たさなければログインへ回し、届かなければ `unmet_authentication_requirements`
- [x] 判定の API の `step_up` と、公開 API の本人の重要な操作の RFC 9470 の `WWW-Authenticate`（本文は変えない）
- [x] 条件の言語の `aal_at_least` と、Org のログインポリシーの `min_aal`
- [x] フィーチャー `acr`（既定オフ）。オフなら今の動作と同じ
- AAL3 と `phrh`（attestation で鍵がハードウェアにあると確かめる方式。ADR 0090 の方式の宣言で足す）、メールのコードと TOTP の区別

### M9 認証方式の拡張

- 外部 IdP：SAML 2.0（Org 専用 SSO と realm の connection）、WS-Federation
- ディレクトリ：LDAP / AD のバインド認証と同期、Kerberos / SPNEGO
- 方式：WebAuthn の attestation と AAGUID の許可リスト、HOTP、SMS・音声、プッシュ、X.509・スマートカード、Verifiable Credentials（OpenID4VP）
- リスクに応じた追加認証、新しい端末の検知、ボット対策、アカウント単位のロックアウト
- Device Authorization Grant（下記）、本人の Personal Access Token

#### Device Authorization Grant（ADR 0095）

**ゴール**：入力の限られた端末（テレビ・CLI など）の連携先が、RFC 8628 で本人にログインを任せられる。

- [x] フィーチャー `device_flow`（既定オフ）。オフなら Discovery・エンドポイント・管理 API に何も出さない
- [x] 連携先ごとに許し、許した連携先だけが device_authorization と device_code の grant を使える（公開クライアントも可）
- [x] device_code は 256 bit、user_code は子音 8 桁。状態は EphemeralStore に封をして置き、user_code と承認は1回だけ使える
- [x] 本人はホスト型の画面でログインし、連携先の名前・コード・スコープを見て許可か拒否を選ぶ（CSRF を拒む。照合の回数に上限）
- [x] `authorization_pending`・`slow_down`（間隔を延ばす）・`access_denied`・`expired_token`。承認の後は認可コードフローと同じトークン
- [x] 監査ログ（承認・拒否・発行）、フィーチャーの無効化で連携先の許可を外す、標準の RP（zitadel/oidc の rp）での E2E
- 端末の名前や場所を確認の画面に出す、承認の通知

#### WebAuthn の attestation と AAGUID の許可リスト（ADR 0096）

**ゴール**：企業が承認した認証器だけで passkey を登録・ログインさせられる。

- [x] フィーチャー `passkey_attestation`（既定オフ）。登録で attestation を求める（既定 `none`、`direct` / `enterprise` は設定）
- [x] packed・tpm・android-key・apple・fido-u2f の署名を go-webauthn で確かめ、MDS3 と設定の信頼の起点まで連なりをたどる
- [x] MDS3 の BLOB をポート `FIDOMetadataSource`（`file` / `http`）から読み、署名を確かめ、バックグラウンドで読み直す。ホットパスは外部を呼ばない
- [x] realm と Org の段の認証器のポリシー（許可・拒否の AAGUID、認定レベルの下限、attestation の要否）。登録・ログイン・2要素目・Org の入場で判定する
- [x] 拒否はコードだけ返し、AAGUID と判定を監査ログに残す。管理 API の passkey の一覧に AAGUID と認証器の名前を出す
- [x] 既存の passkey は自己申告の AAGUID で判定し、`require_attestation` では登録し直しを求める。無効化でポリシーを片付ける
- MDS の BLOB の永続化（再起動の直後に取得できないときの備え）、ポリシーに外れた既存の passkey の一覧と通知

### M10 エンタープライズの運用

- [x] 管理 API の一覧・取得・検索（ユーザー、Org、セッション、付与と所属の逆引き、connections、署名鍵）、管理者によるメールの操作（ADR 0097）
- 運営者による Org への追加
- 監査ログの照会 API、イベントの Webhook の購読の API
- 一括インポート（パスワードハッシュ付き）、運営者のなりすまし（記録付き）
- 役割ごとのプロセス（ADR 0091）と、`org`・`authz`・`authz-manage` を分けるための依存の整理
- メトリクス・トレース、HSM・クラウド KMS の KeyStore、Helm チャート
- Org ごとのブランディングとカスタムドメイン、委任管理、管理画面、本人のデータの書き出し、同意の記録

### M11 OAuth / OIDC とプロビジョニングの拡張

- RS256、JWT のアクセストークン、`offline_access`、`profile` などのスコープ、`claims`、`form_post`、JAR、PAR
- サードパーティの連携先、同意画面、動的クライアント登録、本人による許可の一覧と取り消し
- SAML 2.0 IdP、Token Exchange、CIBA、DPoP、mTLS、FAPI 2.0、RFC 8414・9728
- サービスアカウントの自前の API 向けトークン（RFC 8707）、Workload Identity Federation
- ロール・Group のクレーム、Shared Signals（CAEP・RISC）
- SCIM 2.0（サーバーとクライアント）

### M12 認可の拡張

- 一括判定、権限の一覧、OpenID AuthZEN、ReBAC、ポリシー言語、時限付きの付与と棚卸し

---

## v1.0 の条件

- [ ] OIDC の適合試験と WebAuthn の適合試験に合格（既知の差異を明記）。M8 以降の範囲は、v1.0 の時点で完成しているフィーチャーに限る（ADR 0089）
- [ ] 脅威モデルと不変条件のテストが揃っている（13.5）
- [ ] 第三者のセキュリティ監査を完了し、指摘に対応した
- [ ] 公開 API・Webhook・トークンのクレーム・Go ライブラリのポートの v1 を凍結した（11.10）
- [ ] 運用文書が揃っている
