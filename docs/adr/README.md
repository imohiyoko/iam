# ADR（設計判断の記録）

設計上の重要な判断と、その理由を記録する。現在の仕様の全体像は [design.md](../design.md) を参照。

## 運用

- 新しい判断をしたら、次の番号でファイルを追加する（[template.md](template.md)）
- 承認済みの ADR は書き換えない。判断を変えるときは新しい ADR を作り、古い ADR の状態を「置き換え: NNNN」にする
- design.md は「今どうなっているか」、ADR は「なぜそうしたか」を書く

## 一覧

| 番号 | タイトル | 状態 |
|---|---|---|
| [0001](0001-authn-authz-monorepo.md) | 認証と認可を同一リポジトリの別モジュールにする | 承認 |
| [0002](0002-go.md) | 実装言語に Go を使う | 承認 |
| [0003](0003-ports-and-adapters.md) | 外部依存をポート & アダプタで切り離し、必須の製品を持たない | 承認 |
| [0004](0004-storage-adapter-native.md) | Storage アダプタは DB ごとに内部を最適化する | 承認 |
| [0005](0005-crypto-no-rsa-pqc.md) | RSA を自前の鍵で使わず、耐量子暗号を併用する | 承認 |
| [0006](0006-passkey-rs256.md) | 外部の RS256（passkey 等）は受け入れ、警告の対象にする | 承認 |
| [0007](0007-auth-warnings.md) | 全認証経路に共通の警告の仕組みを持つ | 承認 |
| [0008](0008-hosted-login-and-api.md) | ホスト型ログイン画面と公開 API の2本立てにする | 承認 |
| [0009](0009-notifier-delegated.md) | メールなどの配送は外部に任せる | 置き換え: 0031 |
| [0010](0010-feature-toggles.md) | 機能をフィーチャー単位で取捨選択できるようにする | 承認 |
| [0011](0011-build-time-features.md) | ビルド時にフィーチャーを選択し、台帳で構成変更を保証する | 承認 |
| [0012](0012-extensible-data-model.md) | データモデルは最初から拡張可能な形にする | 承認 |
| [0013](0013-org-feature-personal-org.md) | Org をフィーチャーにし、有効時は個人 Org を自動作成する | 承認 |
| [0014](0014-pii-encryption-minimization.md) | 個人情報は暗号化し、持たなくてよいものは持たない | 承認 |
| [0015](0015-test-separation.md) | フィーチャーのテストと DB のテストを切り離す | 承認 |
| [0016](0016-license-apache.md) | ライセンスを Apache-2.0 にする | 承認 |
| [0017](0017-session-id.md) | セッションは公開用の ID と秘密のトークンに分ける | 承認 |
| [0018](0018-suspension-and-validity.md) | 停止と有効期間を時刻で判定し、停止には種別を付ける | 承認 |
| [0019](0019-quota-as-precondition.md) | Org の人数上限は Membership の前提条件として扱う | 承認 |
| [0020](0020-leaving-and-deletion.md) | 退会の可否はユーザーの種類で決め、削除は猶予期間と crypto-shredding で行う | 承認 |
| [0021](0021-opaque-access-tokens.md) | アクセストークンは不透明トークンにする | 承認 |
| [0022](0022-deny-reason-disclosure.md) | 拒否理由は本人確認の後にだけ返す | 承認 |
| [0023](0023-admin-model.md) | 管理権限は realm の運営者ロールと Org のロールの2層で表す | 承認 |
| [0024](0024-session-validity-cache.md) | セッションの有効性をキャッシュし、反映遅れの上限を保証値とする | 承認 |
| [0025](0025-account-recovery.md) | アカウント復旧は複数の経路と復旧専用のセッションで行う | 承認 |
| [0026](0026-first-party-clients.md) | 連携先は当面ファーストパーティのみとする | 承認 |
| [0027](0027-layered-session-lifetime.md) | セッションの寿命はホスト → realm → Org の階層で設定する | 承認 |
| [0028](0028-time-handling.md) | 時刻は UTC で扱い、タイムゾーンは日付入力の変換にだけ使う | 承認 |
| [0029](0029-audit-retention.md) | 監査ログはホスト先が決めた保持期間で削除し、ハッシュチェーンはチェックポイントで切り詰める | 承認 |
| [0030](0030-security-assurance.md) | 第三者のレビュー不足を、機械による検証と外部の基準で補う | 承認 |
| [0031](0031-notifier-ids-only.md) | 通知は ID だけを渡し、文面・URL・配送は外部が行う | 承認 |
| [0032](0032-username-password-signup.md) | ID とパスワードだけでログインできるアカウントを許可する | 置き換え: 0037 |
| [0033](0033-security-settings-hierarchy.md) | どこまで厳しくするかは、ホスト先と Org の設定で決める | 承認 |
| [0034](0034-email-required.md) | すべてのユーザーに確認済みのメールアドレスを1つ以上持たせる | 承認 |
| [0035](0035-id-login-requires-second-factor.md) | ID（ユーザー名）でのログインには2要素目を必須にする | 置き換え: 0037 |
| [0036](0036-membership-email-and-login-hints.md) | Membership ごとにメールアドレスを結び付け、ログインの手がかりで Org を選ぶ | 承認 |
| [0037](0037-no-usernames.md) | ユーザー名（独自の ID）は持たず、パスワードはメールアドレスと組み合わせる | 承認 |
| [0038](0038-library-selection.md) | OIDC は zitadel/oidc、JOSE は jwx、WebAuthn は go-webauthn を使う | 承認 |
| [0039](0039-implementation-basics.md) | 実装の基本（HTTP、SQL、マイグレーション、ID、M1 のログイン方法） | 承認 |
| [0040](0040-spike-mldsa-opaque-signer.md) | ML-DSA-65 の ID トークンは go-jose の OpaqueSigner で署名でき、kid は自前で付ける | 承認 |
| [0041](0041-spike-jwks-akp.md) | AKP（ML-DSA-65）の鍵を含む JWKS は jwx で出力し、主要な Go の RP がそのまま読める | 承認 |
| [0042](0042-spike-sqlite-count-then-insert.md) | SQLite の書き込みトランザクションは BEGIN IMMEDIATE で直列化する | 承認 |
| [0043](0043-spike-fake-clock-ttl.md) | 有効期限は Clock ポートで判定し、偽の時計で時刻の境界をテストする | 承認 |
| [0044](0044-latency-baseline.md) | 主要操作のレイテンシの基準値と、CI での計測 | 承認 |
| [0045](0045-internal-and-external-ids.md) | 内部 ID と外部 ID を分け、採番の方式を差し替えられるようにする | 承認 |
| [0046](0046-m1-login-flows.md) | M1 のログインの流れ（メールのフロー、通知の claim、OAuth）の細部 | 承認 |
| [0047](0047-m1-login-guards.md) | M1 のログインの守り（警告、応答時間の下限、レートリミット）の細部 | 承認 |
| [0048](0048-operator-bootstrap-and-admin-auth.md) | 最初の運営者の作成と、管理 API の運営者の認証 | 承認 |
