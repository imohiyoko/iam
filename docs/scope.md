# 全部入りの範囲

iam が最終的に持つ機能の一覧（ADR [0089](adr/0089-enterprise-full-scope.md)）。フェーズの割り当ては [roadmap.md](roadmap.md) の M8〜M12。
状態は 2026-11-02 の main（`3a20f7d`）で、API の定義と ADR から確かめた。「要確認」はコードの中まで確かめていない。

## 範囲の決め方

次のどれかに当てはまるものを「全部」に含める。

- **S（標準）**：IETF・OpenID Foundation・OASIS・W3C・FIDO Alliance・NIST などの、認証・認可・プロビジョニングの仕様
- **P（製品）**：Keycloak・Auth0・Okta・Zitadel・Entra ID のうち、2 つ以上が標準で持つ機能
- **C（調達）**：SOC 2・ISO 27001・企業のセキュリティ質問票で、IAM によく求められる項目

含めないもの：

- 廃止・非推奨の仕様（implicit grant、ROPC、OAuth 1.0、SAML 1.1）
- 1 製品だけの独自機能
- IAM の外の領域（PAM、IGA の申請ワークフロー、MDM）

状態：✅ ある、△ 一部、❌ 無い、⛔ 以前の ADR で除外していた（0089 で含める）。

## 1. 認証方式

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| メールのコード・マジックリンク | P | ✅ | |
| パスワード | S（SP 800-63B）P | ✅ | 漏洩の確認（HIBP）も |
| passkey（WebAuthn L3） | S（W3C、FIDO2） | ✅ | Related Origin Requests も |
| WebAuthn の attestation、AAGUID の許可リスト、FIDO MDS | S C | ✅ | 企業が認めた鍵だけを通す。フィーチャー `passkey_attestation`（ADR 0096） |
| TOTP | S（RFC 6238） | ✅ | |
| HOTP・ハードウェアトークン | S（RFC 4226）P | ✅ | フィーチャー `hotp`（ADR 0092）。2要素目 |
| SMS・音声の OTP | P | ✅ | フィーチャー `sms_otp`（ADR 0104）。2要素目。SP 800-63B の制限付きの認証器で、realm と Org で止められる。送信は `sms_sender`（`twilio`） |
| プッシュ通知の承認（番号の照合付き） | P | ✅ | フィーチャー `push_auth`（ADR 0104）。2要素目。端末の鍵の署名、番号の照合、拒否が続けば止める。送信は `push_sender`（`webhook`） |
| X.509 クライアント証明書・スマートカード（PIV、CAC） | S P C | ✅ | フィーチャー `x509`（ADR 0103）。mTLS の専用の待ち受けかプロキシのヘッダー、OCSP・CRL、ハードウェアの CA で AAL3 |
| Kerberos／SPNEGO | S P | ✅ | フィーチャー `kerberos`（ADR 0107）。HTTP の Negotiate、realm ごとの keytab、結び付けは本人の登録・確認済みのメール・LDAP の connection。1要素目（`wia`、AAL1） |
| LDAP のバインド認証 | P | ✅ | フィーチャー `ldap`（ADR 0102）。Active Directory も。ホスト型の画面は後続 |
| 外部 IdP（OAuth／OIDC） | S P | ✅ | |
| 外部 IdP（SAML 2.0） | S P C | ✅ | ADR 0098。Single Logout・暗号化された Assertion は後続 |
| 運営者が発行するログインリンク | P | ✅ | |
| Verifiable Credentials（OpenID4VP、mdoc） | S | △ | フィーチャー `openid4vp`（ADR 0108）。OpenID4VP 1.0 の検証者で、SD-JWT VC（key binding 必須）、同じ端末と別の端末、DCQL、realm ごとの信じる発行者。mdoc は後続 |
| 外部の認証方式（プラグイン・Webhook） | P | △ | ADR 0090。Go のプラグインはある（ADR 0092）。外部 Authenticator のアダプタは未 |

## 2. 多要素・保証レベル・リスク

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| 2 要素目の強制と登録の要求 | P C | ✅ | passkey と TOTP に固定 |
| step-up（RFC 9470） | S P | ✅ | フィーチャー acr（ADR 0093）。判定の API の `step_up`、公開 API の `WWW-Authenticate` |
| `acr`・`acr_values`・AAL | S（OIDC、SP 800-63B） | ✅ | フィーチャー acr（ADR 0093）。AAL3・`phrh` は、ハードウェアの CA を設定した X.509（ADR 0103）で届く |
| リスクに応じた追加認証 | P | ✅ | フィーチャー `login_risk`（ADR 0105）。端末・国・ASN・impossible travel を点数にし、`risk_at_most` と `aal_at_least` で step-up |
| 新しい端末・異常な場所の検知 | P | ✅ | フィーチャー `device_recognition`・`login_risk`（ADR 0105）。通知 `new_device_login`、警告 `new_device`、端末の一覧と削除。GeoIP の mmdb のアダプタは後続 |
| ブルートフォース対策・ロックアウト | P C | ✅ | レートリミットと、フィーチャー `account_lockout`（ADR 0105）の接続元を問わない待ち時間とロック、運営者の解除 |
| ボット対策（CAPTCHA など） | P | △ | フィーチャー `bot_protection`（ADR 0105）。siteverify の検証のポート。ホスト型の画面のウィジェットは後続 |
| Shared Signals（CAEP、RISC） | S | ✅ | フィーチャー `ssf_transmitter`・`ssf_receiver`（ADR 0118）。SSF 1.0 の送信側（push・poll）と受信側（許した動作だけ）。端末の準拠状態は入力として置くだけ |

## 3. アカウントとセルフサービス

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| 登録・複数メール・外部 ID の連携と解除 | P | ✅ | |
| 復旧 | P | ✅ | |
| セッションの一覧と失効 | P | ✅ | |
| アカウントの削除・統合 | P C | ✅ | |
| 本人のデータの書き出し（GDPR） | C | ❌ | |
| 利用規約・同意の版と記録 | C P | ❌ | |
| 段階的なプロフィール収集 | P | ❌ | |
| 本人の Personal Access Token | P | ✅ | フィーチャー `personal_access_tokens`（ADR 0109） |
| 本人が許可した連携先の一覧と取り消し | P | ⛔ | ADR 0026 |

## 4. IdP として

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| OIDC の認可コード + PKCE、Discovery、JWKS、UserInfo | S | ✅ | |
| リフレッシュ、イントロスペクション、失効 | S（RFC 7662、7009） | ✅ | |
| Back-Channel Logout | S | ✅ | |
| RP-Initiated Logout、Front-Channel Logout | S | ✅ | ADR 0094（`oidc_logout`） |
| Session Management | S | ❌ | |
| `profile`・`address`・`phone` スコープ、`claims` パラメーター | S | ⛔ | 適合性メモ |
| `form_post`・`fragment`、JAR（RFC 9101） | S | ⛔ | 適合性メモ |
| PAR（RFC 9126） | S | ✅ | フィーチャー `par`（ADR 0112）。連携先か realm の単位で必須にできる |
| RS256 | S | △ | フィーチャー `rs256`（ADR 0122）。OIDC の ID トークン・Logout Token。SAML の IdP・WS-Federation の RSA-SHA256 は後続 |
| JWT アクセストークン（RFC 9068） | S P | ⛔ | ADR 0021 |
| `offline_access` | S | ⛔ | ADR 0066 |
| 同意画面・サードパーティ・動的登録（RFC 7591、7592） | S P | ⛔ | ADR 0026 |
| ロール・Group のクレーム | P | △ | `pre_token` フックで足せる |
| SAML 2.0 IdP（Web Browser SSO・Single Logout の受け側） | S P C | ✅ | フィーチャー `saml_idp`（ADR 0115）。署名は ECDSA だけ（RSA は RS256 のフィーチャーの後） |
| WS-Federation（パッシブ要求者プロファイル。SAML 1.1 / 2.0 のトークン） | P | ✅ | フィーチャー `wsfed`（ADR 0110）。署名は ECDSA だけ（RSA は RS256 のフィーチャーの後） |
| CAS | P | ❌ | |
| OAuth AS メタデータ（RFC 8414）、Protected Resource Metadata（RFC 9728） | S | ✅ | ADR 0112。9728 は IAM 自身の API（UserInfo）の分 |
| Device Authorization Grant（RFC 8628） | S P | ✅ | フィーチャー `device_flow`（ADR 0095） |
| CIBA（poll・ping） | S | ✅ | フィーチャー `ciba`（ADR 0114）。手がかりは `login_hint`・`id_token_hint`。承認はプッシュの端末か本人の API。push モードと `login_hint_token` はなし |
| FAPI 2.0 | S C | △ | フィーチャー `fapi2`（ADR 0117）。Security Profile を連携先か realm の単位で強いる。Message Signing（JAR・JARM）はなし |
| OpenID4VCI | S | △ | フィーチャー `openid4vci`（ADR 0119）。SD-JWT VC（`dc+sd-jwt`）の発行者で、Pre-Authorized Code（tx_code）と scope の Authorization Code Flow、jwt の proof、Token Status List。mdoc・`authorization_details`・応答の暗号化・遅延発行は後続 |

## 5. M2M と API の保護

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| サービスアカウント（API キー、client_secret、private_key_jwt） | S P | ✅ | 管理 API 専用 |
| 自前の API 向けの client credentials（`aud`・スコープ、RFC 8707） | S P | ✅ | フィーチャー `resource_indicators`（ADR 0112）。入口は `/v1/admin/token`。認可コードフローの `resource` も |
| Token Exchange（RFC 8693）・委任・なりすまし | S P | ✅ | ADR 0099 |
| DPoP（RFC 9449）、mTLS（RFC 8705） | S | ✅ | フィーチャー `dpop`・`mtls_client_auth`（ADR 0113）。`cnf` の結び付け、公開クライアントのリフレッシュトークン、nonce、UserInfo と管理 API での確かめ |
| Workload Identity Federation（RFC 7523、SPIFFE） | S P | ✅ | フィーチャー `workload_identity`（ADR 0116）。入口は `/v1/admin/token` の RFC 8693。GitHub Actions・GitLab CI・Kubernetes・クラウドの JWT。SPIFFE は JWT-SVID だけ |
| Org の管理者による Org のサービスアカウントの管理 | P | ❌ | |

## 6. 認可

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| RBAC（ロール、Group、ネスト、Org 階層） | P | ✅ | |
| 認証の文脈・リスクを条件にした判定 | P | ✅ | |
| 一括判定・権限の一覧 | P | ❌ | |
| OpenID AuthZEN の評価 API | S | ❌ | |
| ReBAC（Zanzibar 型） | P | ⛔ | design.md 1 章 |
| ポリシー言語（CEL、Cedar、Rego） | P | ❌ | |
| 時限付きの付与・アクセスの棚卸し | C | ❌ | |

## 7. Org・マルチテナント

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| Org、招待、Membership、停止、削除 | P | ✅ | |
| ドメインの所有証明、Org 管理ユーザー、Org 専用 SSO（OIDC） | P | ✅ | |
| ログインポリシー、Quota、階層 | P | ✅ | |
| 複数 realm | P | △ | 削除と realm ごとのセキュリティの階層が未完 |
| Org ごとのブランディング・カスタムドメイン | P | ❌ | |
| Org の owner による親の設定 | P | ❌ | |

## 8. プロビジョニングとディレクトリ

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| SCIM 2.0 サーバー | S P C | ⛔ | design.md 1 章 |
| SCIM クライアント（連携先へ送り出す） | S P | ❌ | |
| LDAP／AD の同期 | P | ✅ | ADR 0102。消えた人は利用停止（自動では消さない）、`memberOf` から Group。ネストしたグループは後続 |
| JIT プロビジョニング | P | ✅ | Org 専用 SSO |
| 一括インポート（パスワードハッシュ付き）・段階的な移行 | P | ❌ | |

## 9. 管理

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| 管理 API の作成・変更・停止・削除 | P | ✅ | |
| 管理 API の一覧・取得・検索（ユーザー、Org、セッション、connections、署名鍵） | P | ❌ | |
| 運営者のなりすまし（記録付き） | P | ✅ | Token Exchange で（ADR 0099） |
| 委任管理 | P C | △ | Org の owner・admin |
| 管理画面 | P | ⛔ | design.md 1 章 |
| Terraform プロバイダ・宣言的な設定 | P | ❌ | |
| クライアント SDK | P | ❌ | |

## 10. 監査・コンプライアンス・プライバシー

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| 改ざん検知付きの監査ログ、SIEM への出力 | C | ✅ | |
| 監査ログの照会 API | P C | ✅ | ADR 0100。範囲の検証、Org の管理者向け（`org_audit_log`） |
| 保持期間、crypto-shredding、legal hold、PII の暗号化 | C | ✅ | |
| イベントの Webhook の購読を API で管理 | P | ✅ | ADR 0100（`event_subscriptions`）。設定ファイルの EventSink も残る |
| FIPS 140-3 | C | ❌ | |

## 11. 運用と基盤

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| PostgreSQL・Redis・複数インスタンス | P C | ✅ | |
| 署名付きイメージ、SBOM | C | ✅ | |
| HSM・クラウド KMS の KeyStore（AWS、GCP、Vault、PKCS#11） | C P | ❌ | |
| MySQL の Storage | P | ❌ | |
| メトリクス・トレース | P C | ❌ | |
| Helm チャート、Kubernetes Operator | P | ❌ | |
| 役割ごとのプロセス（ADR 0091） | P | ❌ | |

## 12. 拡張性

| 項目 | 出どころ | 状態 | メモ |
| --- | --- | --- | --- |
| フロー フック | P | ✅ | |
| アダプタの自己登録、ビルド時に選ぶフィーチャー | P | ✅ | |
| 認証方式のプラグイン（ADR 0090） | P | △ | ポート・汎用の認証情報・汎用の HTTP（ADR 0092）。TOTP・パスワード（ADR 0101）と passkey（ADR 0106）は移した |
| 画面のテーマ、i18n | P | △ | |
| 通知の文面のテンプレートと SMTP | P | ⛔ | ADR 0031 |
