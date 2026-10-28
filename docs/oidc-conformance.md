# OIDC の適合性メモ（M5）

OpenID Foundation の適合試験（Basic OP、`oidcc-basic-certification-test-plan`）の観点を、自動テストでどこまで確かめたかと、
既知の差異をまとめる。公式の試験の実行は、公開した環境（M6）で行い、結果をここに追記する。

## 自動テストで確かめている観点

| 観点（Basic OP の試験） | テスト |
| --- | --- |
| Discovery と issuer の一致、JWKS（`oidcc-discovery-*`） | `TestOIDCAuthorizationCodeFlow`、`TestOIDCE2EStandardRP`（zitadel/oidc の rp で Discovery から） |
| 認可コードフロー、ID トークンの署名とクレーム（`oidcc-server`） | `TestOIDCAuthorizationCodeFlow`、`TestOIDCE2EStandardRP`、`TestOIDCE2EMLDSARP` |
| client_secret_basic / post、private_key_jwt、none | `TestOIDCAuthorizationCodeFlow`（basic と post）、`TestOIDCPrivateKeyJWT`、`TestOIDCPublicClientMLDSAAndOrg` |
| nonce の受け渡しと、nonce なしの要求（`oidcc-ensure-request-without-nonce-*`） | `TestOIDCE2EMLDSARP`、`TestOIDCAuthorizationCodeFlow`（nonce なし）、`TestOIDCRefreshIntrospectRevoke`（リフレッシュの ID トークン） |
| UserInfo（GET と POST、Bearer）（`oidcc-userinfo-*`） | `TestOIDCAuthorizationCodeFlow`、`TestOIDCE2EStandardRP` |
| `prompt=none` で未ログインなら `login_required`、`prompt=login`（`oidcc-prompt-*`） | `TestOIDCAuthorizationCodeFlow` |
| `max_age`（`oidcc-max-age-*`） | `TestPKCEAndFreshness` |
| 認可コードの再利用の拒否（`oidcc-codereuse`） | `TestOIDCAuthorizationCodeFlow`、`TestFlowRequestAndCode` |
| 登録に無い redirect_uri の拒否（`oidcc-ensure-registered-redirect-uri`） | `TestOIDCAuthorizationCodeFlow` |
| state の受け渡し | `TestOIDCAuthorizationCodeFlow` |
| リフレッシュ（ローテーションと再利用検知）、イントロスペクション、失効 | `TestOIDCRefreshIntrospectRevoke`、`TestOIDCE2EStandardRP`（rs で RFC 7662） |
| Back-Channel Logout | `TestOIDCBackchannelLogout` |

## 既知の差異

- **RS256 で署名しない。** ID トークンは ES256 か ML-DSA-65（9.3）。Basic OP の試験は RS256 を前提にするので、ES256 で登録して
  実行する
- **PKCE を必ず求める。** 機密の連携先にも S256 を求める（OAuth 2.0 Security BCP）。PKCE を送らない試験は `invalid_request`
  で戻る。試験の設定で PKCE を有効にする
- **`response_mode` は `query` だけ。** `form_post`・`fragment`、`response_type` の `code` 以外は扱わない
- **`request` / `request_uri` パラメーター、`claims` パラメーターを受けない**（`oidcc-request-*`・`oidcc-claims-*` は対象外）
- **スコープは `openid` と `email` だけ。** `profile`・`address`・`phone` は無視し、そのクレームを返さない
  （`oidcc-scope-profile` などは警告になる）
- **同意画面を出さない。** 連携先はファーストパーティだけ（ADR 0026）。`prompt=consent` は無視する
- **動的クライアント登録をしない**（連携先は管理 API で登録する。M5 の対象外）
- リフレッシュで出す ID トークンには `nonce` を入れない（OIDC Core 12.2。最初の nonce を照合する RP では、リフレッシュの後の
  照合を外す）
- `offline_access` は扱わない（リフレッシュトークンもログインの系列に結び付く。ADR 0066）
