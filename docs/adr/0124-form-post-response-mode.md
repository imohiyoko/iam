# 0124. `response_mode=form_post` は既定オフのフィーチャーにし、応答を 1 回限りで預けて自動 POST の画面で返す

- 状態: 承認
- 日付: 2026-11-11
- 関連: [design.md](../design.md) 5.1、11.0、[oidc-conformance.md](../oidc-conformance.md)、[0089](0089-enterprise-full-scope.md)、
  [0122](0122-rs256-id-tokens.md)、[0123](0123-jwt-access-tokens.md)

## 背景

認可応答は `query` だけで返してきた。ASP.NET（OpenIdConnect のミドルウェアの既定）、Spring Security の一部の設定、
多くの SaaS の SSO の設定は `response_mode=form_post`（OAuth 2.0 Form Post Response Mode）を前提にし、`query` を選べないものもある。
`form_post` は認可コードをブラウザの履歴・Referer・アクセスログの URL に残さない利点もある。ADR 0089 は互換のための仕組みを
既定オフのフィーチャーにすると決めた。

## 決定

- フィーチャー `form_post`（既定オフ）。オンなら Discovery の `response_modes_supported` に `form_post` を足し、認可要求の
  `response_mode=form_post` を受ける。`query` は今までどおり。`fragment` は扱わない（`response_type` は `code` だけのため）
- 認可エンドポイントは転送を返すので、応答（`code`・`state`・`iss`、またはエラー）と送り先を EphemeralStore に 1 回限り・1 分で預け、
  `/oauth2/authorize/form_post` の画面へ転送する。画面は値を取り出して消し、redirect_uri へ自動で POST するフォームを返す
- ログインした後の応答はそのブラウザのセッション（`sid`）に結び付け、別のブラウザでは開けない。応答の値は redirect_uri が元から
  持つクエリを除いたもの（元のクエリは送り先の URL に残る）
- 画面は `Cache-Control: no-store`、`Referrer-Policy: no-referrer`、CSP の `form-action` を redirect_uri のオリジンに限り、
  スクリプトは自前の `formpost.js` だけ（インラインのスクリプトは使わない）。スクリプトが無ければボタンで送る
- エラーの応答（`prompt=none` の `login_required` など）も、要求が `form_post` なら同じ画面で返す
- フィーチャーが止まっていれば `response_mode=form_post` は今までどおり扱わず（`query` で返す）、画面は 404。持つデータは無い

## 結果

- `form_post` を前提にする RP（ASP.NET・一部の SaaS）がつながる。OIDC の適合試験の Form Post の構成も回せる
- 応答 1 回につき EphemeralStore への書き込みが 1 回、転送が 1 回増える

## 検討した代替案

- 認可エンドポイントから直接フォームを返す：zitadel/oidc の op は応答を転送で返す作りで、ログインの後の完了の経路と揃わない。
  預けて画面へ回せば、どの経路でも同じ処理になる
- フォームにインラインのスクリプトを置く：CSP の `script-src 'self'` を緩めることになる
- 既定でオンにする：既定の表面を小さく保つ方針（ADR 0089）に反する
