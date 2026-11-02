# 0112. PAR・AS メタデータ・Protected Resource Metadata を足し、自前の API に向けたトークンは realm に登録したリソースに限って resource で 1 つ選ぶ

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.5、5.10、11.0、11.2、[0021](0021-opaque-access-tokens.md)、[0074](0074-service-accounts.md)、
  [0089](0089-enterprise-full-scope.md)、[0099](0099-token-exchange.md)

## 背景

roadmap の M11 のうち、次の 3 つ（[scope.md](../scope.md) の 4 章・5 章）。

- PAR（RFC 9126）：認可要求のパラメーターをブラウザを通さずにバックチャネルで送る。FAPI 2.0 の前提で、パラメーターの改ざんと
  漏えい（URL の長さ・ログ）を防ぐ
- OAuth 2.0 Authorization Server Metadata（RFC 8414）と Protected Resource Metadata（RFC 9728）：OIDC 以外のクライアント
  （MCP のクライアントなど）が AS とリソースを見つける
- 自前の API に向けたトークン（Resource Indicators、RFC 8707）：ホスト先が自分の API をリソースサーバーにし、IAM が `aud` と
  スコープを付けたトークンを出す。人（認可コードフロー）と機械（サービスアカウントの client credentials）の両方

今あるものは次のとおり。

- アクセストークンは不透明（ADR 0021）で、リソースサーバーはイントロスペクション（RFC 7662）で確かめる。`aud` は連携先の
  client_id だけ。Token Exchange（ADR 0099）は連携先ごとの許可の中から aud を選べる（`resource` も受ける）
- サービスアカウントのトークン（`sat_…`、ADR 0074）は管理 API 専用で、発行は管理 API の `POST /v1/admin/token`
- 認可要求と認可コードは EphemeralStore に封をして置く

決めることは、(1) PAR の受け付けと必須にする単位、(2) メタデータの中身と置き場所、(3) リソースの登録の形と、誰がどの
リソースを要求できるか、(4) client credentials の入口、(5) 取り消し・無効化の効き方。

## 決定

### フィーチャー

- `par`（既定オフ。登録は `features/par`）と `resource_indicators`（既定オフ。`features/resourceindicators`）。依存は無い
- メタデータ（RFC 8414・9728）は常に出す（中身は Discovery と同じで、新しい力を足さない）

### PAR（RFC 9126）

- `POST /oauth2/par`（フィーチャーがオフなら 404）。連携先の認証は token エンドポイントと同じ方法（`client_secret_basic`・
  `client_secret_post`・`private_key_jwt`、公開の連携先は `client_id` だけ）。`private_key_jwt` の `aud` は PAR・issuer・token の
  どれでもよい
- パラメーターは本文だけから読む。`request_uri` は拒み（`invalid_request`）、`request`（JAR）は `request_not_supported`
- authorize と同じ規則（op の確かめと IAM の規則：`openid`、PKCE S256、戻り先、スコープ、acr、`resource`）でその場で確かめ、
  誤りは token エンドポイントと同じ形の JSON で返す（戻り先には転送しない）
- 通ればクライアントの認証の項目を除いたパラメーターを、認可コードと同じく EphemeralStore に封をして預け（キーは秘密の
  SHA-256、16 KiB まで）、`201` で `request_uri`（`urn:ietf:params:oauth:request_uri:<秘密>`）と `expires_in` を返す。
  寿命は設定の `oidc.par_request_uri_ttl`（既定 1 分、10 分まで）
- authorize の `request_uri`：1 回だけ取り出し、realm・`client_id`・期限が合わなければ `invalid_request_uri`（理由は返さない。
  取り出したものは合わなくても二度と使えない）。預けたパラメーターだけを認可要求として読み、ブラウザから来たほかの
  パラメーターは見ない。待つ間に連携先の登録が変わってもよいよう、authorize の確かめは最初からやり直す。フィーチャーが
  オフなら `request_uri_not_supported`
- 必須にする単位は連携先（`require_pushed_authorization_requests`）と realm（realm の設定、既定の realm は設定ファイルの
  `realm.require_pushed_authorization_requests`）。どちらかが真なら、PAR を通らない認可要求を戻り先に転送せずに拒む。
  フィーチャーがオフのときに真にはできない（`400`）。Discovery の `require_pushed_authorization_requests` は realm の値
- Discovery に `pushed_authorization_request_endpoint` を載せる（フィーチャーが動いているときだけ）

### メタデータ

- `/.well-known/oauth-authorization-server`（RFC 8414）：OIDC Discovery と同じ内容（項目の名前と意味が同じで、issuer も同じ）。
  複数 realm（11.1）の issuer `…/realms/{slug}` には、RFC 8414 3 のとおり既知の場所を差し込んだ
  `/.well-known/oauth-authorization-server/realms/{slug}` でも答える（realm の issuer の下の場所でも答える）
- `/.well-known/oauth-protected-resource`（RFC 9728）：IAM 自身の API（UserInfo）のメタデータ。`resource` と
  `authorization_servers` は issuer。UserInfo の `401` の `WWW-Authenticate` に `resource_metadata` を付ける
- 自前の API のメタデータは IAM が出さない（リソースサーバーが自分で出す。`authorization_servers` に IAM の issuer を書けばよい）

### リソースの登録

- 表 `authn_oauth_resources`（SQLite 00062、PostgreSQL 00045）。realm ごとに `uri`（`resource` の値で `aud` になる。realm の中で一意）、
  `name`、`scopes`、`clients`（認可コードフローで要求してよい連携先の client_id）、`service_accounts`（client credentials で
  要求してよいサービスアカウント）。外部 ID は `rsc_…`
- `uri` は https（ループバックは http も）の URL か URN。クエリ・フラグメント・userinfo は受けない（RFC 8707 2）。完全一致で引く
- スコープは RFC 6749 3.3 の scope-token。OIDC と IAM 自身のスコープ（`openid`・`email`・`profile` など）は使えない
- 管理 API `/v1/admin/oauth/resources`（作成・一覧・取得・置き換え・削除。権限 `clients:manage`、フィーチャーがオフなら
  `404 resource_indicators_disabled`）。監査ログ `oauth_resource.created`・`updated`・`deleted`
- 許すのは「この主体はこのリソースを要求してよい」だけで、主体ごとにスコープを絞らない。スコープはリソースの全部から選べる

### 認可コードフロー

- authorize（PAR を含む）の `resource` は 1 つだけ。リソースが登録されていて、この連携先に許されていること。どれかが駄目なら
  `invalid_target` を戻り先に返す（`state` 付き）。`openid` は今までどおり要る（ID トークンは今までどおり連携先に出す）
- 認可のスコープは IAM のスコープとリソースのスコープの中から選ぶ。認可（grant）の `audiences` にリソースの URI を置き、
  アクセストークンのイントロスペクションの `aud` はその URI になる
- token エンドポイント（コードの交換・リフレッシュ）の `resource` は、認可で選んだものと同じ 1 つだけ受ける（替える・足すことは
  できない）。違えば `invalid_target`。リフレッシュはリフレッシュトークンを使う前に確かめる（誤った要求で系列を進めない）
- リソースに向けたアクセストークンは UserInfo で使えない（`aud` が IAM ではない）
- Token Exchange（ADR 0099）の元のトークンがリソースに向けたものなら、その `aud` はリソースの URI のまま
- Device Authorization Grant（11.16）では `resource` を受けない

### サービスアカウントの client credentials

- 入口は今の `POST /v1/admin/token`（ADR 0074）のまま。`resource`（1 つだけ）と `scope`（空白区切り。リソースのスコープの
  部分集合、省けば全部）を足す。応答に `scope` を返す
- 出すトークンは今と同じ `sat_…` で、`authn_service_account_tokens` の `audience` と `scopes`（SQLite 00063、PostgreSQL 00046）に
  持つ。`audience` のあるトークンは管理 API の Bearer では使えない。`/oauth2/introspect` で `active: true`・`aud`・`scope`・
  `sub`（サービスアカウントの ID）を返す（管理 API 向けのトークンは今までどおり `active: false`）
- フィーチャーがオフのときの `resource` は `invalid_target`（無視すると、リソースのつもりの要求に管理 API のトークンを渡すことになる）

### 取り消しと無効化

- 使うたび（イントロスペクション・リフレッシュ）に、リソースがまだあり、主体がまだ許されていて、フィーチャーが動いていることを
  確かめる。リソースの削除、連携先・サービスアカウントを許可から外すこと、フィーチャーの無効化は、発行済みのトークンにも次の
  検証から効く（fail-closed）
- リソースのスコープを変えても、発行済みの認可とトークンのスコープは変えない（新しい認可から効く）
- `par` の無効化（11.12）：連携先と realm の PAR の必須を外す。預けた `request_uri` は期限で消える
- `resource_indicators` の無効化：リソースの登録を消す。リソースに向けた認可・トークンの行は消さない（上のとおり使えなくなり、
  寿命で消える）

## 結果

- FAPI 2.0 に向けて、認可要求をバックチャネルで送り、連携先か realm の単位で PAR を必須にできる
- OIDC を知らない OAuth のクライアントも、RFC 8414・9728 で AS とリソースを見つけられる
- ホスト先は自分の API をリソースとして登録し、人と機械の両方に `aud` とスコープを付けた不透明なトークンを出せる。リソース
  サーバーはイントロスペクションで `aud` とスコープを確かめれば、ほかの API や IAM 自身に向けたトークンを受けずに済む
- 1 つの認可で向けられるリソースは 1 つ。複数の API を呼ぶ連携先は、API ごとに認可を取るか Token Exchange で替える
- 主体ごとのスコープの絞り込みは無い（リソースを分けて表す）
- client credentials が `/oauth2/token` に無いため、汎用の OAuth クライアントのライブラリは token エンドポイントの場所を
  `/v1/admin/token` に向ける必要がある。メタデータの `grant_types_supported` に `client_credentials` は載せない
- 無効化しても、リソースに向けた認可の行は寿命まで残る（使えないことは検証で保証する）

## 検討した代替案

- **client credentials を `/oauth2/token` で受ける**：連携先（clients）とサービスアカウントの 2 つの主体が同じ入口に並び、
  client_id の名前空間と認証方式の確かめを分ける必要が出る。ADR 0089 でサービスアカウントの入口は管理 API に置いたので、
  そこに `resource` を足す
- **複数の `resource` を 1 つの認可で受ける**：RFC 8707 は許すが、アクセストークンの `aud` が複数になり、リソースサーバーが
  ほかの API にも使えるトークンを受け取ることになる。トークンをリソースごとに分けるため 1 つに限る
- **主体ごとにスコープを許す（clients × scopes の表）**：表が大きくなり、管理 API と確かめが複雑になる。必要ならリソースを
  分けて登録すれば足りる
- **フィーチャーがオフでも client credentials の `resource` を無視する**：利用者がリソース向けのつもりで管理 API の
  トークンを受け取る。拒む方が安全
- **無効化でリソースに向けた認可・トークンを消す**：件数が多く、消すまでの間も検証で弾く必要は残る。検証で fail-closed にし、
  行は寿命で消す
- **PAR の必須を連携先の登録だけにする**：FAPI 2.0 では AS 全体で求めることが多い。realm の設定と設定ファイルでも選べるようにする
- **Device Authorization Grant でも `resource` を受ける**：端末で選んだリソースを利用者の画面で見せる必要があり、今回の範囲を超える。後に回す
