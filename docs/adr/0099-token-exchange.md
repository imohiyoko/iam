# 0099. Token Exchange（RFC 8693）で委任となりすましを扱い、交換したトークンを元の認可とログインの系列に結び付ける

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.7、11.0、[scope.md](../scope.md) 5・9 章、[0021](0021-opaque-access-tokens.md)、[0022](0022-deny-reason-disclosure.md)、
  [0031](0031-notifier-ids-only.md)、[0052](0052-admin-credential-revocation.md)、[0066](0066-oidc-authorization-code-flow.md)、
  [0084](0084-auth-context-and-risk-in-authz.md)、[0089](0089-enterprise-full-scope.md)

## 背景

連携先のサービスが、受け取った本人のトークンで、さらに下流のサービスを呼びたいことがある。今は受け取ったトークンをそのまま
渡すしかなく、下流は「誰が本人の代わりに呼んでいるか」を知れず、トークンの範囲も広すぎる。また、運営者がサポートのために
本人として動く手段（なりすまし）が無く、ログインリンクの発行（本人のセッションを作る）で代わりにするしかなかった。

どちらも RFC 8693（Token Exchange）で表せる。M11（ADR 0089）で、委任となりすましをフィーチャーとして足す。

## 決定

- token エンドポイントで `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` を受ける。発行するのは不透明な
  アクセストークン（ADR 0021）だけで、リフレッシュトークンと ID トークンは出さない。`requested_token_type` は `access_token`
  （省略可）だけ。交換を求められるのは機密の連携先（`client_secret` か `private_key_jwt`）だけ
- フィーチャーを2つに分ける。どちらも既定オフ
  - `token_exchange`：委任
  - `impersonation`：運営者のなりすまし（`token_exchange` に依存する）
- 連携先ごとの許可（既定は何も許さない）を管理 API の `GET/PUT /v1/admin/clients/{id}/token-exchange`（権限 `clients:manage`）で置く
  - `audiences`：発行するトークンの aud に選べるもの（この realm の連携先の client_id か、絶対 URI の資源）。空なら何も許さない
  - `subject_clients`：連携先自身のほかに、subject_token の aud として受け付ける連携先（ブラウザの連携先が受け取ったトークンを
    API の連携先が交換するとき）
  - `impersonation`：なりすましを許すか
  - 許可は `clients.token_exchange` に JSON で持つ。連携先の内容の置き換え（`PUT /v1/admin/clients/{id}`）では変えない。
    公開クライアントに変えたら消す
- 要求の `audience` と `resource`（RFC 8707）を合わせて aud にする。1 つ以上 5 つまでで、すべて許可の `audiences` に無ければ
  `invalid_target`。`scope` は元のトークンの範囲を超えられない（縮めるだけ。超えれば `invalid_scope`。省略なら元のまま）
- 委任
  - subject_token は IAM が発行したアクセストークンか ID トークン。トークンの aud（認可コードの認可は連携先、交換したトークンは
    その aud、ID トークンは `aud`）に、要求した連携先か `subject_clients` が無ければ `invalid_grant`
  - ID トークンは署名・`iss`・`exp`・`sid` を確かめ、ヘッダーの `typ` が `JWT` のものだけを受ける（同じ鍵で署名する Logout Token を
    取り違えない）。ID トークンにはスコープが無いので、交換したトークンのスコープは `openid` だけ
  - `actor_token`（任意）は、要求した連携先に発行した、交換していないアクセストークンだけ。行為者はそのユーザー
  - 発行するトークンは `act`（RFC 8693 4.1）を持つ。行為者は actor_token のユーザー（`sub` と `client_id`）、無ければ要求した
    連携先（`sub` に client_id）。交換したトークンをさらに交換したら、前の `act` を入れ子にする。重ねられるのは 4 回まで
  - 寿命は `oidc.access_token_ttl` で、元のトークンの期限を超えない
- なりすまし
  - subject_token は、運営者が要求した連携先（サポートの道具）にログインして得た、交換していないアクセストークン。本人は拡張の
    パラメーター `requested_subject`（ユーザーの公開 ID）で指す（Keycloak と同じ形）。`actor_token` とは併用しない
  - 判定の順：運営者ごとのレートリミット（`security.login.rate_limit.per_account`）、step-up（運営者のログインの系列の今のセッションが
    `oidc.impersonation.max_auth_age`（既定 5 分）以内に認証し、要素の数が `oidc.impersonation.min_factors`（既定 2）以上）、
    権限 `users:impersonate`（認証の文脈と名前空間の要件を含む。ADR 0084）、本人のロールの権限をすべて持つこと（outranks。ADR 0052）、
    本人が使えること（停止・有効期間・削除・削除の予定。自分自身は不可）
  - 本人の有無と状態は、権限と step-up を満たした運営者にだけ（拒んだ理由ではなく結果として）分かる。拒んだときは `invalid_grant` で、
    理由は返さない（ADR 0022）。step-up が足りないときだけ説明に `step-up authentication required` を入れ、連携先が運営者に再認証を
    促せるようにする。レートリミットは 429
  - 権限 `users:impersonate` は `realm:owner` だけに付ける。サポートの担当には独自のロールで渡す
  - 発行するトークンの `sub` は本人、`act.sub` は運営者。寿命は `oidc.impersonation.token_ttl`（既定 10 分、1 時間以下）で、
    元のアクセストークンの期限を超えない。Org の文脈は持たない（`org_id` を出さない）
  - 成功も失敗も監査ログ `oidc.impersonated` に残す（失敗は別のトランザクションで、理由を付けて）。本人には通知 `impersonated` を
    確認済みのメールごとに出す（宛先は claim で取り出させる。ADR 0031。復旧の完了と同じ形）
  - なりすましのトークンは、さらに交換しない
- 交換で作った認可（`oidc_grants`）に、種類（`exchange`）・元の認可（`parent_id`）・行為者（`actor_user_id`）・`act`・`audiences` を持つ
  - 検証（UserInfo・イントロスペクション・交換）では、今までの規則に加えて、元の認可をたどってどれも失効・期限切れでないことを
    確かめる。元の認可の失効（RFC 7009、リフレッシュトークンの再利用の検知）とログインの系列の終わりは、交換したトークンにも効く
  - 委任の系列は本人のもの。なりすましの系列は運営者のもので、運営者のログアウト・失効でも使えなくなる。本人が使えなくなれば
    （停止・削除・統合・削除の予定）なりすましのトークンも使えない
  - 系列が終われば交換の認可も失効させるが、Logout Token は送らない（なりすましの系列は本人のものではなく、委任の連携先は元の連携先と
    同じログインを見ている）
  - ユーザーの消去では、本人としての認可に加えて、行為者としての認可も消す。連携先の削除では、その連携先が交換した認可も消す
  - フィーチャーが止まっていれば、残っている交換のトークンは使えない（fail-closed）
- イントロスペクション（RFC 7662）は、交換したトークンに `act` と、交換の `aud` を返す。`client_id` は要求した連携先。なりすましの
  トークンには `impersonation: true` を付け、`sid` を出さない（運営者の系列を本人の sid として見せない）
- 監査ログ：委任は `oidc.token_exchanged`（本人が行為者。連携先・aud・スコープ・act）、許可の変更は `client.token_exchange_updated`
- Discovery の `grant_types_supported` には、`token_exchange` が動いているときだけ載せる
- フィーチャーの無効化：`token_exchange` は連携先の許可（なりすましの許可も）と交換の認可を、`impersonation` はなりすましの許可と
  なりすましの認可を片付ける

## 結果

- 下流のサービスは、イントロスペクションで本人と行為者（`act`）、自分向けの aud を確かめられる。元のトークンの失効・ログアウトが
  交換したトークンにすぐ効く
- 運営者のなりすましは、権限・outranks・直近の多要素の認証を満たし、記録と通知を残す。本人のセッションを作らないので、
  ログインリンクの発行より範囲が狭い
- 交換したトークンの検証では、元の認可をたどる分だけ問い合わせが増える（重ねられる回数で上限がある）
- なりすましの権限の取り消しは、発行済みのトークン（最長 `token_ttl`）には効かない。運営者のログアウトか、元の認可の失効で止める
- 交換したトークンはリフレッシュできない。期限が来たら、元のトークンで交換し直す。なりすましは step-up の期限ごとに運営者の
  再認証が要る

## 検討した代替案

- 交換の記録を別の表に持つ：検証のたびに表を引くことになり、フィーチャーを止めたときに印の無い交換の認可を本人の認可と取り違える
  おそれがある。認可の行に印を持てば、取り違えずに1回で読める
- なりすましを管理 API（`POST /v1/admin/users/{id}:impersonate`）で発行する：運営者は管理 API をセッションのトークンで使うので、
  サポートの道具（連携先）のログインと結び付かず、aud も決められない。Token Exchange にすれば、連携先・aud・系列の扱いが委任と同じになる
- なりすましで `act` を出さない（RFC 8693 の純粋な impersonation）：下流が運営者の操作だと分からず、支払いなどを止められない。
  記録付きのなりすましという要件に合わないので、`act` と `impersonation` を出す
- ID トークンと交換したトークンのリフレッシュトークンも出す：交換したトークンの寿命が元のトークンを超え、元の失効を待つことになる
