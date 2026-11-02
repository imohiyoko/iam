# 0109. 本人の Personal Access Token は権限の名前のスコープで本人の権限を絞り、ハッシュだけを持つ不透明なトークンにする

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.5、4.6、4.11、5.1、11.2、11.18、[0021](0021-opaque-access-tokens.md)、
  [0045](0045-internal-and-external-ids.md)、[0064](0064-authz-roles-groups-check.md)、[0074](0074-service-accounts.md)、
  [0084](0084-auth-context-and-risk-in-authz.md)、[0089](0089-enterprise-full-scope.md)、[0092](0092-authenticator-port-implementation.md)

## 背景

roadmap の M9 の「本人の Personal Access Token」（ADR 0089、[scope.md](../scope.md) の 3 章）。人が CLI やスクリプトから、
自分として API を呼ぶためのトークンで、GitHub・GitLab・Okta などが持つ。今あるものは次のとおり。

- 管理 API の Bearer：運営者のセッションのトークン（`ses_….<秘密>`）か、サービスアカウントの API キー・アクセストークン
  （`sac_…`・`sat_…`。ADR 0074）。セッションは max_auth_age（4.11）の内でなければ使えず、スクリプトには向かない
- 連携先のアクセストークン（`atk_…`。ADR 0021）：リソースサーバーはイントロスペクション（RFC 7662）で確かめ、認可の判定の
  API（ADR 0064）に `access_token` を渡せば、IAM がトークンから認証の文脈（ADR 0084）を組み立てる
- サービスアカウントは人ではない主体で、本人の権限では動かない

決めることは、(1) トークンの形と持ち方、(2) スコープの語彙と「本人の権限を超えない」ことの保証、(3) どの経路で受け付けるか、
(4) realm のポリシー、(5) 片付け（取り消し・消去・統合・フィーチャーの無効化）。

## 決定

### フィーチャー

- `personal_access_tokens`（既定オフ）。コードは `authn/pat`、登録は `features/personalaccesstokens`
- オフなら公開 API・管理 API の PAT の操作は `404`、トークンはどの経路でも受け付けない（形が PAT でも、セッションや
  サービスアカウントの検証と同じく認証の失敗・`active: false`）
- 無効化（11.12）で、全 realm のトークンと realm のポリシーを消す

### トークンの形

```
iampat_<トークン ID の 26 文字>_<秘密 43 文字><検査 6 文字>
```

- 接頭辞 `iampat_` は秘密の走査（GitHub の secret scanning など）で見つけやすくするため。全体の長さ（83 文字）と文字の種類を
  固定し、正規表現 `iampat_[0-9A-HJKMNP-TV-Z]{26}_[0-9A-Za-z]{49}` で引っかけられる
- トークン ID は外部 ID（`pat_…`。ADR 0045）の 26 文字（Crockford Base32）。一覧・取り消し・監査ログはこの ID で指す
- 秘密は base62 の 43 文字（crypto/rand から棄却法で一様に取る。約 256 bit）
- 検査の 6 文字は、その前のすべての CRC32（IEEE）の base62。走査する側が秘密の照会なしに誤検知を減らせる（GitHub の
  トークンと同じ考え）。IAM は検査が合わなければ DB を引かずに拒む
- DB には秘密の SHA-256 だけを持ち、定数時間で照合する（5.2、ADR 0074 と同じ）。トークンは作ったときに1回だけ返す

### スコープ

- スコープは権限の名前（`<リソース>:<操作>`、`x:*` も可。4.11 の permRE）にする。IAM 自身の権限（`users:read` など）も、
  連携先の権限（ロールに入れて判定の API で確かめるもの）も同じ語彙で書く。1 個以上 20 個まで。重複は除き、順に並べて持つ
- **スコープは本人の権限を絞るだけ**：判定（authz/check）は認証の文脈 `AuthContext.Scopes` を持ち、それがあるときは、
  付与で許す操作のうちスコープに含まれる（`role.Covered`）ものだけを許す。`Holds`（付与・なりすましで「呼び出し側が
  すべて持つか」を見るところ）も、スコープに含まれない権限は持たないとみなす。判定のどの経路も、主体の文脈を渡せばこの絞り込みが効く
  （管理 API の各操作、`outranks`、ロールの付与、要件の自己締め出しの確認）
- 本人がスコープの権限を持っているかは作るときに確かめない。使うときに本人の今の権限と交わる（後から権限を外せばすぐ効く）
- `*` だけのような「すべて」は書けない（permRE が許さない）。管理 API を広く使うトークンでも、リソースごとに書く

### 受け付ける経路

| 経路 | 扱い |
|---|---|
| 管理 API の Bearer | 本人（ユーザー）として認証し、文脈は `amr: [pat]`・要素 1・`auth_time` はトークンの作成時刻・`Scopes`。運営者の max_auth_age は見ない（トークンの期限が代わり）。名前空間の要件（ADR 0084 の `auth_within` など）で、敏感な操作から PAT を締め出せる |
| 判定の API の `access_token` | 主体と同じユーザーのトークンなら、上と同じ文脈で判定する（スコープで絞る）。リソースサーバーは PAT でもアクセストークンと同じに問い合わせられる |
| イントロスペクション（RFC 7662） | `active`、`token_type: personal_access_token`、`sub`（本人の公開 ID）、`scope`（今効くスコープ）、`iat`、`exp`（期限があれば）、`iss`、`auth_time`、`amr`。`client_id`・`aud` は出さない（連携先に結び付かない。`aud` を確かめるリソースサーバーは受け付けない） |
| 公開 API（本人の API） | 受け付けない。PAT で PAT を作れず、本人の重要な操作（4.11 の `me:`）にも使えない |
| UserInfo | 受け付けない（OIDC の認可ではない） |

- 使うたびに、トークン（取り消し・期限）、本人（`account.Check`。作成の時刻から今までの停止も見る。セッションと同じで、
  停止をまたいだトークンは解除しても戻らない）、realm の今のポリシー（下）を確かめる。どれかが駄目なら理由を返さずに拒む
- 最後に使った時刻（`last_used_at`）を、前の記録から 1 分以上たっていれば書く（毎回は書かない）

### realm のポリシー

- realm ごとに `max_lifetime`（秒。0 なら無し）、`allowed_scopes`（空なら形だけ確かめる）、`require_expiry` を持つ。
  表 `authn_personal_access_token_policies`。設定ファイルの `personal_access_tokens.max_lifetime` はホスト先の上限で、realm は
  それより長くできない（2.8 と同じ考え。0 なら上限なし）
- 作るとき：期限は今より後で、効く上限（realm とホスト先の短い方）の内。上限があって期限を省けば、上限の期限を付ける。
  `require_expiry` で上限が無ければ、期限を省けない。スコープは `allowed_scopes` のどれかに含まれる（`role.Covered`）こと
- 使うとき：ポリシーを後から厳しくすれば、既存のトークンにもすぐ効く（作成から上限を過ぎたもの・期限の無いもの
  （`require_expiry`）は使えない。`allowed_scopes` から外れたスコープは効かず、効くスコープが無くなれば使えない）
- ユーザーごとの有効なトークンの数の上限は設定ファイルの `personal_access_tokens.max_per_user`（既定 50。`409 token_limit`）

### API

- 公開 API（セッション。フィーチャーがオフなら 404）
  - `GET /v1/me/personal-access-tokens`：一覧（取り消した・期限切れも含む。秘密もハッシュも返さない）
  - `POST /v1/me/personal-access-tokens`：作る（`name`・`scopes`・`expires_at`）。直近の認証（4.11 の `me:personal_access_tokens`。
    max_auth_age と名前空間 `me` の要件）が要る。`401 reauthentication_required` は他の本人の重要な操作と同じ
  - `POST /v1/me/personal-access-tokens/{id}:revoke`：取り消す（もう取り消していても 204）
  - `GET /v1/me/personal-access-token-policy`：作る前に上限と許すスコープを知るため
- 管理 API
  - `GET /v1/admin/users/{id}/personal-access-tokens`、`POST …/{token_id}:revoke`：権限 `credentials:revoke`（4.6 の認証情報の
    一覧と無効化と同じ）。取り消しは対象のロールの権限をすべて持つときだけ（`outranks`）
  - `POST /v1/admin/users/{id}/credentials:revoke-all`（侵害時の初動）は PAT も取り消し、数を `personal_access_tokens` で返す
  - `GET`・`PUT /v1/admin/personal-access-token-policy`：権限 `personal_access_tokens:manage`（realm:owner）
- 権限のリソース `personal_access_tokens` は IAM 自身の権限（ロールに入れて人に渡すには自分が持っている必要がある）

### 監査ログ

- `personal_access_token.created`（`token_id`・`scopes`・`expires_at`。名前は個人情報になりうるので載せない）
- `personal_access_token.revoked`（`token_id`・`user_id`・`reason`：`user`・`operator`・`revoke_all`・`merged`）
- `personal_access_token.policy_updated`（新しいポリシー）
- 管理 API を PAT で呼んだ操作の行為者は本人（`user` と公開 ID）

### 片付け

- 消去（4.10）で行を消し、統合（11.6）で統合元のトークンを取り消す。無効化（11.12）は全部消す
- 期限切れ・取り消し済みのトークンは本人と運営者の一覧に残す（自動では消さない）

### 汎用の認証情報（ADR 0092）を使わない理由

`authn_credentials` はログインの認証方式のための表で、データは本人のデータ鍵で暗号化し、方式は realm と方式に閉じた
ストアからしか見えない。PAT はログインの手段ではなく（セッションを作らない）、使うたびに ID で引き、期限・スコープ・最後に
使った時刻を平文の列で扱い、一覧と数え上げをする。`authn_credentials` に置くと、本人の認証手段の一覧（`/v1/me/methods`）や
2要素目の候補に混ざり、毎回の検証でデータを復号することになる。秘密はハッシュだけなので暗号化の利点も無い。専用の表にする
（SQLite 00056、PostgreSQL 00039）。

## 結果

- 人がスクリプトから自分として API を呼べ、トークンごとに使える権限を本人の権限の内側に絞れる。本人の権限を後から外せば、
  トークンもすぐに使えなくなる
- 漏れたトークンは接頭辞と検査の文字で見つけやすく、DB が漏れても秘密は戻せない
- 運営者が PAT で管理 API を使うと、max_auth_age の再認証を経ない。期限（realm のポリシー）、スコープ、名前空間の要件で抑える
- PAT で呼んだ管理 API の監査ログは、どのトークンで呼んだかを持たない（最後に使った時刻で追う）。監査の行為者に経路を足すのは後に回す
- `aud` を確かめるリソースサーバーは PAT を受け付けない。連携先に結び付けた PAT（audience を持つ）は後に回す
- 作成の同時の要求で、ユーザーごとの上限をわずかに超えることがある（数えるのと作るのを1つの文にしない）

## 検討した代替案

- **JWT の PAT**：取り消し・停止が期限まで効かない（ADR 0021 と同じ理由）
- **OAuth のスコープを別の語彙にする**：IAM の判定と対応付ける表が別に要り、「本人の権限を超えない」ことをどこで保証するかが
  ぼやける。権限の名前をそのまま使えば、判定の 1 か所で絞れる
- **作るときに本人がスコープの権限を持つかを確かめる**：作った後に権限が変わるので、使うときの交わりが要ることは変わらない。
  使うときだけにする（本人が持たないスコープは単に効かない）
- **ポリシーを realm の設定（`realms.settings`）に置く**：既定の realm の設定は設定ファイルが正で API から変えられない（ADR 0083）。
  PAT のポリシーは運営者が API で変えたいので、表に置く
- **サービスアカウントの API キーで足りる**：サービスアカウントは人ではなく、本人の権限の変化に追従しない。本人の退職・停止で
  止まらない
