# 0093. 認証の強さは amr から AAL を求めて acr で出し、足りなければ step-up（RFC 9470）を求める

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.4、4.5、5.1、11.15、[0066](0066-oidc-authorization-code-flow.md)、[0069](0069-org-login-policy.md)、
  [0084](0084-auth-context-and-risk-in-authz.md)、[0089](0089-enterprise-full-scope.md)、[0090](0090-authenticator-plugins.md)

## 背景

認証の強さを外に伝える手段が `amr`（RFC 8176）しか無い。連携先や Org のポリシーは「`hwk` を含む」「要素が 2 つ以上」のように
手段の名前と数で書くしかなく、「NIST SP 800-63B の AAL2 以上」のような強さの言い方ができない。OIDC の `acr`・`acr_values`
（OpenID Connect Core 2、3.1.2.1、5.5.1.1）も扱っておらず、連携先がもっと強い認証を求める手段が `max_age` と `prompt=login` だけである。

保護された API が「今の認証では足りない」と返す標準の形として RFC 9470（OAuth 2.0 Step Up Authentication Challenge）がある。
IAM 自身の本人の重要な操作（`max_auth_age` と名前空間 `me` の要件。0084）は、足りなければ `401 reauthentication_required` を
返すだけで、何をすれば足りるかを伝えていない。

0090 で認証方式は自分の強さ（到達できる AAL）を宣言するようになる。それまでの間も、強さで書けるようにしたい（roadmap の M8。0089）。

## 決定

### フィーチャー

- フィーチャー `acr`（依存なし、既定でオフ）。オフなら今までどおり：`acr` を出さず、`acr_values`・`claims` を見ず、
  `WWW-Authenticate` を足さず、`aal_at_least` と `min_aal` を保存できない

### AAL の求め方

- AAL はセッションの `amr` から求める。対応表（`shared/acr` の `Methods`）は amr の値ごとに、要素の分類（知識・所持・生体・外部 ID）、
  検証者のなりすましに強いか（`PhishingResistant`）、鍵がハードウェアにあると確かめたか（`HardwareBound`）を持つ。0090 で方式が
  強さを宣言するようになれば、この表を方式の宣言で置き換える（引く側は `acr.AAL(amr)` のまま）
- 規則（SP 800-63B 4 章）
  - AAL1：数える手段が 1 つ以上
  - AAL2：分類の違う 2 要素以上で、うち 1 つが所持
  - AAL3：AAL2 で、検証者のなりすましに強くハードウェアに鍵がある手段を IAM で使った
  - 0：数える手段が無い（ログイン用リンク `link`、復旧 `rec`、サービスアカウントの手段など）
- 慎重に扱うもの
  - `hwk`（passkey）は検証者のなりすましに強い。ただし IAM は attestation を確かめず、同期する passkey と区別できないので
    `HardwareBound` にしない。今の方式では AAL3 に届かない（届く方式が対応表に入ったときに、自動で AAL3 を出す）
  - `mfa` の印は数えない。数えるのは使った手段の分類だけにする
  - `otp` はメールのコードと TOTP の両方に使っている。SP 800-63B はメールを認証器と認めないが、amr では区別できないので TOTP と
    同じ所持として数える。このため、メールのコードだけのセッションも AAL1 になる。メールのコードと TOTP は同じ分類なので
    AAL2 にならない（AAL2 はパスワードと TOTP、本人確認つきの passkey など）。メールのコードを分けるのは 0090 の方式の宣言で行う
  - `user` と生体は、所持の要素と一緒のときだけ数える（SP 800-63B 5.2.3）。`kba` は SP 800-63B が認めないので数えない
  - 外部 ID（`fed`）は分類の分からない 1 要素。`trust_upstream_amr`（0084）で足した `fed:<手段>` は分類としてだけ数え、
    検証者のなりすましへの強さとハードウェアには数えない（IAM が確かめていない）

### acr の値

- AAL は `urn:iam:aal1`・`urn:iam:aal2`・`urn:iam:aal3`。SP 800-63 の AAL には IANA の「Authentication Context Class Reference
  Values」に登録された値が無い。`http://idmanagement.gov/ns/assurance/aal/N` は特定の事業者の名前空間で、その定義への適合を名乗る
  ことになるので使わない。acr の値の意味は OP ごとに決めてよい（OpenID Connect Core 2）
- 検証者のなりすましへの強さは、IANA に登録された `phr`・`phrh`（OpenID Connect Extended Authentication Profile の ACR Values）を使う
- AAL1 に届かない認証は `0`（OpenID Connect Core 2）。返すだけで、要求には使えない
- Discovery の `acr_values_supported` は、対応表で届く値だけ（今は `urn:iam:aal1`・`urn:iam:aal2`・`phr`）。`claims_supported` に `acr`

### OIDC

- authorize は `acr_values` と、`claims` パラメーターの `id_token.acr`（`value`・`values`）を受ける。`claims` に acr があれば
  そちらを使う。`claims` のほかの項目は見ない（`claims` パラメーターそのものは 0089 の別のフィーチャー）。`claims` が JSON で
  なければ `invalid_request`
- 知らない値は捨てる（任意の要求。OpenID Connect Core 3.1.2.1）。残った値は要求の順に試し、最初に満たす値を `acr` にする
- `essential` かどうかは区別しない。どちらも、満たさなければ step-up を求め、ログインし直しても満たさなければエラーにする
  （任意の要求でも、連携先が求めたものを満たさないまま返すより、はっきり断る方が安全なため）
- 今のセッションが満たさなければ、要求を預かり、その時刻より後のログインを求めてログイン画面へ回す（`prompt=login` と同じ）。
  2 要素目を登録していれば、ログインで 2 要素目を求めるので強くなる。`prompt=none` なら `login_required`
- ログイン画面から戻っても満たさなければ（2 要素目が無い、強い方式で入らなかった）、連携先に
  `unmet_authentication_requirements`（OpenID Connect Core Error Code）を返す
- 要求が無ければ AAL の値（`urn:iam:aal<n>` か `0`）を `acr` にする
- 決めた `acr` は認可（`oidc_grants.acr`）に持ち、ID トークン（リフレッシュでも同じ値）・UserInfo・イントロスペクション
  （RFC 9470 6）に載せる。オフのときの認可は空にする。フィーチャーを止めた後は、前に作った認可でも載せない

### step-up（RFC 9470）

- 判定の結果（`check.Decision`）に `StepUp`（求める AAL と、認証からの経過の上限）を足す。満たさなかった条件のうち、
  `aal_at_least` の最大と `auth_within` の最小を集める（`any` は満たさなかった子をすべて集め、厳しい方に寄せる）。理由のコード
  （`unmet`）を返すときだけ返す（権限の有無を漏らさない規則は 0084 と同じ）
- 判定の API（`/v1/me:check`、`/v1/admin/authz:check`）は、`unmet` と一緒に `step_up`（`acr_values`・`max_age`）を返す。
  リソースサーバーはこれを `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…", max_age="…"` に
  載せて返せる
- IAM 自身の公開 API の本人の重要な操作は、直近の認証（`max_auth_age`）や名前空間 `me`・Org の要件を満たさずに 401 を返すとき、
  RFC 9470 の `WWW-Authenticate` を足す。`max_age` は効いている `max_auth_age`（か要件の `auth_within`）、`acr_values` は要件の
  `aal_at_least`。本文（`reauthentication_required`）と状態コードは変えず、追加の情報だけにする。ほかの 401（未ログインなど）には
  付けない。今のパスワードで `max_auth_age` の代わりにする操作で、通ったときは付けない

### ポリシーと条件

- 条件の言語（0084）に `aal_at_least(<n>)`（1〜3）を足す。理由のコードは `condition.aal`。文脈の `amr` から AAL を求める
  （申告の文脈なら申告の amr から。名前空間・Org の要件は今までどおり `attested()` を暗黙に AND する）。サービスアカウントの
  文脈（`sak`・`client_secret`・`private_key_jwt`）は AAL を持たない（0）ので、`aal_at_least` を満たさない。サービスアカウントにも
  通したい操作は `any` で書き分ける
- Org のログインポリシー（0069）に `min_aal`（1〜3）を足す。理由は `policy.min_aal`。判定は 0069 と同じくログインと切り替えのとき
- フィーチャーが止まっている間は、`aal_at_least` を含む条件と `min_aal` の新しい保存・変更を拒む（`invalid_condition`・
  `setting_invalid`）。保存済みのものをそのまま残す更新は受ける（ほかの項目の変更を止めない。0069 と同じ）
- 無効化（0073）：`min_aal` は数えて片付ける（`require_sso` と同じ。止めている間は判定しない）。`aal_at_least` の条件は残し、
  止めても判定し続ける。外すと緩むためで、運営者が条件を書き換えて外す。AAL は amr から求めるので、フィーチャーを含まない
  バイナリでも判定できる

## 結果

- 連携先・Org・サービスは「AAL2 以上」のように強さで書ける。0090 で方式の宣言に置き換えても、書いたポリシーは変わらない
- 連携先は `acr_values` で step-up を求め、ID トークンの `acr` で結果を確かめられる。保護された API は判定の API の `step_up` を
  RFC 9470 の形で返せる
- AAL は厳しめに出る。メールのコードと TOTP のログイン（今いちばん多い組み合わせ）は AAL1 で、AAL3 はまだ出せない。強さを
  正しく伝えるための制約として受け入れ、0090 で方式が宣言すれば上がる
- `acr_values` で強い認証を求めると、2 要素目の無いユーザーは連携先に入れなくなる（`unmet_authentication_requirements`）。
  連携先は要求を外すか、ユーザーに 2 要素目の登録を案内する
- 認可に列が 1 つ増える（SQLite 00037、PostgreSQL 00020）

## 検討した代替案

- **acr をセッションに保存する**：ログインのたびに書く値が増え、対応表を変えたときに古い値が残る。amr から毎回求め、連携先に
  渡した値だけを認可に持つ
- **`mfa` の印で AAL2 にする**：メールのコードと TOTP が AAL2 になり、SP 800-63B の要件（メールは認証器でない）を満たさない値を出す
- **passkey を AAL3 にする**：同期する passkey は鍵がハードウェアの外に出るので、AAL3 の要件（取り出せない鍵）を満たさない。
  attestation を確かめる方式を足すまで出さない
- **`http://idmanagement.gov/ns/assurance/aal/N` を使う**：広く使われているが、特定の事業者の定義への適合を名乗ることになる
- **満たせない acr_values でもそのまま返す**（OpenID Connect Core の任意の要求のとおり）：連携先が `acr` を確かめ忘れると、
  弱い認証のまま通る。断る方を既定にする
- **`reauthentication_required` を RFC 9470 の本文に置き換える**：既存のクライアントが壊れる。ヘッダーを足すだけにする
