# 0105. ログインの守りは、アカウント単位のロックアウト・端末の記憶・ログインのリスクの点数・ボット対策の 4 つのフィーチャーに分ける

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 4.1、4.9、10章、11.17、[0007](0007-auth-warnings.md)、[0031](0031-notifier-ids-only.md)、
  [0045](0045-internal-and-external-ids.md)、[0050](0050-second-factor.md)、[0073](0073-build-and-feature-toggle.md)、
  [0081](0081-flow-hooks.md)、[0084](0084-auth-context-and-risk-in-authz.md)、[0089](0089-enterprise-full-scope.md)、
  [0093](0093-acr-aal-step-up.md)

## 背景

roadmap の M9 の「リスクに応じた追加認証、新しい端末の検知、ボット対策、アカウント単位のロックアウト」（ADR 0089、
[scope.md](../scope.md) の 2 章）。今あるものは次のとおり。

- レートリミット（`security.login.rate_limit`）：固定窓で、メールアドレスと接続元ごと（`per_account`）、メールアドレスごと
  （`per_account_total`）、接続元ごと（`per_ip`）に要求の**回数**を数える。失敗だけを数えるのではなく、窓が過ぎれば元に戻る。
  繰り返し失敗しても待ち時間は延びず、運営者が状態を見たり解いたりする手段も無い
- リスク（ADR 0084）：セッションに種類ごとの点数を持ち、条件（`risk_below`・`risk_at_most`）で操作を絞れる。点数を入れるのは
  フック `post_authentication` と評価器の管理 API だけで、IAM 自身はリスクを評価しない
- step-up（ADR 0093）：条件の `any` の中の `aal_at_least` を満たさなければ、判定の API が `step_up` を返す
- 警告（ADR 0007）：design.md 10 章の表に `new_device` があるが、評価するルールが無い
- ボット対策は無い

決めることは、(1) ロックアウトの数え方と、アカウントの有無を漏らさない応答、(2) 端末をどう覚え、何を知らせるか、
(3) IAM がどのリスクを評価し、どう step-up につなぐか、(4) CAPTCHA などの確認をどこで、いつ求めるか、(5) フィーチャーの分け方。

## 決定

### フィーチャー

4 つに分け、すべて既定でオフにする。オフなら今までと同じに動く。

| フィーチャー | 依存 | オンのとき |
|---|---|---|
| `account_lockout` | ― | パスワードと 2 要素目のコードの失敗を数え、待ち時間とロックをかける |
| `device_recognition` | ― | 端末の Cookie で端末を覚え、新しい端末を知らせ、本人が一覧・削除できる。警告 `new_device` を評価する |
| `login_risk` | `device_recognition` | ログインのときにリスクの種類 `device`・`ip` の点数をセッションに入れる |
| `bot_protection` | ― | ログインの入口でボットの確認（CAPTCHA・Turnstile など）を求める |

運用で選び方が違う（ロックアウトだけ欲しい、ボットの確認は外部の契約が要る、など）ので 1 つにまとめない。リスクの点数は
端末の記録を材料にするので `device_recognition` に依存する。

### アカウント単位のロックアウト（`account_lockout`）

- 数えるのは推測で当てられる照合の**失敗**だけ：パスワードのログイン（メールアドレスのブラインドインデックスごと）と、2 要素目の
  コード（TOTP と、汎用の認証方式の 2 要素目。ユーザーごと）。接続元を問わずに数える（接続元を変えても続きから数える）
- メールのコード・リンク、passkey、外部 IdP は数えない。メールのフローは回数の上限とフローごとの試行の上限を持ち、passkey は推測で
  当てられない。ロックされたアカウントでも本人はメールや passkey で入れる（第三者に本人を締め出させない）
- 段階
  - `delay_after` 回目の失敗から、次に試せるまでの待ち時間（`base_delay` から倍々、`max_delay` まで）をかける
  - `window` の内に `threshold` 回失敗すればロックする。ロックの長さは `lock_duration` から、続けてロックされるたびに倍々
    （`max_lock_duration` まで。ロックの回数は、最後のロックが明けてから `max_lock_duration` の間覚えておく）
  - 成功すれば失敗の回数と待ち時間を消す（ロックの回数は残す）
- 待ち時間とロックの間は照合をせずに `429 rate_limited`（`Retry-After`）を返す。レートリミットと同じ応答で、区別できない
- アカウントの有無を漏らさない：パスワードはメールアドレスのブラインドインデックスで数えるので、無いアドレスも同じ回数で同じように
  ロックされる。応答の形・状態コード・`Retry-After` は有無で変わらない。応答時間は `min_response_time` で揃える（4.9）
- 状態は EphemeralStore に置く（レートリミットと同じ。複数インスタンスでは共有できるストアが要る）。Storage には書かない
  （失敗のたびに DB に書かない。消えても守りが一時的に緩むだけで、レートリミットは残る）
- 監査ログ：ロックしたとき `account.locked`（`scope`（`password` / `second_factor`）・`until`・`level`。アカウントがあるときだけ。
  無いアドレスのロックは記録しない）、運営者が解いたとき `account.unlocked`
- 管理 API：`GET /v1/admin/users/{user_id}/lockout`（状態）と `POST /v1/admin/users/{user_id}:unlock`（ユーザーのすべての
  メールアドレスと 2 要素目のロック・待ち時間・失敗の回数・ロックの回数を消す）。権限は運営者による認証情報の無効化と同じ `credentials:revoke`（owner・admin・security）
- フィーチャーを止めても EphemeralStore の状態は期限で消えるので、片付けは要らない

### 端末の記憶（`device_recognition`）

- 端末は Cookie `__Host-iam_device`（realm ごと。`Secure`・`HttpOnly`、寿命 `security.devices.cookie_ttl`、
  既定 400 日）の 256 bit の乱数で見分ける。Cookie はブラウザに 1 つで、ユーザーには結び付けない。認証の Cookie ではない（これだけでは
  何もできない）ので `SameSite=None` にし、外部 IdP からのクロスサイトの POST（SAML の ACS）でも送らせる
- 保存するのは乱数のブラインドインデックス（HMAC。Cookie の値そのものは持たない）で、表 `authn_known_devices`（SQLite 00049、
  PostgreSQL 00032）にユーザーごとに 1 行。Cookie を偽っても、乱数を知らなければほかの人の端末にはなれない。署名付きの Cookie
  （値を IAM が作り、MAC を付ける）と同じ守りを、鍵の管理を増やさずに得る
- 端末の詳細（User-Agent、IP、国・ASN・座標、強い認証で確かめたか）はユーザーのデータ鍵で暗号化して置く（9.5。削除で
  クリプトシュレッドされる）
- 記録は本人確認を終えたログイン（制限の無いセッションの発行）のときだけ。2 要素目を待つ間は記録しない
  - 知っている端末なら最終の利用時刻と詳細を更新する
  - 知らない端末なら行を作る。ユーザーが前に端末を 1 つ以上持っていたときだけ「新しい端末」とし、通知 `new_device_login`
    （ID だけ。`user_id` と `device_id`。ADR 0031）を積み、監査ログ `device.added` に `new: true` を残す。初めての端末
    （登録の直後や、フィーチャーを有効にした後の最初のログイン）は知らせない
  - ユーザーごとの上限（`security.devices.max_per_user`、既定 50）を超えれば、最後に使った時刻の古いものから消す
- 警告 `new_device`（既定 ignore）を評価する。`deny` は設定できない（拒めば端末が記録されず、二度と入れない）
- 公開 API：`GET /v1/me/devices`（一覧。今の端末に `current`）、`DELETE /v1/me/devices/{device_id}`（忘れる。監査ログ
  `device.forgotten`）。忘れた端末で次に入れば新しい端末になる
- 統合（11.6）では統合元の端末を忘れる。フィーチャーの無効化では行を消す

### ログインのリスク（`login_risk`）

- IAM の組み込みの評価器として、ログイン（制限の無いセッションの発行）のときに 2 つの種類の点数を出す（ADR 0084 の組み込みの種類）
  - `device`：強い認証（AAL2 以上。ADR 0093）で確かめた端末は 0、知っているが確かめていない端末は `unconfirmed_device_score`
    （既定 30）、新しい端末（初めての端末を含む）は `new_device_score`（既定 60）。点数はそのログインの前の状態で決め、
    AAL2 以上のログインはその後の端末を「確かめた」にする
  - `ip`：GeoIP のポートで接続元の国・ASN・座標を引く。前に使った端末のどれにも無い国なら `new_country_score`（既定 70）、
    無い ASN なら `new_asn_score`（既定 30）、最後に使った端末の場所から `max_speed_kmh`（既定 1000）を超える速さでないと
    来られなければ `impossible_travel_score`（既定 90）。大きい方をとる。GeoIP が無いか引けなければ `ip` は評価しない
- 点数は realm の一覧（ADR 0084）で有効な種類だけ入れ、フック `post_authentication` の点数と種類ごとに大きい方をとる。
  監査ログ `session.risk_updated` に `source: login_risk` で残す
- 「リスクが高ければ step-up」は新しい仕組みを作らず、ADR 0084 の条件と ADR 0093 の step-up で書く。例：名前空間の要件
  `any(risk_at_most(device, medium), aal_at_least(2))` は、新しい端末から 1 要素で入ったセッションには満たさず、判定の API は
  `step_up`（`acr_values=urn:iam:aal2`）を返す。連携先は `acr_values` を付けて authorize をやり直し、2 要素目で入り直せば満たす
  （2 要素目の無いユーザーは満たせない。0093 と同じ）。IAM 自身の本人の重要な操作も名前空間 `me` の要件で同じことができる
- 同じ端末でもう一度 1 要素で入り直しても、その端末は「確かめていない」ままなので `device` は下がり切らない（新しい端末 60 →
  確かめていない 30）。しきい値を 30 未満にすれば、強い認証を一度通るまで step-up を求め続けられる
- GeoIP はポート `GeoIP`（`Lookup(ip)` → 国・ASN・座標）。アダプタは CIDR の表を読む `static`（CSV）を置く。MaxMind の
  データベースのアダプタは依存が増えるので別のモジュールで後から足す

### ボット対策（`bot_protection`）

- ポート `BotVerifier`（`Verify(token, remote_ip)`）。アダプタは汎用の siteverify（`POST` で `secret`・`response`・`remoteip` を
  送り、JSON の `success` と、設定すれば `hostname` を確かめる。Cloudflare Turnstile・hCaptcha・reCAPTCHA に共通の形）と、
  開発用の `dev`（設定した値だけを通す。`dev: true` でだけ作れる）
- 確認を求めるのはログインの入口：`POST /v1/login/email:start`・`/v1/login/password`・`/v1/login/methods/{method}:complete`・
  `/v1/recovery/email:start`・`/v1/recovery/code:redeem`。トークンはヘッダー `IAM-Bot-Token` で受ける（本文の形を変えない）
- `mode`
  - `always`：いつも求める
  - `suspicious`（既定）：接続元（IPv6 は /64）の、`window` の内のログインの失敗（パスワード・メールのコード・リカバリーコード・
    認証方式・2 要素目の 401 と 429）が `after_failures` 回以上のときだけ求める
- 足りない・確かめられないときは `403 bot_check_required`。検証の障害（タイムアウトなど）も通さない（fail-closed）
- ホスト型のログイン画面はまだウィジェットを出さない。`always` にするのは、自前の画面からトークンを送る構成だけにする

### 設定

```yaml
security:
  lockout:        { threshold: 10, window: 15m, lock_duration: 15m, max_lock_duration: 24h, delay_after: 3, base_delay: 1s, max_delay: 30s }
  devices:        { cookie_ttl: 400d, max_per_user: 50, notify: true }
  login_risk:     { new_device_score: 60, unconfirmed_device_score: 30, new_country_score: 70, new_asn_score: 30,
                    impossible_travel_score: 90, max_speed_kmh: 1000 }
  bot_protection: { mode: suspicious, after_failures: 5, window: 10m }
geoip:      { driver: static, file: /etc/iam/geoip.csv }
bot_check:  { driver: siteverify, url: https://challenges.cloudflare.com/turnstile/v0/siteverify, secret_env: IAM_BOT_SECRET }
```

`bot_protection` が動いていて `bot_check` が無ければ起動しない。`login_risk` で `geoip` が無ければ `ip` を評価しない（警告を出す）。

## 結果

- 推測の失敗が続くアカウントは、接続元を変えても待たされ、ロックされる。運営者は状態を見て解ける。無いアカウントも同じに扱うので、
  応答からアカウントの有無は読めない
- 本人はメールのコードや passkey で入れるので、第三者がロックで本人を締め出すことはできない（パスワードと 2 要素目のコードだけが止まる）
- 新しい端末からのログインを本人に知らせ、本人は覚えた端末を見て消せる。端末の一覧はユーザーごとに上限があり、ログインのたびに
  1 行書く
- `device`・`ip` の点数が ADR 0084 の条件で使えるようになり、step-up は 0093 のまま連携先に返る。IAM の中に「リスクが高ければ
  何をするか」の別の規則を足さない
- ロックアウトとボットの確認の状態は EphemeralStore にあるので、memory のままでは再起動で消え、インスタンスごとに数える
  （`server.multi_instance` の検査で防ぐ）
- フィーチャーを有効にした直後は、どのユーザーにも端末の記録が無い。最初のログインの端末は知らせず、`device` の点数は新しい端末の
  ものになる
- ホスト型のログイン画面は CAPTCHA のウィジェットを出さないので、`bot_protection` の `suspicious` で確認を求められた接続元は、
  ホスト型の画面からはパスワード・メールのログインを始められない（passkey と外部 IdP は入口に含めないので使える）

## 検討した代替案

- **ロックアウトをユーザーの行（Storage）に持つ**：再起動でも消えないが、失敗のたびに DB に書き、無いアカウントには書く場所が無い
  （有無で振る舞いが変わる）。レートリミットと同じ EphemeralStore にする
- **ロック中は 401 を返す**：パスワードが正しいかを試させない点は同じだが、正しいパスワードで 401 を返すと本人が理由を誤解する。
  レートリミットと同じ 429 にする
- **ロックでアカウント全体を止める（メールのログインも）**：第三者が本人を締め出せる。推測で当てられる手段だけを止める
- **端末を汎用の認証情報（`authn_credentials`）に入れる**：表は増えないが、本人と運営者の認証手段の一覧・復旧の「後から足した
  手段」の判定・全手段の無効化に端末が混ざる。端末は認証の手段ではないので表を分ける
- **署名付きの Cookie に端末 ID を入れる**：署名の鍵の管理とローテーションが増える。乱数を Cookie に置き、ブラインドインデックスで
  引けば同じ守りになる
- **端末の指紋（ブラウザの特徴量）**：変わりやすく、プライバシーの懸念が大きい。Cookie だけにする
- **ログインのときにリスクが高ければ IAM が 2 要素目を求める**：2 要素目を登録したユーザーは今でもいつも求められる（4.1）ので
  変わらず、登録していないユーザーには求めようがない。操作ごとの条件と step-up（0084・0093）の方が、サービスごとにしきい値を決められる
- **CAPTCHA のトークンを本文に入れる**：エンドポイントごとに本文の形が変わる。ヘッダーなら入口の前でまとめて確かめられる
- **ボットの確認の障害で通す（fail-open）**：外部の障害のときに守りが外れる。止めて、運営者が `bot_protection` を止めて戻す
