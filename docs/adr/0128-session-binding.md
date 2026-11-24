# 0128. ログインの後のセッションの端末・接続元の変化を見て、乗っ取りの兆候を記録し、リスク・失効・通知につなぐ

- 状態: 承認
- 日付: 2026-11-24
- 関連: [design.md](../design.md) 5.2、5.3、11.17、[0017](0017-session-id.md)、[0024](0024-session-validity-cache.md)、
  [0031](0031-notifier-ids-only.md)、[0063](0063-audit-client-data.md)、[0084](0084-auth-context-and-risk-in-authz.md)、
  [0088](0088-trusted-proxies.md)、[0093](0093-acr-aal-step-up.md)、[0105](0105-risk-based-login-protection.md)

## 背景

ログインのリスク（`login_risk`。ADR 0105）は**ログインの瞬間**の端末と接続元しか見ない。ログインの後にセッションの Cookie
（やセッションのトークン）が盗まれ、別のブラウザ・別の接続元から使われても、IAM は何も気づかない。セッションの検証
（`withSession`）はトークンの秘密が合えば通し、端末や接続元を比べない。

同じセッションの ID が、短い時間に別々の接続元・端末から使われる（「カチカチ変わる」）のは、セッションハイジャックの典型的な
兆候である。一方で、正当な利用でも接続元は変わる：モバイル回線（CGNAT で IP が入れ替わる）、Wi-Fi とモバイルの行き来、
IPv4 と IPv6 のデュアルスタック、VPN の付け外し、ブラウザの更新（User-Agent の版）。誤検知でログアウトさせると影響が大きい。

決めることは、(1) どこで何を比べるか、(2) 判定のホットパスを重くしない方法、(3) 誤検知の抑え方、(4) 見つけたら何をするか。

## 決定

### フィーチャー

`session_binding`（既定オフ。依存なし）。オフなら今までと同じに動く。端末の Cookie（`__Host-iam_device`）は
`device_recognition` が動いていれば比べ、動いていなければ User-Agent と接続元だけを見る。

### どこで、何を比べるか

- セッションの検証の後（`withSession`。公開 API・authorize・SAML の IdP・WS-Federation の入口）で、制限の無い**ユーザーの**
  セッションだけを見る（サービスアカウントは見ない）
- 起点はログインの系列（`sid`。ID を入れ替えても変わる）ごとに、**最初に見た要求**とする（ログインの応答が置いた端末の Cookie は
  次の要求から届く）。新しいログインは新しい系列なので、新しい起点から見る
- 兆候（それぞれ有効・無効、点数、アクションを設定する）

| 兆候 | 中身 | 既定の点数 | 上げるリスク |
|---|---|---|---|
| `device_changed` | Cookie のセッションが、起点と違う端末の Cookie で（または端末の Cookie 無しで）送られた。Cookie を盗まれて別のブラウザで使われた形。Bearer では端末の Cookie が届かないので比べない | 90 | `device` |
| `user_agent_changed` | User-Agent の種類（数字・`.`・`_` を除いたもの。ブラウザ・OS の更新では変わらない）が変わった | 60 | `device` |
| `country_changed` | 接続元の国が起点と変わった（GeoIP が要る） | 70 | `ip` |
| `asn_changed` | 国は同じで ASN が変わった（GeoIP が要る） | 30 | `ip` |
| `network_flapping` | `window`（既定 10 分）の内に `max_networks`（既定 4）以上の別々のネットワークから使われた | 70 | `ip` |
| `unfamiliar_network` | ユーザーが普段使う接続元の一覧（下記）に、CIDR も ASN も無いネットワークから使われた | 50 | `ip` |
| `unfamiliar_browser` | 系列が新しいネットワークから使われたとき、そのブラウザの種類が普段の接続元の一覧のどのネットワークでも使われていない | 50 | `device` |

- 「ネットワーク」は、GeoIP で ASN が引ければ ASN、引けなければ IPv4 の /24・IPv6 の /64 とする
- 兆候は系列ごとに**種類ごとに 1 回だけ**記録し、アクションを取る（同じ兆候で監査ログ・DB の書き込みを繰り返さない）
- 接続元は ADR 0088 の信頼できるプロキシの規則で決めた値を使う

### ユーザーが普段使う接続元の一覧

系列の中の変化だけでは、ログインの直後から攻撃者が使う場合や、ゆっくり移る場合を見られない。ユーザーをまたいで「普段どの
ネットワークから、どのブラウザで使うか」を覚え、比べる。

- 系列が新しいネットワークから使われるたび（ログインの後の最初の要求を含む。同じ系列で同じネットワークに居続ける間は数えない）に、
  接続元の **CIDR**（IPv4 は /24、IPv6 は /64）・ASN・国と、そこで使った**ブラウザの種類**（版の数字を除いた User-Agent。
  最後に見た User-Agent も）の回数・最初と最後に見た時刻を数える
- ユーザーごとに 1 行（`authn_network_profiles`）。中身は**ユーザーのデータ鍵で暗号化**する（9.5。ユーザーを消せば読めなくなり、
  行も消す。統合元の一覧は消す）。フィーチャーを止めれば片付けで消す
- 上限：ネットワークは `profile.max_networks`（既定 20）、ネットワークごとのブラウザは `profile.max_browsers`（既定 5）。超えれば
  最後に見た時刻の古いものから捨てる。`profile.retention`（既定 90 日）より長く見ていないものも捨てる
- 一覧の回数の合計が `profile.min_observations`（既定 5）に届くまでは `unfamiliar_*` を見ない（育つ前は何でも知らないものになる）
- `unfamiliar_*` を見るのは、一覧と比べるとき（系列が新しいネットワークから使われたとき）だけ。同じ系列で、同じネットワークのまま
  ブラウザの種類だけが変わったときは `user_agent_changed` が見つけ、`unfamiliar_browser` にはしない
- 知っているネットワークかは、**CIDR が同じか ASN が同じか**で決める（モバイル回線は同じ事業者の中で /24 が変わる）
- 比べて足すのは、兆候の記録と同じトランザクションで行う。系列が新しいネットワークから使われたときだけなので、Storage への書き込みは
  ログインごと・ネットワークの移動ごとに 1 回程度。一覧を読めない（鍵を消したユーザーなど）ときは、ほかの兆候の記録を止めない。
  系列の状態に、この系列で一覧に足し終えた（一覧と比べられ、トランザクションがコミットした）ネットワークを覚え、それ以外の
  ネットワークからの要求では比べ直す（失敗で `unfamiliar_*` の `revoke` を取り逃がさない）。足し終えたネットワークは、同じ系列の
  間は数えない。この記憶は `network_flapping` の数え上げとは別に持つ。数は抑え、長く使っていないものから捨てる（捨てたネットワークに
  戻れば一覧にもう一度数えるだけで、取り逃がしにはならない）
- 運営者は `GET /v1/admin/users/{id}/networks` で一覧を見る（権限 `users:read` と `audit:read_client_data`。接続元と
  User-Agent は監査ログの接続元と同じ扱い。監査ログ `user.pii_read`）。`profile.enabled: false` なら一覧を作らず、API は 404

### ホットパスを重くしない

- 状態（起点の端末の Cookie のハッシュ・User-Agent の種類のハッシュ・起点の国と ASN・最近見たネットワークの ID と時刻・
  知らせ済みの兆候）は EphemeralStore に、系列ごとに 1 つの値で置く。秘密も IP そのものも置かない
- 要求ごとに EphemeralStore を 1 回読む。書くのは状態が変わったときだけで、同じネットワークに居続ける間は `window` の 1/4 ごとに
  時刻を更新するだけにする。覚えた時刻は最後に見た時刻より最大 `window/4` 古いので、数え落とさないよう `window` の 1.25 倍まで
  さかのぼって数える（数える範囲は `window` から `window` の 1.25 倍）
- 兆候を知らせ済みにするのは、監査ログとアクションを記録できた後にする（記録できなければ次の要求でもう一度見つかる）。通知は
  別のトランザクションにし、失敗しても記録・リスク・失効を取り消さない
- Storage に書く（監査ログ・リスク・失効・通知）のは兆候を見つけたときだけ。ADR 0084 の「ホットパスでは評価器を呼ばない」は、
  外部の評価器（フック・Webhook）を呼ばないという意味で守る（ここで行うのは EphemeralStore の読み書きと GeoIP の表引きだけ）
- 状態が消えれば（memory の再起動など）、次の要求を新しい起点にする。守りが一時的に緩むだけでセッションは使える。複数インスタンスは
  `server.multi_instance` の検査（共有できる EphemeralStore）に従う
- 監視の障害（状態を読めない・書けない、記録できない）では要求を止めない。ただし失効させるはずだった要求は止め、次の要求で
  もう一度見つける

### 誤検知を抑える

- 同じ ASN の中の IP の変化は数えない（モバイル回線・CGNAT）。GeoIP が無ければ同じ /24・/64 の中の変化を数えない
- 少し前に見たネットワークに戻るのは、新しいネットワークとして数えない（2 つの回線・IPv4 と IPv6 の行き来で `network_flapping` に
  ならない。既定の `max_networks` を 4 にする）
- `ignore_networks`（IP か CIDR）の接続元は、接続元の比較と数え上げから外す（会社の出口・自前の VPN の出口など）
- User-Agent は版の数字を除いて比べる（ブラウザの自動更新）
- ブラウザの特徴量の「指紋」は使わない（ADR 0105 と同じ理由：変わりやすく、プライバシーの懸念が大きい）。端末の Cookie と
  User-Agent の種類を代わりにする

### 見つけたら

- 監査ログ `session.anomaly_detected` にいつも残す（接続元は監査ログの IP・User-Agent に入る。ADR 0063）。`details` は
  `signal`・`sid`・`user_id`・`actions` と、兆候ごとの内容（`from_country`・`to_country`、`from_asn`・`to_asn`、`networks`・
  `window_seconds`、`device_cookie`、`unfamiliar_*` の `network`（CIDR）・`asn`・`country`・`known_networks`・`observations`）。SIEM・イベントの購読・SSF の送信側に流れる
- アクション（兆候ごとに選ぶ。複数可）
  - `risk`：ログインの系列の、終わっていないセッションのリスクを、兆候の種類（`device`・`ip`）ごとに点数まで上げる
    （下げない。realm の一覧で止めた種類は入れない）。`session.risk_updated` に `source: session_binding` で残す。その要求の判定から
    効く。「リスクが高ければ再認証」は新しい仕組みを作らず、ADR 0084 の条件（`risk_at_most`）と ADR 0093 の step-up で書く
  - `revoke`：ログインの系列を失効させる（ID の入れ替えの猶予の中の古い ID も。理由 `session_anomaly`。Back-Channel Logout も
    動く）。その要求から未ログインとして扱い、Cookie を消す
  - `notify`：本人に通知 `suspicious_session`（ID だけ。ADR 0031。宛先は `new_device_login` と同じに決める）
- 既定はすべての兆候でアクション無し（記録だけ）にする（オーナーの判断）。まず監査ログ・SIEM で誤検知の量を見てから、運営者が
  兆候ごとにアクションを足す。VPN やモバイル回線の誤検知を考えると、足すならまず `risk`（重要な操作の前に step-up で本人に確かめる）、
  確度の高い `device_changed` だけ `revoke`、のように段階的にする

### 設定

```yaml
security:
  session_binding:
    window: 10m
    max_networks: 4
    ignore_networks: [203.0.113.0/24]
    device_changed:     { enabled: true, score: 90, actions: [] }
    user_agent_changed: { enabled: true, score: 60, actions: [] }
    country_changed:    { enabled: true, score: 70, actions: [] }
    asn_changed:        { enabled: true, score: 30, actions: [] }
    network_flapping:   { enabled: true, score: 70, actions: [] }
    unfamiliar_network: { enabled: true, score: 50, actions: [] }
    unfamiliar_browser: { enabled: true, score: 50, actions: [] }
    profile:
      enabled: true
      min_observations: 5
      max_networks: 20
      max_browsers: 5
      retention: 2160h  # 90 日
```

状態を覚える長さはセッションの寿命の上限（`security.session.absolute_lifetime` の `default` と `max` の大きい方）。

## 結果

- 盗んだセッションの Cookie を別のブラウザで使うと、最初の要求で `device_changed` が記録される（既定はここまで）。`risk` を選べば
  系列のリスクが上がり、要件に `risk_at_most` を書いた操作は step-up を求め、2 要素目を持たない攻撃者は通れない。`revoke` を選べば
  その場で使えなくなる
- 短い時間に接続元が渡り歩くセッションは `network_flapping` で見つかる
- ログインの直後から普段と違う国・事業者・ブラウザで使われるセッションは `unfamiliar_network`・`unfamiliar_browser` で見つかる。
  運営者は調査のとき、そのユーザーが普段どの CIDR・ASN から、どのブラウザで使っているかを API で見られる
- 一覧は Storage に置くので、系列が新しいネットワークから使われるたびに 1 行を読み書きする（要求ごとではない）。新しいネットワークへの
  旅行・転居・ブラウザの乗り換えは、一覧に入るまで `unfamiliar_*` になる（既定は記録だけ）
- ホットパスの増分は EphemeralStore の 1 回の読み（と GeoIP の表引き）で、書き込みは変化のときだけ
- 状態は EphemeralStore にあるので、memory のままでは再起動で消える（新しい起点から見直す）
- 起点は最初に見た要求なので、ログインの直後に攻撃者が先に使えば攻撃者が起点になる（本人の要求が兆候になるので、記録は残る）
- 同じブラウザ・同じ回線で盗んだトークンを使う攻撃（端末の上のマルウェアなど）は見つけられない。DPoP（ADR 0113）や
  Device Bound Session Credentials のような送信者制約が別に要る
- Bearer のセッション（別のドメインのアプリ）は端末の Cookie を比べないので、User-Agent と接続元だけで見る

## 検討した代替案

- **セッションの行（Storage）に起点を持つ**：再起動でも消えないが、要求ごとの比較の結果を書くのが DB になり、ホットパスが重い。
  起点を書くだけならログインのときでよいが、端末の Cookie は次の要求から届き、User-Agent と接続元の変化の記録は結局一時的な状態に要る
- **接続元が変わったらすぐ失効させる**：モバイル回線・VPN・デュアルスタックで正当な利用者が頻繁にログアウトされる。既定は記録だけ
- **既定で `risk`**：誤検知の量を見る前に、正当な利用者に step-up を求めることになる。運営者が兆候ごとに選ぶ
- **点数をログインの評価器（`login_risk`）に足す**：ログインの瞬間しか呼ばれず、ログインの後の盗用を見られない
- **外部のリスクの評価器に任せる（評価器の管理 API。ADR 0084）**：今でもできるが、要求ごとの接続元を外に送ることになり、
  ホットパスで外部を呼ぶか、ログを後から流して遅れる。組み込みで軽く見る
- **ブラウザの指紋**：ADR 0105 と同じ理由で採らない
- **IP の完全一致で比べる**：CGNAT・IPv6 のプライバシー拡張で、正当な利用でも要求ごとに変わる
- **一覧を ASN だけで持つ**：調べるときに CIDR が分からない。GeoIP が無い構成で使えない。CIDR で持ち、ASN も添えて、比べるときは
  どちらかが合えば知っているものとする
- **一覧を端末の記録（`device_recognition`）に足す**：端末の記録はログインのときだけ書き、端末の Cookie ごとに分かれる。接続元の
  一覧はセッションの使われ方から育て、端末の Cookie が無い（Bearer）要求も数えたい
- **一覧を login_risk の評価に使う**：ログインの瞬間しか見ないので、ログインの後の盗用には効かない。ログインの評価に使うのは今後
