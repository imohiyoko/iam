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

- 「ネットワーク」は、GeoIP で ASN が引ければ ASN、引けなければ IPv4 の /24・IPv6 の /64 とする
- 兆候は系列ごとに**種類ごとに 1 回だけ**記録し、アクションを取る（同じ兆候で監査ログ・DB の書き込みを繰り返さない）
- 接続元は ADR 0088 の信頼できるプロキシの規則で決めた値を使う

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
  `window_seconds`、`device_cookie`）。SIEM・イベントの購読・SSF の送信側に流れる
- アクション（兆候ごとに選ぶ。複数可）
  - `risk`（既定）：ログインの系列の、終わっていないセッションのリスクを、兆候の種類（`device`・`ip`）ごとに点数まで上げる
    （下げない。realm の一覧で止めた種類は入れない）。`session.risk_updated` に `source: session_binding` で残す。その要求の判定から
    効く。「リスクが高ければ再認証」は新しい仕組みを作らず、ADR 0084 の条件（`risk_at_most`）と ADR 0093 の step-up で書く
  - `revoke`：ログインの系列を失効させる（ID の入れ替えの猶予の中の古い ID も。理由 `session_anomaly`。Back-Channel Logout も
    動く）。その要求から未ログインとして扱い、Cookie を消す
  - `notify`：本人に通知 `suspicious_session`（ID だけ。ADR 0031。宛先は `new_device_login` と同じに決める）
- 既定はすべての兆候で `risk` だけにする。VPN やモバイル回線の誤検知でログアウトさせると影響が大きく、`risk` なら重要な操作の前に
  step-up で本人に確かめられる。`revoke` は運営者が選ぶ（例：`device_changed` だけ `revoke`）

### 設定

```yaml
security:
  session_binding:
    window: 10m
    max_networks: 4
    ignore_networks: [203.0.113.0/24]
    device_changed:     { enabled: true, score: 90, actions: [risk] }
    user_agent_changed: { enabled: true, score: 60, actions: [risk] }
    country_changed:    { enabled: true, score: 70, actions: [risk] }
    asn_changed:        { enabled: true, score: 30, actions: [risk] }
    network_flapping:   { enabled: true, score: 70, actions: [risk] }
```

状態を覚える長さはセッションの寿命の上限（`security.session.absolute_lifetime` の `default` と `max` の大きい方）。

## 結果

- 盗んだセッションの Cookie を別のブラウザで使うと、最初の要求で `device_changed` が記録され、系列のリスクが上がる。要件に
  `risk_at_most` を書いた操作は step-up を求め、2 要素目を持たない攻撃者は通れない。`revoke` を選べばその場で使えなくなる
- 短い時間に接続元が渡り歩くセッションは `network_flapping` で見つかる
- ホットパスの増分は EphemeralStore の 1 回の読み（と GeoIP の表引き）で、書き込みは変化のときだけ
- 状態は EphemeralStore にあるので、memory のままでは再起動で消える（新しい起点から見直す）
- 起点は最初に見た要求なので、ログインの直後に攻撃者が先に使えば攻撃者が起点になる（本人の要求が兆候になるので、記録は残る）
- 同じブラウザ・同じ回線で盗んだトークンを使う攻撃（端末の上のマルウェアなど）は見つけられない。DPoP（ADR 0113）や
  Device Bound Session Credentials のような送信者制約が別に要る
- Bearer のセッション（別のドメインのアプリ）は端末の Cookie を比べないので、User-Agent と接続元だけで見る

## 検討した代替案

- **セッションの行（Storage）に起点を持つ**：再起動でも消えないが、要求ごとの比較の結果を書くのが DB になり、ホットパスが重い。
  起点を書くだけならログインのときでよいが、端末の Cookie は次の要求から届き、User-Agent と接続元の変化の記録は結局一時的な状態に要る
- **接続元が変わったらすぐ失効させる**：モバイル回線・VPN・デュアルスタックで正当な利用者が頻繁にログアウトされる。既定は `risk`
- **点数をログインの評価器（`login_risk`）に足す**：ログインの瞬間しか呼ばれず、ログインの後の盗用を見られない
- **外部のリスクの評価器に任せる（評価器の管理 API。ADR 0084）**：今でもできるが、要求ごとの接続元を外に送ることになり、
  ホットパスで外部を呼ぶか、ログを後から流して遅れる。組み込みで軽く見る
- **ブラウザの指紋**：ADR 0105 と同じ理由で採らない
- **IP の完全一致で比べる**：CGNAT・IPv6 のプライバシー拡張で、正当な利用でも要求ごとに変わる
