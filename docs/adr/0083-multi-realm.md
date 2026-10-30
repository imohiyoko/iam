# 0083. 複数 realm は1つの App のまま要求ごとに realm を決め、realm ごとのサービスの組に渡す

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 2.8、3.1、5.2、11.1、[0045](0045-internal-and-external-ids.md)、[0072](0072-retention.md)、[0074](0074-service-accounts.md)

## 背景

design.md 11.1 は「互いに独立したユーザー集合を1インスタンスで持つ。realm はホスト名かパス（`/realms/{slug}/…`）で決める」
とする。これまでは設定ファイルの `realm` の1つだけで動き、サービス（セッション・アカウント・Org・OIDC Provider など）は
起動時にその realm の設定で組み立てていた。データはすべて `realm_id` を持ち、Storage の契約テストで realm の分離を確かめている。

方式は2つ考えられる。realm ごとにプロセス（または App）を分けるか、1つの App のまま要求ごとに realm を決めるか。
開発の手間を問わずに最もよい形を選ぶ（roadmap の M7 の決定）。

## 決定

- フィーチャー `multi_realm`（依存なし、既定でオフ）。オフなら今までどおり realm は1つで、振り分けも realm の管理 API も無い
- 1つの App のまま、要求ごとに realm を決める
  - 公開 API・管理 API の入口で、Host がいずれかの realm のホスト名ならその realm、パスが `/realms/{slug}/…` なら（ホスト名を
    持たない）その realm、どちらでもなければ既定の realm（設定ファイルの `realm`。今までどおり root で動く）
  - 知らない slug と、ホスト名を持つ realm をパスで指したものは `404 realm_not_found`
  - パスで指したときは接頭辞を外して、その realm のハンドラに渡す
- realm ごとのサービスの組：realm の設定・issuer・passkey の RP・Cookie の名前を持つ App を realm ごとに作り、表に持つ。
  アダプタ（接続・キャッシュ）、暗号化、outbox の送出（EventSink・通知・Back-Channel Logout）、予約の処理、保持期間の掃除は
  既定の realm の App が持ち、全 realm で共有する。予約の処理は出来事の `realm_id` の App で行う
- realm の場所
  - ホスト名で指す realm：最初のホスト名を正とし、issuer は `<scheme>://<host>`（scheme とポートは `server.public_url` から）、
    passkey の RP ID はそのホスト名。Cookie はホストごとに分かれる
  - パスで指す realm：issuer は `<public_url>/realms/{slug}`。passkey の RP ID は既定の realm と同じ。Cookie は
    `__Host-` のまま（Path=/ が要る）、名前に `.{slug}` を付けて分ける。ホスト型ログイン画面は接頭辞で API と資源を指す
  - 署名鍵・連携先・接続はもとから realm ごと
- realm は実行中に作る：既定の realm の管理 API の `/v1/admin/realms`（権限 `realms:manage`。realm:owner が持つが、既定の
  realm でだけ効く）で作成・一覧・変更する。作った realm の最初の運営者は `POST /v1/admin/realms/{id}/operators` か
  `iam operator create -realm <slug>` で作る（1回限りのログイン用リンク）
- realm ごとの設定（タイムゾーン・確認済みとみなす経路・Org を作れる人・削除の猶予・メールの保持モード・Quota で数えるもの）は
  realm の行に JSON で置き、設定ファイルの `realm` の値を既定にする。既定の realm は設定ファイルで変える。セキュリティの階層
  （セッションの寿命など）はホスト先の段のまま全 realm で共通（Org の段は今までどおり）
- realm の表は、変更したインスタンスではすぐに、他のインスタンスでは `validity_max_delay` の間隔で読み直す。読み直すときは
  更新時刻の変わった realm の App だけを作り直す。まだ表に無い realm の予約の出来事は次の回に回す
- ホスト名は小文字の DNS 名（ポートなし）で、realm をまたいで重複しない（`authn_realm_hosts` の主キー）
- 監査ログに `realm.created`・`realm.updated` を、その realm の出来事として残す（行った運営者の realm を詳細に残す）
- realm の削除はまだ無い。既定以外の realm があるうちは `multi_realm` を無効にできない

## 理由

- 1つの App なら、realm を実行中に足せ、接続・キャッシュ・outbox の送出を realm の数によらず1つにできる。realm ごとに
  プロセスを分けると、realm の追加に再起動か配置の変更が要り、接続とバックグラウンドの処理が realm の数だけ増える
- サービスは realm の ID を引数に取るように作ってあるため、realm ごとに違うのは設定と場所だけになる。それを持つ App を
  realm ごとに作れば、各ハンドラは今の形のまま正しい realm で動き、既定の realm の動きは変わらない
- ホスト名で指す形を推す（Cookie・passkey・オリジンが分かれる）。ワイルドカードの DNS や証明書を用意できない構成のために
  パスでも指せるようにする

## 影響

- パスで指す realm は、passkey の RP ID と、Cookie を送る範囲（ホスト）を既定の realm と共有する。認証器は別の realm の
  passkey を候補に出しうる（ユーザーが realm ごとに違うためログインはできない）。分けたいならホスト名で指す
- 通知の受け取り（配信用のサービスアカウント）は realm ごと。通知の `realm_id` で、配信用のアプリが URL を決める
- realm の削除、realm ごとのセキュリティの階層は後で足す

## 検討した代替案

- realm ごとにプロセスを分ける（設定ファイルを realm ごとに持つ）：分離は強いが、実行中に足せず、接続と送出が realm の数だけ増える
- サービスに realm の設定を要求ごとに渡す：全サービスの引数が変わり、設定の取り違えを型で防ぎにくい
- 既定の realm も `/realms/{slug}` にだけ置く：既存の連携先の issuer と URL が変わる
