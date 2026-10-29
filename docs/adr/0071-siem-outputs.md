# 0071. SIEM 向けの出力は EventSink のアダプタで、形式と個人情報の出し方を出力先ごとに選ぶ

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 6.3、9.6、[0063](0063-audit-client-data.md)

## 背景

監査ログを SIEM に送る口として、標準出力のほかに syslog・OTLP・Webhook が要る（roadmap M6）。形式は独自の JSON か OCSF、
個人情報は出力先ごとに そのまま・仮名化（既定）・出さない を選べること（6.3）。

## 決定

- アダプタ：`stdout`（JSON Lines）、`syslog`（RFC 5424。tcp・tls は RFC 6587 のオクテット数えの枠付け、udp）、
  `otlp`（OTLP/HTTP の JSON。各イベントを LogRecord にする）、`webhook`（`{"events": [...]}` を POST。
  `secret_env` があれば `X-IAM-Signature: t=<秒>,v1=<HMAC-SHA-256("<t>.<本文>")>`）
- 共通の項目（`adapters/eventsink/sinkfmt`）：`format`（`iam` か `ocsf`）、`pii`（`raw`・`pseudonymize`・`omit`）、
  `pseudonym_key_env`。仮名化は鍵つき HMAC（`p_` + 先頭 16 バイトの16進）で、同じ鍵の間は相関できる。`pii` を省けば、鍵があれば仮名化、無ければ `omit`（これまでの出力と同じ）
- 対象の個人情報は、監査ログに残す切り詰めた IP と User-Agent の大分類。outbox にはこれを残し（`audit.External` は全文の暗号文
  だけを外す）、アダプタが出し方を決める。全文の暗号文はどの出し方でも出さない
- OCSF は 1.3 の IAM カテゴリ（3）。クラスは type の接頭辞で決め（ログイン・セッションは Authentication 3002、
  ユーザーと認証手段は Account Change 3001、ロールの付与・取り消しは User Access Management 3005、Group は Group Management 3006、
  ほか（ロールそのものを含む）は Entity Management 3004）、`activity_id` と `type_uid` はクラスごとの列挙で決める。
  クラスが必須とする対象（`user`・`privileges`・`group`・`entity`）は details の識別子から作り、無ければ主体を、それも無ければ
  `name: unknown` を入れる（対象を省いた不完全な記録は出さない）。切り詰めた IP は `src_endpoint.subnet_uid`（`ip` は完全な
  アドレスのときだけ）、仮名は `src_endpoint.uid`。IAM 固有の項目（realm・Org・details・チェーンの位置）は `unmapped`
- 仮名化は IP と User-Agent の大分類の両方に掛ける。syslog の MSG は UTF-8 の BOM から始める（RFC 5424 6.4）。OTLP の 2xx の本文が
  読めない・64 KiB を超える・JSON でないときは送出の失敗にする（拒まれた記録を見落とさない）
- 送り先の URL は https に限る（開発ビルドと localhost は http 可）。秘密（ヘッダー、署名の鍵、仮名化の鍵）は環境変数の名前で渡し、
  設定ファイルに書かない
- 少なくとも1回：失敗すれば送出全体をやり直す。受け取る側はイベント ID で重複を除き、`chain.seq` の欠けで抜けを検出する
- 出力先は1つ。複数の SIEM へは OpenTelemetry Collector などで分ける

## 理由

- 外部ライブラリ（OTel SDK など）を足さず、標準ライブラリで足りる
- 仮名化を出力の段で行えば、出力先ごとに鍵を分けられ、Storage の監査ログ（チェーン）は変わらない

## 影響

- これまで外部出力に出していなかった切り詰めた IP と UA の大分類が、`raw` か `pseudonymize` を選べば出る
- 複数の出力先を IAM 自身で持つには、出力先ごとの配送の状態（outbox）が要る。必要になれば足す

## 検討した代替案

- 出力先を複数持つ：1つの失敗が他を止めない配送には出力先ごとの outbox が要り、M6 の範囲を超える
- 仮名化を記録の段で行う：出力先ごとに選べず、監査ログ本体の値が変わる
