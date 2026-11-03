# 0118. Shared Signals Framework は監査ログを outbox にした送信側と、許した動作だけを行う受信側の 2 つのフィーチャーにする

- 状態: 承認
- 日付: 2026-11-03
- 関連: [design.md](../design.md) 5.10、5.13、6.7、11.12、[0074](0074-service-accounts.md)、[0093](0093-acr-aal-step-up.md)、
  [0100](0100-audit-query-and-event-subscriptions.md)、[0105](0105-risk-based-login-protection.md)、[0112](0112-par-and-resource-indicators.md)

## 背景

roadmap の M11 の Shared Signals（CAEP・RISC。[scope.md](../scope.md) の 2 章）。OpenID Shared Signals Framework 1.0（SSF）で、
セッションの失効・認証情報の変化・アカウントの停止などを、連携先や他の IdP と Security Event Token（SET、RFC 8417）で知らせ合う。
iam は次の 2 つの役を持つ。

- 送信側（Transmitter）：iam で起きたことを、連携先（受信側）に push（RFC 8935）か poll（RFC 8936）で送る
- 受信側（Receiver）：外の IdP・MDM・EDR などの送信側からの SET を受け、iam のユーザーに効かせる

今あるものは次のとおり。

- 監査ログ（6 章）はすべての出来事を realm ごとの連番で持つ。Webhook の購読（ADR 0100）は監査ログを outbox にし、購読ごとの
  位置から少なくとも 1 回送る。送り先は公開のアドレスに限る（`eventsub.PublicClient`・`CheckURL`）
- realm の署名の鍵（ES256）と JWKS（`/oauth2/keys`）
- サービスアカウント（ADR 0074）と、自前の API に向けたトークン（RFC 8707、ADR 0112）
- セッションの一括の失効、パスワードの無効化、利用停止（4.11）

決めることは、(1) 受信側の認証、(2) どの出来事をどのイベントにするか、(3) 配送の仕組み、(4) 受けた SET の確かめと、
何を動かしてよいか、(5) 端末の準拠状態（device posture）の置き場所。

## 決定

### フィーチャー

- `ssf_transmitter`（既定オフ。`features/ssftransmitter`）と
  `ssf_receiver`（既定オフ。`features/ssfreceiver`。依存なし）。役が違い、片方だけ使うことが多いので分ける
- 送信側の前提は `resource_indicators` と `service_accounts`（受信側の認証に使う）。バイナリの依存（Requires）にはせず、前提が
  動いていなければ送信側の API はどのトークンも `401` にする（前提を先に無効化しても、送信側のデータを残したまま安全に止まる）
- どちらも issuer（`server.public_url`）が無ければ動かない（SET の `iss` と受け口の URL に要る）
- 新しい表：`authn_ssf_streams`・`authn_ssf_stream_subjects`・`authn_ssf_poll_events`（SQLite 00074、PostgreSQL 00057）、
  `authn_ssf_transmitters`・`authn_device_postures`（SQLite 00075、PostgreSQL 00058）。外部 ID は `sst_…`（ストリーム）と `stx_…`（送信側の登録）

### 送信側：入口と受信側の認証

- `GET /.well-known/ssf-configuration`（SSF 1.0 の 6 章。複数 realm では RFC 8414 と同じく issuer の下と、既知の場所を差し込んだ場所）。
  `jwks_uri` は `/oauth2/keys`、`delivery_methods_supported` は push と poll、`default_subjects` は `NONE`
- ストリームの管理 API：`/ssf/streams`（POST 作成・GET 取得と一覧・PATCH 変更・PUT 置き換え・DELETE 削除）、`/ssf/status`（GET・POST）、
  `/ssf/subjects:add`・`/ssf/subjects:remove`、`/ssf/verify`、poll は `/ssf/poll/{stream_id}`
- 受信側はサービスアカウントの、`aud` が `<issuer>/ssf`、スコープ `ssf` のアクセストークン（ADR 0112 のリソースのトークン）で呼ぶ。
  運営者は `<issuer>/ssf` をリソースとして登録し（スコープ `ssf`）、受信側のサービスアカウントを許す。DPoP に結び付けたトークンは受けない
  （この API では証明を確かめないため）。ストリームはサービスアカウントのもので、ほかの受信側のストリームは 404（あるかどうかも見せない）
- SET の `aud` はサービスアカウントの ID。受信側は 5 本、realm で 50 本まで。対象はストリームごとに 10 万まで
- 対象は `email`（確認済みのメール）と、`iss` が自分の issuer の `iss_sub`（`sub` はユーザーの公開 ID）。知らない対象は 404。
  ストリームには公開 ID で持つ（メールが変わっても対象は同じ人）
- `verify` はストリームごとに 1 分に 5 回まで。`state` を verification のイベントで返す
- 運営者の管理 API：`GET /v1/admin/ssf/streams`、`POST /v1/admin/ssf/streams/{id}:delete`（権限 `ssf:manage`。realm の owner と security）

### 送信側：イベントの作り方

監査ログに残っている出来事だけから作る（新しい発生源を足さない）。成功の出来事だけ。

| 監査ログ | イベント |
| --- | --- |
| `session.revoked`（同じログインの続きの入れ替え `rotated`・`replaced_by_login`・`second_factor_completed`・`deletion_cancelled`・`org_switched` を除く） | CAEP `session-revoked`。一括の失効（`sessions` がある）なら RISC `sessions-revoked` も |
| `credential.registered`・`credential.revoked`・`passkey.*`・`totp.revoked`・`password.removed` | CAEP `credential-change`（`credential_type` は password・fido2-platform・app・phone-sms・x509・verifiable-credential。知らない方式は送らない） |
| `credentials.revoked_all`（パスワードも無効化したとき） | RISC `credential-compromise` |
| `session.created`（入れ替えで前のセッションがあり、AAL が変わったとき。`previous` を足した） | CAEP `assurance-level-change`（`namespace` は `NIST-AAL`） |
| `user.suspended`（すぐに始まるもの）・`user.suspension_started`・`user.validity_ended` | RISC `account-disabled`（`security_risk` なら `reason` は `hijacking`） |
| `user.deleted` | RISC `account-purged`（届けたら対象から外す） |
| `device_posture.changed`（受信側が受けたもの） | CAEP `device-compliance-change`（`complex` の対象。端末は不透明な参照） |
| `ssf.verification_requested`・`ssf.stream_updated`（状態の変更） | SSF の `verification`・`stream-updated`（そのストリームだけ） |

- ストリームの対象のユーザーの、求めたイベント（`events_requested` と送れるものの積が `events_delivered`）だけを送る
- `jti` はストリーム・監査ログのイベント ID・何番目かの SHA-256 から決める。送り直しても同じ値で、受信側が重複を除ける
- `iss`・`aud`・`iat`・`jti`・`txn`（監査ログのイベント ID）・`sub_id`・`events` を realm の鍵で ES256 で署名する（`typ` は `secevent+jwt`）
- `account-enabled` は送らない（停止を解いた出来事を受信側が誤って広く効かせないよう、後に回す）

### 送信側：配送

- 監査ログを outbox にし、ストリームごとの位置から読む（ADR 0100 と同じ。少なくとも 1 回）。作ったときの位置は最新（過去の出来事は送らない）
- push：`Content-Type: application/secevent+jwt` で POST し、受信側が登録した `authorization_header` を付ける（ストリームごとのデータ鍵で
  暗号化して置く）。2xx は届いた。400 は受信側が SET を受けない（RFC 8935 2.3）ので飛ばし、`last_error` に `rejected_<err>` を残す。
  ほかは 10 秒から倍々（上限 1 時間）で送り直す。送り先は https で、実際につなぐアドレスが公開のアドレスに限る（転送に従わない）。
  インスタンスをまたいで 1 分の lease で取り合わない
- poll：要求のたびに位置から読んで待ちに積み（1000 件まで）、`maxEvents`（既定・上限 100）件を返す。`ack` と `setErrs` の SET を待ちから外し、
  `setErrs` は `ssf.poll_errors` として監査ログに残す。長いポーリングはしない（`returnImmediately` に関わらずすぐ返す）
- 状態：`paused` は位置を残して止め、戻すと続きから送る。`disabled` は待ちを捨て、戻すと最新から送る（止めた間の出来事は捨てる）。
  poll から push に変えると待ちを捨てる
- 監査ログ：`ssf.stream_created`・`updated`・`deleted`、`ssf.subject_added`・`removed`、`ssf.verification_requested`、`ssf.poll_errors`

### 受信側

- 運営者が管理 API の `/v1/admin/ssf/transmitters`（作成・一覧・取得・置き換え・`:delete`。権限 `ssf:manage`。オフなら
  `404 ssf_receiver_disabled`）で送信側を登録する：名前、`issuer`（完全一致。realm で一意）、`jwks_uri`（https・公開のアドレス）か `jwks`
  （公開鍵だけ）、受ける `audience`、`allowed_actions`、`iss_sub` の対象を外部 ID で引く `subject_connection`（connection の slug）
- 受け口は `POST /ssf/receiver/{transmitter_id}`（RFC 8935）。送信側は登録のときに 1 度だけ返す `push_token`（`ssfpt_…`。SHA-256 だけを持ち、
  定数時間で比べる。置き換えで作り直せる）を `Authorization: Bearer` に付ける。iam から送信側にストリームを作りには行かない
  （送信側の管理 API の形と認証が送信側ごとに違うため。送信側で iam の受け口を登録してもらう）
- 確かめ（どれかが駄目なら 400 と `err`・`description`。認証は 401）：64 KiB まで、`alg` は非対称のものだけ（`none`・HMAC を受けない）、
  `typ` は `secevent+jwt`、署名（`kid` があれば同じ `kid` の鍵だけ）、`iss` が登録と一致、`aud` が登録のどれか、`iat` が 24 時間以内で
  1 分より先でない、`exp` があれば過ぎていない、`jti`、イベントがちょうど 1 つ、対象の形（RFC 9493。`sub_id` か、古い RISC のイベントの中の `subject`）
- `jwks_uri` は 10 分覚え、確かめられなければ 1 分以上前に取ったものに限り 1 度だけ取り直す。取れなければ 503（送り直してもらう）
- 同じ `jti`（送信側ごと）は 1 度だけ動かす（EphemeralStore に `iat` の上限 + 2 分覚える）。2 度目は何もせず 202。動かすのに失敗したら
  忘れて、送り直しでもう一度試す
- 対象は realm の有効なユーザーに結び付ける：確認済みのメール、`subject_connection` の外部 ID の `iss_sub`、`complex` の `user`。
  結び付かなければ動かさない（`unknown_subject`。応答は 202 で、ユーザーがいるかどうかを送信側に見せない）
- 動作（`allowed_actions` に無いものは行わない）：

| イベント | 動作 |
| --- | --- |
| CAEP `session-revoked`・RISC `sessions-revoked` | `revoke_sessions`：本人のセッションをすべて失効（理由 `ssf_signal`） |
| RISC `credential-compromise`（`credential_type` が password） | `revoke_password`：パスワードを無効化し、セッションも失効 |
| RISC `account-disabled` | `suspend_user`：`security_risk` の利用停止（`external_ref` は送信側と jti。最後の realm の owner は止めない＝`refused`） |
| CAEP `device-compliance-change` | `record_device_posture`：端末の準拠状態を記録（下記） |
| ほか | 記録だけ（`ignored`） |

- どの SET も `ssf.signal_received`（送信側・イベント・jti の参照・対象・結果 `applied`・`not_allowed`・`unknown_subject`・`ignored`・`stale`・
  `refused`）を監査ログに残す。動作そのものも各機能の監査ログ（`session.revoked` など）に、主体 `ssf_transmitter` で残る
- 送信側の登録の監査ログ：`ssf.transmitter_created`・`updated`・`deleted`

### 端末の準拠状態（device posture input）

- `device-compliance-change` の `complex` の対象の `device`（`opaque` の `id` か `iss_sub` の「iss sub」）を端末の識別子にし、
  `authn_device_postures` に realm・ユーザー・端末ごとの最新の状態（`compliant` か `not-compliant`）、知らせた送信側、状態が変わった時刻
  （`event_timestamp`、無ければ `iat`）を置く。古い知らせでは上書きしない（`stale`）
- 状態が変わったら `device_posture.changed`（端末は realm と識別子の SHA-256 の参照だけ）を監査ログに残す。送信側のフィーチャーが
  動いていれば、それを iam のストリームにも `device-compliance-change` として送る
- 今回は入力として置くだけで、ログインの判定（ADR 0105 の risk、ADR 0093 の acr）にはまだ使わない。iam のセッションの端末と
  送信側の端末の識別子を結び付ける仕組みが要るため。条件（requirements）で使う形は後で決める
- ユーザーの削除で消え、送信側の登録を消すとその送信側の状態も消える

### 無効化（11.12）

- `ssf_transmitter`：ストリーム（対象・poll の待ち・Authorization のデータ鍵とともに）を消す。受信側のサービスアカウントとリソースの登録は残す
- `ssf_receiver`：送信側の登録と、端末の準拠状態を消す
- オフのときエンドポイントは 404、管理 API は `404 ssf_transmitter_disabled`・`ssf_receiver_disabled`

## 結果

- 連携先は iam のセッションの失効・停止・認証情報の変化を、ポーリングやイントロスペクションを待たずに知れる（Continuous Access Evaluation）
- 外の IdP・EDR の知らせで、運営者が許した範囲だけ iam のセッションを止められる。許していない動作は記録だけで、運営者が後から判断できる
- 新しい発生源を足さないので、監査ログに残る出来事が増えればイベントも足せる。監査ログの保持期間（6.5）より長く止めた
  ストリームは、その間の出来事を失う
- 受信側の認証はリソースのトークン（ADR 0112）に乗るため、送信側を使うには `resource_indicators` と `service_accounts` も有効にする
- iam が送信側でも受信側でもあるとき、自分の送ったイベントを自分で受けるループは、動作が冪等で同じ知らせを作らないため広がらない
  （受けた `session-revoked` による失効は `session.revoked` になって送られるが、送り先が iam 自身でなければ終わる）
- 端末の準拠状態はまだ判定に使わない

## 検討した代替案

- **受信側の認証に SSF 専用のクライアントの登録を作る**：サービスアカウントとリソースのトークン（ADR 0112）で足り、取り消し・監査も揃う
- **Webhook の購読（ADR 0100）の送り先の 1 種類にする**：SET の署名・対象の絞り込み・poll・ストリームの状態など、SSF の決まりが多く、
  形が違う。outbox と送り先の確かめ（公開のアドレス）は同じものを使う
- **ストリームの対象をメールで持つ**：メールの変更で対象から外れる。公開 ID で持つ
- **iam から外の送信側にストリームを作りに行く（受信側として）**：送信側ごとに管理 API の認証が違い、資格情報を持つことになる。
  受け口と Bearer の値を出し、送信側で登録してもらう
- **受けた `account-disabled` で無条件に止める**：外の送信側の誤りで realm の人が止まる。運営者が送信側ごとに許す動作を選ぶ
- **長いポーリング（RFC 8936 の `returnImmediately: false`）**：接続を持ち続けるためインスタンスの資源を使う。すぐに返し、受信側が間を置いて呼ぶ
- **端末の準拠状態をその場でログインの判定に使う**：端末の識別子の結び付けが無く、誤って止めるおそれがある。まず入力として置く
