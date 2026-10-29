# 運用

本番で運用するホスト先のための手順（roadmap M6）。設計の根拠は [design.md](design.md) と ADR にある。

## 1. 構成

テストしている構成は2つ。どちらも E2E（`cmd/iam/e2e_test.go`）を CI で通している。

| 構成 | Storage | EphemeralStore | 用途 |
|---|---|---|---|
| 単一インスタンス | SQLite | インメモリ | 小規模・検証。インスタンスは1台だけ |
| 複数インスタンス | PostgreSQL | Redis | 本番。インスタンスを並べられる |

- 複数インスタンスでは `server.multi_instance: true` にする。インメモリの EphemeralStore は共有されないため、この設定では起動を拒否する
- 公開 API（既定 `:8080`）と管理 API（既定 `127.0.0.1:8081`）は別のリスナー。管理 API は内部のネットワークだけに出す
- `/healthz` は Storage に届くかを返す（ロードバランサーのヘルスチェックに使う）
- DB との時刻がずれていれば起動時に警告する（`server.clock_skew_warn`、既定 1 秒）。NTP で合わせる
- 公式イメージは全部入り（`ghcr.io/imohiyoko/iam`）と最小構成（`-minimal`）。自分の構成は `iam build` で作る（README、ADR 0073）。
  署名は `cosign verify ghcr.io/imohiyoko/iam@<digest> --certificate-identity-regexp 'https://github.com/imohiyoko/iam/' --certificate-oidc-issuer https://token.actions.githubusercontent.com` で確かめる

## 2. 鍵のバックアップ

KeyStore（`file` または `env`）には次の鍵がある。**鍵を失うと、メールアドレスなどの個人情報と監査ログの全文は復元できない**（9.5）。

| 鍵 | 用途 | 失ったとき |
|---|---|---|
| マスター鍵（`master_keys`） | ユーザーごとのデータ鍵を包む | 暗号化した個人情報（メール、TOTP、IP など）を読めない |
| インデックス鍵（`index_keys`） | メールのブラインドインデックス | メールでユーザーを引けない（ログインできない） |

OIDC の署名鍵と、監査ログの日ごとの鍵は Storage にあり、マスター鍵で包まれている。

手順：

1. `iam keys generate -out keys.json` で作った直後に、keys.json を Storage とは別の場所（秘密の管理サービス、オフラインの媒体など）に複製する。ファイルの権限は 0600
2. `env` の KeyStore では、同じ JSON を秘密の管理サービスに置き、環境変数 `IAM_KEYS` で渡す（読み込んだ後に環境変数から消す）
3. DB のバックアップと鍵のバックアップは別々に保管する（片方だけが漏れても読めないように）。DB だけを戻すときは、そのバックアップを取った時点の鍵が要る
4. マスター鍵を入れ替えるときは、新しい鍵を `master_keys` に足して `current_master_key` を変える。古い鍵は消さない（既存のデータ鍵の復号に要る）。インデックス鍵の入れ替え（全件の再計算）はまだ無い

削除したユーザーのデータ鍵は消える（crypto-shredding）が、DB のバックアップには残る。バックアップの保持期間を決め、期間を過ぎたものは消す。

## 3. アップグレード

データ形式は前進のみ。保証するのは「1つ前のバージョンのバイナリが同じデータで動く」こと（11.12）。

1. リリースノートで、マイグレーションとデータ形式の変更を確かめる
2. DB をバックアップする
3. `iam migrate -config iam.yaml` を1台から実行する（`storage.auto_migrate: true` なら起動時に行う。複数インスタンスでは false にして明示的に実行する）
4. インスタンスを1台ずつ入れ替える。古いバイナリと新しいバイナリが同時に動いてもよい
5. 失敗したら1つ前のバイナリに戻す（マイグレーションは戻さない）

本体の更新とフィーチャーの構成の変更は、別のデプロイで行う。

## 4. 構成の変更（フィーチャー）

```sh
iam features plan -config iam.yaml -build build.yaml   # 次のバイナリで起動できるか
```

- 追加：新しいバイナリを全台に配る → 設定の `features` に足す → `iam features enable <name>`（準備処理の後に active）→ 全台を再起動する
- 削除：`iam features disable <name>`（disabling になる）→ 全台を再起動する（書き込みが止まる）→ データを片付ける
  （`-purge`、または共有 Org は管理 API で削除。`realm.org_deletion_grace`（既定 30 日）が正なら、削除は猶予期間の後にスケジューラが実行するまで終わらない。すぐ消すなら `{"immediate": true}` を付ける）→ もう一度 `iam features disable <name>` で台帳から消える → 設定から外し、含まないバイナリを配る
- 依存するフィーチャー（`quota` と `org_login_policy` は `org` に依存）を先に無効にする
- 台帳にあるフィーチャーを含まないバイナリは起動を拒否する

## 5. Storage の移行

SQLite から PostgreSQL へ（逆も）：

1. 書き込みを止める（インスタンスを止める）
2. `iam storage export -config from.yaml -out dump.jsonl`
3. 移行先の KeyStore に、移行元と同じ鍵（`master_keys` と `index_keys`）を置く。新しい鍵を作らない（書き出しは鍵を含まず、`storage import` は鍵が合うかを確かめないので、違う鍵では個人情報を復号できず、メールの検索もできない）
4. 移行先で `iam migrate -config to.yaml`、続けて `iam storage import -config to.yaml -in dump.jsonl`（空の Storage にだけ入る。監査ログのチェーンを検証する）
5. 設定を移行先に変えて起動する

dump.jsonl には暗号化した個人情報が入る。移行が終わったら消す。

## 6. 保持期間

- 監査ログは `realm.audit_retention`（既定 90 日）を過ぎたら先頭から消す。長期保管は SIEM で行う。消した位置は `audit.truncated` として SIEM に届く
- 失効したセッション、配送済みの outbox、発火済みの予約イベントは `realm.ended_retention`（既定 7 日）の後に消す
- メールのアドレスを持たない構成は `realm.email_storage: index_only`（9.6、ADR 0072）

## 7. 障害時の手順

| 症状 | 原因 | 対応 |
|---|---|---|
| `/healthz` が 503、API が 503 | Storage に届かない | DB を復旧する。認証は失敗側に倒れる（セッションの Cookie は消さない） |
| ログインのフローやレート制限の確かめが失敗する | Redis に届かない | Redis を復旧する。フローの途中の状態は失われ、利用者はやり直す |
| SIEM にイベントが届かない | EventSink の送り先の障害 | 送り先を復旧する。outbox に溜まり、復旧後に送られる（少なくとも1回。イベント ID で重複を除く） |
| 通知が届かない | Notifier の送り先の障害 | 同上（outbox から再送する） |
| 起動を拒否する（ledger does not match binary） | 台帳とバイナリの構成が合わない | 前のバイナリに戻すか、`iam features plan` で手順を確かめる |
| 起動を拒否する（鍵） | KeyStore を読めない | 鍵のファイルの権限（0600）と環境変数を確かめ、バックアップから戻す |
| `storage import` が監査ログの検証で失敗する | 監査ログの改ざん、または書き出しの破損 | 書き出しをやり直す。改ざんならインシデントとして扱い、SIEM の記録と照らし合わせる |
| 運営者のアカウントの乗っ取りが疑われる | ― | 別の owner が管理 API で停止（`security_risk`）し、全認証情報と全セッションを無効化する（`POST /v1/admin/users/{id}/credentials:revoke-all`）。運営者がいなければ `iam operator create` で作り直す |
| 署名鍵の漏洩が疑われる | ― | 運営者のトークンで `POST /v1/admin/signing-keys:rotate`（`Authorization: Bearer …`、`Content-Type: application/json`、本文 `{"alg": "ES256"}` か `{"alg": "ML-DSA-65"}`）を実行し、漏れた鍵のアルゴリズムを新しい鍵に切り替える。古い鍵は `oidc.retired_key_ttl`（既定 7 日）の間 JWKS に残り、その間は漏れた鍵で署名した ID トークンが RP の検証を通りうる。個別に失効させる API は無いので、`oidc.retired_key_ttl` を `oidc.id_token_ttl` を少し超える値に一時的に下げて全台を再起動し、残る期間を縮める。影響の範囲を記録し、RP に古い `kid` を信頼しないよう伝える |
| マスター鍵の漏洩が疑われる | ― | DB の漏洩と合わせて評価する。新しいマスター鍵に切り替え（2章）、データ鍵の包み直しは今は無いため、影響を記録する |
