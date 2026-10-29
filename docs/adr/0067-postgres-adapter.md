# 0067. PostgreSQL のアダプタは SQLite のアダプタから作り、advisory lock で直列化する

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 2.4、[0004](0004-storage-adapter-native.md)、[0039](0039-implementation-basics.md)、[0042](0042-spike-sqlite-count-then-insert.md)

## 背景

M6 で、複数のインスタンスから使える Storage として PostgreSQL のアダプタを足す。Storage ポートには、SQLite のアダプタで
決めた約束がある。

- 書き込みを含むトランザクションは直列化される（件数の確認と追加を同じ Tx で行ってよい。0042）
- 一意制約の違反は `errs.Conflict` で返り、同じ Tx を続けてよい
- 文字列の ID と時刻の並びはバイト順

アダプタを2つ手で保つと、SQL と変換のコードがずれる。

## 決定

- スキーマは SQLite のマイグレーションを適用した後の形と同じにする（型は TEXT・BYTEA・BIGINT）。文字列の列は
  `COLLATE "C"`、時刻は SQLite と同じ固定長の RFC 3339 の文字列。outbox の追加の順は `ord`（BIGSERIAL）で持つ
- クエリと Repository の実装（`authn.go` など）は、SQLite のアダプタから `cmd/pgport` で作る（`?` を `$n` に、
  `LIMIT` を bigint に、`max` を `GREATEST` に）。PostgreSQL の側は手で直さず、CI で作り直して差分が無いことを確かめる。
  SQL は2つで動く書き方にする。マイグレーションは PostgreSQL の側に手で足す
- 直列化：すべてのトランザクションの始めに `pg_advisory_xact_lock` を取る。SQLite の `BEGIN IMMEDIATE` と同じ約束になり、
  複数のインスタンスでも件数の上限・監査ログのチェーンが保たれる
- `ExecContext` を通る書き込みの文は SAVEPOINT で囲み、失敗したらその文だけを取り消す（PostgreSQL は文の失敗で Tx 全体を
  使えなくする）。`QueryContext` を通る `RETURNING` つきの書き込みは囲まないので、一意制約に触れうる列を書き換えない
- 接続の上限は既定で 10（`max_open_conns`）。Tx は advisory lock で1つずつ進むため、待っている Tx が接続を持ったまま
  増えて PostgreSQL の `max_connections` に達しないようにする
- マイグレーションは goose のセッションロックで、同時に起動したインスタンスから1つずつ適用する
- 契約テスト（`storagetest`）を `IAM_TEST_POSTGRES` の DB で動かす（試験ごとに DB を作る）。CI は PostgreSQL 16 のサービスで動かす

## 理由

- 約束を変えずに済み、アプリの側（Quota、監査ログ、一意性の確認）に手を入れない
- 生成にすれば、SQLite で足したクエリが PostgreSQL で抜けることがない

## 影響

- トランザクションは1つずつ進むので、書き込みの多い負荷では PostgreSQL の並行性を生かせない。セッションの検証などの
  読み取りはキャッシュ（5.3）で受ける。必要になれば、realm ごとのロックや読み取り専用のトランザクションをポートに足し、
  契約テストで確かめてから広げる
- 書き込みの文ごとに SAVEPOINT の往復が2回増える
- 時刻を文字列で持つので、PostgreSQL の時刻の関数は使わない（SQLite と同じ）
