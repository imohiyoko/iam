# 0070. Quota は時刻ごとの上限と人数で判定し、区切りの時刻だけを調べる

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 11.14、12章、[0042](0042-spike-sqlite-count-then-insert.md)

## 背景

Org の人数の上限（フィーチャー `quota`、roadmap M6）を、期間つきの付与（base / addon / override）の合算で求める。
有効期間のある Membership や招待があるため、「今の人数 < 上限」だけでは将来の時点で超えうる。

## 決定

- 付与は `org_quota_grants`（`quota_key` は `members`）。時刻 t の上限 = 有効な override（新しいもの）、なければ有効な base
  （新しいもの）+ Σ addon。有効な付与が無ければ無制限。期間は `starts_at ≤ t < ends_at`
- 数える人は、終わっていない Membership（必ず）と、realm の `quota_count` で選んだもの（`invited`：期限内の招待を受け入れて作る
  Membership の有効期間で、`future`：有効期間がまだ始まっていない Membership、`suspended`：停止中の Membership を停止の間も）。
  既定はすべて数える。個人 Org には適用しない
- 判定：新しい人の有効期間のうち今以降のすべての時点で「その時点の人数 + 1 ≤ 上限」。人と付与の区間の端だけを調べる。
  招待（`invited` を数えるとき）、招待の受け入れ（その招待の枠は除く）、有効期間を延ばす・早める変更（本人の今の分は除く）で行う。
  足りなければ `409 quota_exceeded` で、`quota` に不足する期間（`from`・`until`）、上限、人数、足りない人数を返す
- 付与の変更：手動の付与の登録・変更・削除で、今以降に既存の人数が新たに上限を超える時点ができれば拒否する。
  外部の付与（`external_ref` つき。同じ参照があれば上書き）は課金などの事実なので拒否せず、超えれば `org.quota.exceeded` を
  監査ログに残す（既存のメンバーは外さず、新規を止める）。外部の付与は手では変えない（`409 quota_grant_external`）
- 件数の確認と追加は同じトランザクション。Storage のトランザクションは直列（SQLite は BEGIN IMMEDIATE、PostgreSQL は advisory lock、
  インメモリは mutex）なので上限を超えない。契約テスト（`QuotaCountThenAddConcurrent`）で各アダプタを確かめる
- 管理 API：`GET /v1/admin/orgs/{id}/quota`、`POST …/quota/grants`、`PUT|DELETE …/quota/grants/{grant_id}`
- ホットパス（セッションの検証、ログイン）では判定しない
- 停止を解く・早く終える操作（`suspended` を数えないとき、人数が増える）は拒まない。停止は安全のための操作で、枠で止めると
  解けなくなるため。超えた分は既存のメンバーと同じ扱いで、新規を止める

## 理由

- 人数と上限はどちらも区間の端でしか変わらないので、端だけを調べれば全時点を調べたのと同じになる
- 外部の課金で減ったものを IAM が拒んでも事実は変わらないため、記録して新規を止める方が運用に合う

## 影響

- 判定のたびに Org の Membership と招待を読む。大きな Org では重くなるが、判定は書き込みの操作だけで起こる
- Org の本人（owner・admin）向けの Quota の表示は後で足す

## 検討した代替案

- 今の人数だけで判定する：期間の重ならない人どうしで枠を共有できず、将来の減少（付与の終わり）も見落とす
- 人数を数え上げた行（カウンタ）を持つ：期間つきの判定には時点ごとのカウンタが要り、Membership の変更のたびに整合を保つ必要がある
