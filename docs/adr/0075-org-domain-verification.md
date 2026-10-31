# 0075. Org のドメインの所有は DNS の TXT で証明し、証明済みのドメインは realm で1つの Org だけが持つ

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 11.3、[0045](0045-internal-and-external-ids.md)、[0069](0069-org-login-policy.md)

## 背景

Org 管理ユーザー（11.3）は、Org が所有を証明したドメインのアドレスで登録した人を Org のものにする。
その前提として、Org がドメインを持つことを確かめる手段が要る。

## 決定

- フィーチャー `org_managed_users`（既定オフ、`org` が要る）。テーブル `org_domains`（`dom_…` の外部 ID）
- Org の owner（`org:settings`）が公開 API の `/v1/me/orgs/{id}/domains` で登録・一覧し、`…/{domain_id}:verify` で確かめ、`…:delete` で消す。
  個人 Org には登録できない。1つの Org に 20 まで。運営者は管理 API の `/v1/admin/orgs/{id}/domains`（`orgs:update`）で同じことをする
- ドメインは ASCII の小文字（IDN は A ラベル）で、末尾の点を除く。ラベルは2つ以上で、TLD は数字だけではない（IP アドレスを除く）
- 登録すると IAM がトークン（160bit の乱数）を作る。owner が `_iam-challenge.<domain>` に TXT `iam-domain-verification=<token>` を置き、
  確かめると証明済みになる。TXT が無ければ `409 domain_not_verified`（確かめた時刻は残す）、DNS の障害は `503 dns_unavailable`
- 証明済みのドメインは realm で1つの Org だけが持てる（部分一意索引）。別の Org が証明済みなら登録・証明は `409 domain_taken`。
  証明前の登録は複数の Org が持ててよい（先に証明した方が持つ）
- DNS はトランザクションの外で引き、結果を書くときに行が同じ（トークンが同じ）ことを確かめる
- 監査ログ：`org.domain.added`、`org.domain.verified`、`org.domain.removed`
- フィーチャーを無効にするときは `org_domains` の行を消す。Org を消すとき（即時・猶予の後）もその Org のドメインを消す

## 理由

- TXT は DNS の管理者だけが置けるので、Web サーバーやメールを持たない Org でも証明できる。名前を `_iam-challenge` に分けるのは、
  apex の TXT（SPF など）と混ざらないようにするため
- 証明前の登録を排他にすると、他の Org のドメインを先に登録して妨げられる
- 公開接尾辞（`co.jp` など）は、その TXT を置けないので証明できない。接尾辞の一覧は持たない
- DNS の待ちでトランザクション（SQLite では書き込みの鍵）を握らない

## 影響

- 証明済みのドメインの定期的な確かめ直しは [0087](0087-org-domain-recheck.md) で足した（TXT が猶予の間ずっと無ければ証明を外す）
- Org 管理ユーザーの登録（証明済みドメインのアドレス）は、この上に足す

## 検討した代替案

- HTTP の `/.well-known/` のファイル：Web サーバーを持たないドメインで使えない
- 確認メール（`admin@<domain>` など）：受信箱を持つ人がドメインの管理者とは限らない
