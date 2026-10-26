# 0055. Org の土台（個人 Org、共有 Org、後からの有効化）

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 3.1、4.4、4.11、11.12、11.13、[0045](0045-internal-and-external-ids.md)

## 背景

M3 で Org を入れる（11.13）。design.md は表（orgs、memberships）、個人 Org の自動作成、作成のポリシー（`anyone` /
`operators_only` / `invite_only`）、後から有効にする準備処理を決めているが、Org を決める処理との分担、`invite_only` の意味、
既存の DB で有効にする手順、M4 までの暫定の権限を決める必要があった。

## 決定

- フィーチャー `org`（既定でオン）は `authn/org` が登録する。動いていなければ `account` も `session` も Org を扱わず、
  セッションの active な Org は空のまま（M1・M2 と同じ振る舞い）。Org の API は 404
- 個人 Org はユーザーの作成（`account.CreateWithEmail`）と同じトランザクションで、本人の `owner` の Membership と一緒に作る。
  ユーザーに1つで、Storage の一意制約（realm 内の `personal_owner_id`）で守る。名前は持たない
- Membership はユーザーと Org の組に1つ（終了しても行を残す。再参加は後のチケットで行を使い直す）。`email_id` が空なら primary
- セッションの active な Org は発行時に `session.OrgPicker` が決める。M3 の最初の段では、明示的な指定（その Org の active な
  Membership が要る。無ければ `no_available_org`）か個人 Org。手がかりと前回の Org による選択は #50 で足す。
  2要素目の完了は前の段の Org を引き継ぎ、ID の入れ替えは行をそのまま写す
- 共有 Org は作った人を最初の `owner` にする。作れる人は `realm.org_creation`：
  - `anyone`（既定）：ログインしているユーザーなら誰でも
  - `operators_only`：運営者（管理 API、権限 `orgs:create`）だけ
  - `invite_only`：共有 Org の active な Membership を持つ（どこかに招かれた）ユーザーと運営者
  運営者はポリシーに関わらず作れる（最初の Org を運営者が作り、招待で広げる運用のため）
- 名前は前後の空白を除いて 1〜100 文字。制御文字は受け付けない
- 権限（M4 で authz のロールに置き換えるまでの固定）
  - 運営者：`orgs:create`（realm:owner、realm:admin）、`orgs:read`（加えて realm:support）
  - `org_role`：owner は read / invite / remove / suspend / settings / transfer / delete、admin は read / invite / remove /
    suspend、member は read。active でない Membership は権限を持たない（`role.OrgAllows`）
- 後から有効にするときは `iam features enable org`：台帳を `enabling` にし、全 realm の active なユーザーに個人 Org を作り
  （冪等。200 件ずつのトランザクション）、`active` にして `feature.enabled` を残す。動いているサーバーは再起動で反映する。
  準備の後・再起動の前に作られたユーザーは個人 Org を持たないことがあるため、`Pick` は個人 Org が無ければ作る
- 監査ログ：`org.created`（種類、持ち主か owner の公開 ID）。`session.created` に active な Org の公開 ID を載せる

## 結果

- Org がオフの構成は M1・M2 と同じに動き、オンにしても既存のログインの経路は変わらない（Org はセッションの属性が増えるだけ）
- 個人 Org の取りこぼしがログイン時に救われるため、enable の後に再起動が遅れても入れる Org が無いことは起きない
- `invite_only` は「どこかに招かれた人」を条件にするため、招待（#49）が入るまでは運営者が作った Org の owner だけが作れる

## 検討した代替案

- 個人 Org を初回のログインで作る：ユーザーの作成と同じトランザクションという design.md の約束（11.13）に反し、
  ログインの前に Org を参照する処理（運営者の画面など）で欠ける。救済としてだけ使う
- `invite_only` を「招待を受け入れて登録した人だけ」：登録の経路を記録し続ける必要があり、後から招かれた既存のユーザーが作れない
- enable を管理 API にする：準備処理が長くなりうるため、まず CLI にした（11.12 の「CLI または管理 API」の CLI 側）
