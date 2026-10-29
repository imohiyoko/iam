# 0082. アカウント統合は両方のログインで証明し、統合元の個人 Org は残して中身を新しい Org に移す

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 3.1、4.10、11.6、[0045](0045-internal-and-external-ids.md)、[0076](0076-org-managed-users.md)

## 背景

同じ人が別のメールや外部 IdP で2つのアカウントを作ってしまうことがある。design.md 11.6 は「A にログインした状態で B の
所有を証明すると、B のメール・外部 ID・passkey・Membership・ロール・個人 Org のデータを A に移す（Org 管理ユーザーが絡む
場合はその Org の許可が必要）。B は `status = merged`、`merged_into = A` になり、セッションとトークンを失効する。`sub` が
変わるため `user.merged` イベントを出す。取り消し不可。」とする。

## 決定

- フィーチャー `account_merge`（依存なし。Org が動いていれば Membership も引き継ぐ）
- 所有の証明：統合元 B でログインした本人が `POST /v1/me/merge-tokens` で1回限り・10 分の統合トークンを発行し、統合先 A で
  ログインした本人が `POST /v1/me/merges` で使う。どちらも直近の本人確認（`max_auth_age`）が要る。認証手段を問わずに
  両方の所有を確かめられる。トークンは秘密の SHA-256 をキーに一時ストアに置き、中身は封をする
- 統合しない場合：同じユーザー（`400 same_user`）、どちらかが停止・期間外・削除の予定あり（`409 deletion_scheduled`）、
  どちらかが Org 管理ユーザー（`409 managed_user`。Org の許可の流れは未実装）、B に消去の保留（`409 legal_hold`）、B の Membership に終わっていない停止（予約を含む。停止は Membership に付き
  引き継げない。`409 membership_suspended`）
- 移すもの（1つのトランザクションで）：
  - メール：同じ ID のまま、A のデータ鍵で暗号化し直して移す（primary は A のものを残す）
  - 外部 ID：B の紐付けを無効化し、同じ外部 ID を A に紐付け直す
  - passkey：A に移す。認証器は B のユーザーハンドル（B の公開 ID）を返すので、passkey にそのハンドルを残し、照合に使う
  - TOTP・パスワード：A に無ければ移す（TOTP は暗号化し直す）。B のものは無効化する。B のリカバリーコードは捨てる
  - ロールの付与・Group の所属：A に付け直す（同じものがあれば B のものを消すだけ）
  - カスタム属性の値：A に値の無い属性だけ移す（暗号化する属性は暗号化し直す）。B の値は消す
  - Membership：A が所属していない Org では A の Membership を作り、所属している Org では役割の高い方と active を残す
    （引き上げるのは B の Membership が active で有効期間内のときだけ）。
    B の Membership は `merged` で終える
- 統合元の個人 Org は消さずに残す（B の Membership も残し、B は使えないので誰も入れない）。A を owner にした新しい共有 Org
  （名前は `Merged account`。owner が変えられる）を作り、個人 Org の設定と中身（Group・独自のロール・サービスアカウント・
  Quota の付与・passkey のログインで入る Org）を ID を変えずに移す。ロールの付与は移さない（新しい Org では owner 以外は
  権限を持たずに入り、owner が付け直す）。個人 Org での B のロールの付与も個人 Org に残す
- B はログインの系列を終え（連携先の認可の失効、Back-Channel Logout）、セッションを失効させてから `merged`
  （`merged_into = A`）にする。監査ログと EventSink に `user.merged`（`user_id`・`merged_user_id`・移した件数、個人 Org が
  あれば `personal_org_id`・`shared_org_id`）を出す。ホスト先はこれを見て、B の `sub` と個人 Org の ID で持つデータを
  付け替える
- B のデータ鍵は残す（失効したセッションの IP などを読むため）。消去は通常の削除の流れに従わない

## 理由

- 両方でログインさせれば、メール・passkey・外部 IdP のどの手段のアカウントでも同じ流れで証明でき、片方の乗っ取りだけでは
  統合できない
- 個人 Org を共有 Org に変えたり A の個人 Org に混ぜたりすると、名前の衝突や「個人 Org はユーザーに1つ」の前提が崩れる。
  新しい Org に移せば衝突せず、元の個人 Org は記録として残る
- ロールの付与を持ち込まないことで、統合で意図しない権限が新しい Org に生まれない
- メールと passkey の ID を変えなければ、Membership の EmailID や連携先から見た値が指し続ける

## 影響

- 統合元の公開 ID は `merged` の墓標として残る。統合先の公開 ID は変わらない
- ホスト先は、個人 Org の ID で持つデータを新しい Org に付け替える（付け替えなければ、残した個人 Org を指したまま）
- Org 管理ユーザーの統合（Org の許可）、運営者による統合は後で足す

## 検討した代替案

- 統合元の個人 Org を共有 Org に変える：データと ID はそのままだが、個人 Org が消え、種類の前提が変わる
- A の個人 Org に移す：Group・ロールの名前が衝突しうる
- 統合元のメールにコードを送って証明する：メールの無いアカウント（passkey・外部 IdP だけ）を統合できない
