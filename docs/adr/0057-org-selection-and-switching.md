# 0057. Org の決定と切り替え

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.4、5.2、[0055](0055-org-foundation.md)、[0056](0056-invitations-and-membership-email.md)

## 背景

design.md 4.4 は、ログインで入る Org を「明示的な指定 → ログインの手がかりに結び付いた Org（複数ならその中の前回の Org、
無ければ選択させる）→ 前回の Org → 個人 Org」の順に決め、切り替え時にセッションの ID を入れ替えるとしている。
手がかりの取り方、「前回」の持ち方、選ばせ方、切り替えの API を決める必要があった。

## 決定

- 決定はセッションの発行の中で `session.OrgPicker`（`org.Service.Pick`）が行う。候補は active な Membership のある Org
  （停止・有効期間は [0058](0058-org-and-membership-suspension.md) で候補から外す。ログインポリシーは後で）
- 手がかり
  - ログインに使ったメール（メールのコード・パスワード。セッションの認証情報に載るメールの ID）を結び付けた Membership
  - OAuth のプロバイダが確認済みとして返したアドレス：その場で HMAC を計算し、本人のメールと一致すればそのメールを結び付けた Membership
  - passkey：`passkeys.preferred_org_id`（本人が `/v1/me/passkeys/{id}:set-org` で決める）
  - Membership のメールが未設定（primary を使う）なら手がかりにしない（どの Org にも同じように結び付くため）
- 前回の Org は、最後に発行したセッションの active な Org とする（新しい表を持たない）
- 手がかりの Org が複数で、前回の Org がその中に無いときは、セッションを個人 Org に入れ、候補を `org_choices` で返す。
  クライアントは選ばせて `/v1/me/orgs/{id}:switch` を呼ぶ
- 候補が空なら `no_available_org`（本人確認の後なので理由を返す）
- 切り替え（`POST /v1/me/orgs/{id}:switch`）は、active な Membership のある Org にだけ。セッションの ID を入れ替え、
  古い ID はすぐ失効させる（別の Org の文脈で使われ続けないように。猶予は置かない）。Bearer のセッションには新しいトークンを
  必ず返す。監査ログは `session.org_switched`
- ログインの応答（LoginResult）に、入った Org の公開 ID（`org_id`）を返す
- 切り替え時の step-up と Org の寿命による再認証は、Org の設定の段（#53）で足す

## 結果

- 仕事用のメールでログインすると、そのメールを結び付けた Org に入る。passkey ごとに入る Org を決められる
- 手がかりがあいまいなときに勝手に共有 Org に入らない（個人 Org が既定）

## 検討した代替案

- 前回の Org をユーザーの列に持つ：書き込みが増え、セッションの一覧と食い違いうる
- あいまいなときにログインを止めて選ばせる：ログインの API ごとに途中の状態が要る。セッションを個人 Org で発行し、
  後から切り替える方が単純
