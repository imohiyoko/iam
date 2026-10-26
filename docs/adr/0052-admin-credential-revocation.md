# 0052. 運営者による認証情報の無効化

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 4.6、4.11、4.12、5.3、[0050](0050-second-factor.md)、[0051](0051-password.md)

## 背景

本人による無効化（passkey・外部 ID・TOTP・パスワード）は #32〜#34 で作った。M2 の残りとして、運営者による個別と一括の無効化
（侵害時の初動）の細部を決める必要があった。

## 決定

- 権限 `credentials:revoke` を足し、`realm:owner`・`realm:admin`・`realm:security` に付ける（4.11 の「無効化」）
- 管理 API：
  - `GET /v1/admin/users/{id}/credentials`：有効な passkey・外部 ID の紐付け・TOTP・パスワードの一覧（個人情報は含めない）
  - `POST /v1/admin/users/{id}/credentials/{credential_id}:revoke`：公開 ID（`psk_`・`idn_`・`otp_`）で個別に無効化
  - `POST /v1/admin/users/{id}/password:revoke`：パスワードの無効化
  - `POST /v1/admin/users/{id}/credentials:revoke-all`：全認証情報と全セッションの一括の無効化
- 本人と違い、運営者は最後の1つも無効化できる。以後は復旧の手順（4.12）で戻る。メールは無効化しない（復旧の経路）
- 削除せず `revoked_*` を記録し、取り消せない。passkey は credential_id の再登録も拒否する（0049）
- セッション：
  - 個別の無効化では、その認証情報で作ったセッションが次の検証から使えない（遅くとも `validity_max_delay` の後。5.3）
  - パスワードの無効化と一括の無効化では、ユーザーの全セッションをすぐに失効させる（パスワードはセッションの認証情報に
    入れていないため。0051）
- 監査ログには操作した運営者と対象のユーザー（公開 ID）、理由（`revoked_by_admin` / `compromised`）を残す

## 結果

- 侵害の疑いがあれば、1回の呼び出しで認証情報とセッションを止められる
- Back-Channel Logout による連携先への通知は M5 で足す
