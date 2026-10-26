# 0049. passkey の細部（Relying Party、本人確認、無効化と再登録の拒否）

- 状態: 承認
- 日付: 2026-10-26
- 関連: [design.md](../design.md) 2.5、3.1、4.1、4.6、9.4、[0006](0006-passkey-rs256.md)、[0045](0045-internal-and-external-ids.md)

## 背景

M2 で passkey（WebAuthn）の登録とログインを作るにあたり、design.md に書かれていない細部を決める必要があった。

## 決定

### Relying Party

- 設定は `passkey.rp_id`・`rp_name`・`origins`。省略すると `server.public_url` のホストと origin を使う。どちらも無ければ passkey は使えない（API は 404）
- rp_id のドメインの外の origin は Related Origin Requests で関連付ける。`/.well-known/webauthn` は設定した origins を返す（rp_id のドメインで返すのはホスト先の役目）
- 受け入れる署名のアルゴリズムは ES256 と EdDSA（この順）。RS256 は警告 `passkey_alg_rsa` と一緒に後から足す（0006）。attestation は求めない（`none`）

### 登録

- ログイン済みの本人だけが登録できる（4.2）。discoverable credential（resident key）を必須にし、登録済みの passkey は除外を求める
- user handle はユーザーの公開 ID。内部 ID は認証器に渡さない（0045）
- 表示名は primary のメール（最小化モードでは公開 ID）
- 既に有効な passkey なら `409 passkey_exists`、無効化した credential なら `409 passkey_revoked`。本人は認証器で所有を示した後なので、理由を返してよい

### ログイン

- 1要素目（`/v1/login/passkey`）は discoverable credential で、本人確認（UV）を必須にする。`amr` は `hwk` と `user`
- 2要素目の確認（ユーザーの passkey に限る。UV は求めない）は `passkey.Service.Verify` として用意し、2段階認証の流れ（#34）から呼ぶ
- challenge はフロー ID（256bit の乱数。`__Host-iam_passkey` Cookie か API の応答）に結び付け、EphemeralStore に封をして置く。1回限りで、目的（登録・ログイン・2要素目）とユーザーが合わなければ失敗。期限（既定 5 分）は Clock で確かめる（2.7）
- 署名の回数が戻った応答（複製の疑い）は拒否する。BE フラグが登録時から変わった応答も拒否する（ライブラリの検証）

### 無効化

- 本人による無効化は削除せず `revoked_at` を記録し、credential_id を `revoked_passkey_credentials` に残す。同じ credential は再登録できない（4.6）
- 本人は最後のログインの手段を無効化できない（`409 last_method`）。数えるのは有効な passkey、外部 ID の紐付け、`code` が有効なら確認済みのメール
- その passkey で作ったセッションは、次の検証（遅くとも `validity_max_delay` の後）から使えない。キャッシュの即時の破棄は認証情報の無効化（#35）で扱う

## 結果

- passkey だけで本人確認まで済むため、1要素目のログインが2要素（所有と本人確認）になる
- UV のできない認証器（PIN の無いセキュリティキーなど）は、1要素目には使えず2要素目にだけ使える
- rp_id を後から変えると、登録済みの passkey は使えなくなる（設定のコメントに記す）

## 検討した代替案

- **1要素目で UV を `preferred` にする**：UV の無い応答が1要素のログインになり、単一の所有要素だけでアカウントに入れてしまうため採らない
- **user handle に内部 ID を使う**：認証器と同期先（パスワードマネージャー）に内部 ID が出るため採らない（0045）
- **無効化した passkey の行を消し、拒否リストだけ残す**：監査と「どのセッションがどの passkey で作られたか」の確認のため、行も残す
