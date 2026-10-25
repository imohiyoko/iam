# 0048. 最初の運営者の作成と、管理 API の運営者の認証

- 状態: 承認
- 日付: 2026-10-25
- 関連: [design.md](../design.md) 2.5、4.1、4.11、5.2、[0046](0046-m1-login-flows.md)

## 背景

最初の運営者は CLI で作る（2.5）。CLI は `iam serve` と別のプロセスで動き、EphemeralStore（memory）を共有しない。
また管理 API は、これまでサービスアカウントの API キーでしか呼べなかった。

## 決定

### `iam operator create`

- `iam operator create -config iam.yaml -email <address> [-role realm:owner] [-ttl 15m]` は Storage と KeyStore に直接つなぎ、
  ユーザーを経路 `admin` で登録し（メールの所有は実行する人が確かめる）、ロールを付与し、1回限りのログイン用リンクのトークンを表示する
- アドレスが登録済みなら、そのユーザーにロールを足す。運営者による明示的な操作なので、自動リンクの禁止（4.2）には当たらない
- `system:` のロール（配信用）は付与できない
- 監査ログの行為者は `operator_cli`。外部出力は outbox に残り、次の `iam serve` が送る

### ログイン用リンク

- トークンは自己完結にする：realm、ユーザーの公開 ID、期限、256bit の乱数を、マスター鍵から用途ごとに導いた鍵で封じる（`pii.Crypter.Seal`、用途 `login_link`）。CLI と IAM が共有するのは KeyStore だけで足りる
- 1回限りは、使うときに乱数を EphemeralStore の `Incr` で数えて保証する（期限まで覚える）。memory の EphemeralStore では、IAM を再起動すると期限までは使い直せる。期限は既定 15 分、上限 24 時間に抑える
- 公開 API の `POST /v1/login/link:redeem` で使う。ログインの要求なので、応答時間の下限とレートリミット（0047）がかかり、失敗は `authentication_failed` に揃える
- 管理 API の `issueLoginLink`（権限 `users:login_link`）でも発行できる。発行は監査ログに残し、トークンは残さない
- セッションの `amr` は `link`（RFC 8176 に無い独自の値。要素の数には数えないので `single_factor` に当たる）

### 管理 API の運営者の認証

- `Authorization: Bearer` の値がセッションのトークンの形なら運営者のセッションとして、そうでなければサービスアカウントの API キーとして確かめる
- 権限は組み込みのロールで判定する（4.11）。ロールの無いユーザーのセッションは `403 permission_denied`
- 運営者のセッションには直近の認証を求める：認証から `security.session.max_auth_age`（既定 15 分）を過ぎていれば `401 reauthentication_required`
- M1 の認証手段（メール、OAuth、リンク）はどれも1要素のため、「強い認証」（4.11）は M2 で passkey と TOTP が入ってから求める

## 結果

- 最初の運営者は、メールを送れない環境でも CLI だけで作れる
- 管理 API の要求ごとに、運営者の権限と直近の認証が確かめられる

## 検討した代替案

- リンクの状態を Storage の表に置く：スキーマが増え、M1 の用途（最初の運営者と、運営者による再発行）には重い
- CLI が API キーを発行して運営者に渡す：人に長期の秘密を持たせることになり、セッションの寿命や失効の仕組みに乗らない
