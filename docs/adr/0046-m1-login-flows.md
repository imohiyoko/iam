# 0046. M1 のログインの流れ（メールのフロー、通知の claim、OAuth）の細部

- 状態: 承認
- 日付: 2026-10-25
- 関連: [design.md](../design.md) 2.4、4.1、4.2、4.9、9.4、[0031](0031-notifier-ids-only.md)、[0045](0045-internal-and-external-ids.md)

## 背景

M1 でメールのコード・リンクと OAuth（Google）によるログインを作るにあたり、design.md に書かれていない細部を決める必要があった。

## 決定

### メールのフロー

- フロー ID、コードのハッシュ、リンクのハッシュは EphemeralStore に封をして（`pii.Crypter.Seal`）置く。キーはフロー ID のハッシュ
- 照合の試行はフローごとに数え（既定 5 回）、超えたらフローを捨てる。成功は `Take` で 1 回限りにする
- 開始の応答はアカウントの有無で変えない。登録済みなら `magic_link`、未登録なら `email_verification` の通知を積む

### 通知の秘密の claim

- outbox のペイロードは ID だけ（0031）。宛先・コード・リンクは EphemeralStore に封をして置き、配信用のサービスアカウント（`system:notification_delivery`、権限は `notifications:claim` だけ）が `POST /v1/admin/notifications/{id}:claim` で 1 回だけ取り出す。claim のキーには realm を含め、別の realm からは取り出せない
- 期限までに claim されなかった通知は、M1 では監査ログに残さない（M2 で検討する）

### OAuth / OIDC

- 認可コード + PKCE（S256）。state、nonce、PKCE の verifier、フロー ID はそれぞれ 256bit の乱数。state はフロー ID（`__Host-iam_oauth` Cookie か API の応答）に結び付け、1 回限り
- ID トークンはトークンエンドポイントから TLS で直接受け取り、署名の検証は TLS で代替する（OIDC Core 3.1.3.7。design.md 9.4）。iss、aud、azp、exp、iat、nonce、sub は必ず確かめる。トークンエンドポイントへの接続はリダイレクトを追わず、10 秒で打ち切り、応答は 1 MiB まで
- 識別は `(connection, provider_subject)`。外部 ID が紐付いていればログイン、無ければ登録する
- 登録には、プロバイダが確認済み（`email_verified`）としたメールだけを使う（経路は `oauth_provider`）。未確認なら `400 email_unverified`
- メールが別のユーザーで登録済みなら自動リンクせず（4.2）、`409 account_exists` を返す。本人はプロバイダでそのメールの所有を示した後なので、理由を返しても登録の有無を第三者に明かすことにはならない（4.9 の「本人確認の後」）
- セッションの `amr` は `fed`。認証に使った外部 ID をセッションに残し、外部 ID を無効にしたらそのセッションも使えなくする（4.6）
- connection の設定（`connections.config`）はプリセット（M1 は `google`）から作る。クライアントシークレットは `pii.Crypter.Seal` で封をして置き、平文を DB に置かない。URL は dev 以外では https に限る。戻り先（`redirect_uri`）は connection ごとの許可リストに限る

## 結果

- メール・OAuth のどちらでも、秘密（コード、リンク、state、クライアントシークレット）は平文で保存されない
- `account_exists` を返すため、利用者は「メールでログインしてから連携する」と案内できる。連携の操作は M2（4.2）
- ID トークンの署名を検証しないため、トークンエンドポイントへの経路（TLS とその証明書の検証）に頼る

## 検討した代替案

- **ID トークンの署名を JWKS で検証する**：直接受け取る場合は OIDC Core が TLS での代替を認めており、JWKS の取得・キャッシュ・鍵の入れ替えの扱いが増えるだけなので採らない。暗黙フローやフロントチャネルで ID トークンを受け取ることはしない
- **メールが一致したら自動でリンクする**：未確認のメールを返すプロバイダや、メールの再利用で乗っ取りにつながるため採らない（4.2）
- **`account_exists` も 401 にまとめる**：利用者が次に何をすればよいか分からなくなる。本人確認の後なので、理由を返す
- **クライアントシークレットを環境変数で渡す**：connection を実行中に管理 API で作れなくなるため採らない
