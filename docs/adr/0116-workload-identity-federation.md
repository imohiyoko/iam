# 0116. Workload Identity Federation は RFC 8693 の交換で外部の JWT をサービスアカウントのトークンに替え、条件は完全一致・一覧・前方一致に限る

- 状態: 承認
- 日付: 2026-11-03
- 関連: [design.md](../design.md) 5.13、11.2、[scope.md](../scope.md) 5 章、[0005](0005-crypto-no-rsa-pqc.md)、[0074](0074-service-accounts.md)、
  [0077](0077-org-sso.md)、[0089](0089-enterprise-full-scope.md)、[0099](0099-token-exchange.md)、[0112](0112-par-and-resource-indicators.md)、
  [0113](0113-sender-constrained-tokens.md)

## 背景

CI（GitHub Actions・GitLab CI）、Kubernetes、クラウド（AWS・GCP・Azure）で動くワークロードが iam の管理 API や自前の API（0112）を呼ぶには、
今はサービスアカウントの API キー・client_secret・private_key_jwt の鍵（0074）を、そのワークロードの環境に置くしかない。置いた秘密は漏れ、
ローテーションも要る。どの基盤も、ワークロードに署名した短命の JWT（OIDC の ID トークンの形）を渡す仕組みを持ち、発行者（issuer）の
Discovery と JWKS で誰でも確かめられる。この JWT を iam のサービスアカウントのトークンに替えられれば、秘密を置かずに済む
（scope.md 5 章の「Workload Identity Federation」。出どころ S P）。0089 で範囲に含めた。

## 調査結果（2026-11-03 時点）

- 基盤のトークン：GitHub Actions（`iss` は `https://token.actions.githubusercontent.com`、`aud` は既定で持ち主の URL か指定の値、
  `sub` は `repo:<owner>/<repo>:ref:<ref>` など、ほかに `repository`・`repository_owner_id`・`ref`・`environment`・`workflow_ref`・`jti`。RS256）、
  GitLab CI（`id_tokens` で `aud` を指定。`project_path`・`namespace_path`・`ref`・`ref_type`・`ref_protected`。RS256）、
  Kubernetes の projected service account token（`iss` はクラスタの issuer、`sub` は `system:serviceaccount:<ns>:<name>`、入れ子の
  `kubernetes.io` に `namespace`・`serviceaccount.name`。RS256 か ES256。issuer がクラスタの中の名前のことが多い）、
  GCP（Google が署名する ID トークン、`iss` は `https://accounts.google.com`）、Azure（Entra ID のマネージド ID のトークン、
  `iss` はテナントごと）、AWS（EKS は Kubernetes のトークン、STS の Web Identity のトークン）。どれも `iss`・`aud`・`exp`・`iat` を持ち、
  `/.well-known/openid-configuration` の `jwks_uri` で鍵を出す
- GitHub の issuer は全リポジトリで共通である。`iss` と `aud` だけを確かめると、任意のリポジトリのワークフローが通る。
  条件（`repository`・`repository_owner_id` など）で絞ることが安全の前提になる。Kubernetes の issuer も、クラスタ内の全ての service account が共有する
- 他製品の交換の入口：GCP の Security Token Service は RFC 8693（`subject_token_type` に `urn:ietf:params:oauth:token-type:jwt`）。
  AWS は独自の `AssumeRoleWithWebIdentity`。Azure（Entra のフェデレーション資格情報）は client assertion（RFC 7523 の 2.2。クライアントの認証）。
  Vault・Keycloak は JWT の認証方式か RFC 8693
- 条件の書き方：GCP は CEL（`attribute_condition`）、AWS は IAM ポリシーの `StringEquals`・`StringLike`、Azure は `sub` の完全一致
  （と後から足した「柔軟な」一致）。式言語は強いが、評価のコストと誤りの余地が大きい
- 署名の方式：基盤の多くは RS256。iam の鍵では RSA を使わない（0005）が、外部の署名の検証は 0098・0103・0115 と同じく受ける
- go-jose v4（すでに依存にある）は `jwt.ParseSigned` で許す alg を列挙させ、`none` と列挙に無い alg を解析の時点で拒む。
  `crit` の知らないヘッダーも拒む

## 決定

- フィーチャー `workload_identity`（既定オフ。`service_accounts` に依存）。実装は `authn/workloadidentity`（発行者・結び付けの管理、
  JWT の検証、条件、JWKS の取得）と `server/app/workloadidentity.go`（管理 API と token エンドポイントへのつなぎ）。ログインの方式ではなく
  サービスアカウントの認証の手段なので、`authn/method/` には置かない（0074 の client assertion と同じ）
- **交換の入口は `POST /v1/admin/token` の RFC 8693 Token Exchange**（`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`、
  `subject_token`、`subject_token_type` は `urn:ietf:params:oauth:token-type:jwt` か `…:id_token`）。RFC 7523 の jwt-bearer grant は採らない。理由：
  - この入口は RFC 7523 の client assertion（`iss`・`sub` がサービスアカウントの ID で、iam に登録した鍵で署名したもの）をすでに受ける。
    同じ `assertion` の形で外部の発行者の JWT も受けると、どちらとして確かめるかを JWT の中身で分けることになり、取り違えの余地ができる。
    RFC 8693 なら `grant_type` と `subject_token_type` で入口から分かれる
  - 交換される JWT はクライアントの認証ではなく「主体を表すトークン」で、RFC 8693 の `subject_token` の意味に合う。GCP の STS と同じ形で、
    クライアントのライブラリ（google-auth の STS など）がそのまま使える
  - `resource`・`scope`（0112）と `requested_token_type` を同じ要求で受けられる。応答の `issued_token_type` で何を返したかを示せる
  - クライアントの認証（`client_secret`・`client_assertion`・`Authorization`）は付けない。付ければ `400 invalid_request`
    （秘密を持たないことが目的で、付けられると交換と認証のどちらで決まったかが曖昧になる）。`actor_token`・`audience` も受けない
    （`audience` は `400 invalid_target`。自前の API は `resource` で選ぶ）。`requested_token_type` は省くか `…:access_token` だけ
- 発行者（workload identity provider）は管理 API `/v1/admin/workload-identity/providers`（一覧・作成・取得・置き換え・削除。権限
  `service_accounts:manage`。realm ごと）
  - `issuer`（https の絶対 URL。クエリ・フラグメント・利用者情報なし。realm の中で一意。JWT の `iss` と完全一致で比べる）、`name`
  - `audiences`：1〜10 個。JWT の `aud` がどれかを含むこと。既定は持たない（基盤ごとに決めた値を必ず書かせる）
  - 鍵：`jwks`（固定の JWKS。ネットワークに出ない。クラスタ内の issuer の Kubernetes に使う）か `jwks_uri`（https。Discovery を飛ばす）。
    どちらも無ければ `issuer` + `/.well-known/openid-configuration` の `jwks_uri` を使う（Discovery の `issuer` が登録と完全一致すること）。
    `jwks` と `jwks_uri` の両方は受けない。固定の JWKS に秘密鍵・対称鍵があれば受けない
  - `algorithms`：RS256・RS384・RS512・PS256・PS384・PS512・ES256・ES384・ES512・EdDSA から選ぶ。既定は RS256 と ES256。`none` と HS* は選べない
  - `max_token_lifetime`（秒。60〜86400、既定 3600）：`exp` − `iat` と、今から `exp` までの上限
  - `disabled`：止めると交換を受けず、発行済みのトークンも次の検証から使えない
  - 設定は `authn_workload_identity_providers` の `config`（JSON）にまとめる（0115 と同じ理由）
- 結び付け（binding）は `/v1/admin/workload-identity/providers/{id}/bindings`（一覧・作成・削除。変更は消して作り直す）
  - サービスアカウント 1 つと条件の組。発行者ごとに 100 個まで。作るときは、呼び出し側がそのサービスアカウントのロールの権限を
    すべて持つこと（認証情報の追加と同じ outranks。0074。`service_accounts:manage` だけで強いサービスアカウントを外から使えるようにさせない）
  - **条件は 1〜20 個の AND で、空の条件は受けない**（共有の issuer で誰でも通ることを防ぐ）。1 つの条件は `claim`（JSON Pointer、RFC 6901。
    `/repository`、`/kubernetes.io/namespace`。深さ 8 まで）と、`equals`（文字列）・`in`（文字列の一覧。1〜50 個）・`prefix`（空でない文字列）の
    ちょうど 1 つ。比べるのはクレームの値が文字列のときだけで、無い・文字列でない（数・真偽・配列・オブジェクト）は一致しない。
    大文字・小文字・Unicode の正規化はしない（バイト列の完全一致）。式の評価・正規表現・ワイルドカードは持たない
  - 条件の解析は `ParseConditions`（不明な項目・2 つの演算子・空の値・不正な Pointer（`~` の後が 0・1 以外）・上限の超過を拒む）。ファジングする
- 交換の手順（どれかに外れれば `400 invalid_grant`。理由は返さず、アプリケーションログに出す）
  1. 16 KiB を超えるものを拒み、go-jose で解析する（alg は上の 10 個に限る。署名は 1 つ）。署名を確かめる前に `iss` だけを読み、
     realm の発行者を完全一致で引く。無い・止めている発行者はネットワークに出ずに拒む
  2. alg が発行者の `algorithms` に入ること。鍵は `kid` が一致し（無ければ alg に合う全ての鍵を試す）、`use` が `sig` か空で、alg に合う種類と大きさ
     （RSA は 2048 bit 以上、EC は alg の曲線、EdDSA は Ed25519）のもの
  3. `iss` の完全一致、`aud` が `audiences` のどれかを含む、`exp`・`iat` が必須、`nbf` はあれば確かめる（ずれ 60 秒）、`iat` が未来でない、
     `exp` − `iat` と今から `exp` までが `max_token_lifetime` 以内
  4. 発行者の結び付けのうち、条件をすべて満たすもの。要求に `client_id`（サービスアカウントの ID）があれば、そのサービスアカウントの結び付けに限る。
     無ければ、満たす結び付けのサービスアカウントが 1 つのときだけ選ぶ（2 つ以上なら `client_id` が要る）
  5. `jti` があれば、発行者と `jti` の組を EphemeralStore の `Incr` で 1 回だけにする（`exp` まで覚える）。無いトークン（基盤による）は受ける
  6. サービスアカウントが使えること（削除・有効期間・停止・Org・フィーチャー。0074 と同じ）を確かめ、0074 のアクセストークンを発行する。
     `resource`・`scope`（0112）と DPoP の結び付け（0113）は client credentials と同じに効く
- 発行したトークンは結び付けを「認証情報」として記録する（`credential_id` に結び付けの ID）。検証のたびに結び付けと発行者が残っていて
  発行者が止まっていないことを確かめるので、結び付けの削除・発行者の停止と削除・フィーチャーの無効化は、発行済みのトークンにも次の検証から効く。
  認証の手段（amr）は `workload_identity`
- JWKS の取得（SSRF の対策は 0077・0100 と同じ）：https だけ、名前を解決した後に実際につなぐアドレスが公開のアドレスであることを確かめ
  （`oauth.PublicAddr`。DNS rebinding も通らない）、プロキシを使わず、転送に従わず、5 秒で打ち切り、応答は 256 KiB まで。開発ビルド（`dev`）だけ
  公開でないアドレスを許す。取得した JWKS は EphemeralStore に 1 時間置く（キーは発行者の ID と更新時刻。設定を変えれば読み直す）。
  知らない `kid` のときはキャッシュを使わずに読み直す。取得（Discovery と JWKS）は発行者ごとに 1 分に 5 回までにする（未認証の要求で
  発行者に問い合わせを繰り返させない）。取得に失敗すれば拒む（fail closed）
- 新しいテーブル：`authn_workload_identity_providers`（sqlite 00070、postgres 00053）と `authn_workload_identity_bindings`
  （sqlite 00071、postgres 00054）。結び付けは本人の認証情報ではなく、条件で外部の主体をサービスアカウントに対応させる規則なので、
  `authn_credentials`（0092）には置かない。サービスアカウントの認証情報（`authn_service_account_credentials`）にも入れない
  （秘密も公開鍵も持たず、発行者ごとに一覧・片付けをしたい）
- 監査ログ：`workload_identity.provider.created`・`updated`・`deleted`、`workload_identity.binding.created`・`deleted`、発行は
  `service_account.token_issued`（`workload_identity_provider_id`・`workload_identity_binding_id`・外部の `sub` を足す）。
  署名を確かめた後に拒んだもの（結び付けが無い・あいまい・`jti` の再送・サービスアカウントが使えない）は `workload_identity.exchange_denied`
  （発行者・外部の `sub`・理由）。署名を確かめる前の失敗は未認証で起こせるので、アプリケーションログにだけ出す
- フィーチャーの無効化で、発行者・結び付けと、結び付けで発行したアクセストークンを消す。取得した JWKS は EphemeralStore の期限で消える

## 結果

- CI・Kubernetes・クラウドのワークロードが、秘密を置かずに iam のサービスアカウントとして管理 API と自前の API（0112）を呼べる
- 条件の書き方は GCP の CEL より弱い。否定・「どれかを満たす」は書けず、結び付けを分けて表す（結び付けのどれかに当たればよいので OR になる）。
  正規表現が無いので、タグの形などは前方一致で書く。代わりに、評価が必ず止まり、誤った条件で意図より広く通る余地が小さい
- クラスタの中の名前を issuer にする Kubernetes は、公開のアドレスで JWKS を出せないので、固定の `jwks` を登録し、クラスタの鍵を替えたら登録も替える
- `jti` の 1 回だけの扱いで、同じ基盤のトークンを 2 度交換できない（GitHub Actions のトークンは要求ごとに新しく作る）。`jti` の無い基盤の
  トークンは、寿命の間は何度でも交換できる。`max_token_lifetime` を短くして抑える
- 発行者の JWKS が止まると、キャッシュが切れた後の交換は失敗する（古い鍵を使い続けない）
- RSA の署名を検証する（0005 の「iam の鍵では RSA を使わない」は変わらない）

## 検討した代替案

- RFC 7523 の jwt-bearer grant（`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`、`assertion`）：仕様としては素直だが、
  上のとおり既存の client assertion と形が同じで、入口で分けられない
- Azure と同じく client assertion（RFC 7523 の 2.2）として受ける：外部の発行者の JWT を「クライアントの認証」として扱うと、`iss`・`sub` が
  サービスアカウントの ID であることを前提にした今の検証と混ざる。結び付けの条件で主体を決める今回の形にも合わない
- CEL などの式言語：評価のコスト（未認証の要求で評価する）、ライブラリの攻撃面、誤った式で広く通る危険がある。必要な場面の多くは完全一致・
  一覧・前方一致で足りる。足りなければ後から演算子を足せる（JSON の形なので互換を保てる）
- 結び付けを発行者の設定（JSON）にまとめる：一覧・削除の監査と outranks の確かめがサービスアカウントごとにしにくく、発行済みのトークンを
  結び付けに結べない
- JWKS を DB に置く：交換のたびに書き込みが要り、複数のインスタンスで取得が重なる。EphemeralStore（共有できる）で足りる
- 取得に失敗したら古い JWKS を使い続ける：鍵の漏えいで発行者が鍵を外したときに、外した鍵を受け続ける。可用性より安全を取った
- SPIFFE（X.509-SVID・JWT-SVID）：JWT-SVID は発行者の JWKS を登録すれば同じ仕組みで受けられる（`sub` は SPIFFE ID）。X.509-SVID は
  mTLS（0113）の側の話で、今回は扱わない
