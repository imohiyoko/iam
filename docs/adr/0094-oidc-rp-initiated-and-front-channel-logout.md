# 0094. RP-Initiated Logout はセッションと合う id_token_hint のときだけ確かめずに終え、Front-Channel Logout は完了の画面の iframe で知らせる

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.2、5.5、5.6、11.0、[oidc-conformance.md](../oidc-conformance.md)、[0022](0022-deny-reason-disclosure.md)、
  [0066](0066-oidc-authorization-code-flow.md)、[0083](0083-multi-realm.md)、[0089](0089-enterprise-full-scope.md)

## 背景

連携先は Back-Channel Logout（0066）で、IAM でのログアウトを知れる。逆に、連携先の画面でログアウトしたときに IAM の
セッションも終える標準の手段（OpenID Connect RP-Initiated Logout 1.0）が無かった。また、サーバーから呼べる送り先を持たない
連携先（SPA や、社内のネットワークの中のアプリ）は Back-Channel Logout を受けられない。ブラウザの中で知らせる
Front-Channel Logout 1.0 が要る。どちらも scope.md の標準（S）の項目で、0089 のとおり既定オフのフィーチャーとして足す。

決めることは次のとおり。

- ログアウトを本人に確かめる条件。確かめなければ、別のサイトに置いたリンクでログアウトさせられる（ログアウトの CSRF）
- 戻り先（`post_logout_redirect_uri`）の確かめ方。オープンリダイレクトにしない
- Front-Channel Logout で、どの連携先をどう開くか。CSP をどう書くか

## 決定

- フィーチャー `oidc_logout`（依存なし、既定でオフ）。オフなら次のどれも無い（Discovery にも出さない）。issuer
  （`server.public_url`）が無ければ OIDC のエンドポイントごと無い（0066 と同じ）
- `end_session_endpoint`：`/oauth2/end_session`（GET の問い合わせか POST のフォーム）。受けるのは `id_token_hint`・
  `client_id`・`post_logout_redirect_uri`・`state`・`ui_locales`・`logout_hint`
  - `id_token_hint`：この realm の鍵で署名した ID トークン（`typ: JWT`。Logout Token は `typ` と `events` で拒む）。
    `iss` がこの realm の issuer で、`aud`（1つのとき）か `azp`（`aud` に含まれる）がこの realm の連携先であること。
    期限（`exp`）は見ない（RP-Initiated Logout 2 は期限切れも受け付けるとする）。退役から `oidc.retired_key_ttl` を過ぎた鍵の
    ものは検証できないので拒む
  - `client_id` と `id_token_hint` の連携先が違えば拒む
  - `post_logout_redirect_uri` は、連携先に登録した値と完全に一致するときだけ使う。連携先が分からない（`client_id` も
    `id_token_hint` も無い）ときは拒む
  - 正しくない要求は、連携先に戻さずに画面（400）で止め、理由は言わない（0022 と同じく、何が違うかを試させない）
  - `logout_hint` は手がかりにすぎない（ログアウトするのはこのブラウザのセッション）ので使わない。`ui_locales` は画面の
    言語に使う（無ければ Accept-Language）
- 確かめる条件
  - `id_token_hint` の `sid` と `sub` が、ブラウザのセッションの系列（`sid`）と本人に合えば、確かめずにセッションを失効させる
  - 合わない・無いときは確認の画面を出す。要求は EphemeralStore に封をして預け（キーは秘密の ID の SHA-256、10 分）、
    フォームにはその ID だけを入れる。答え（`POST /oauth2/end_session/confirm`）は CrossOriginProtection の内側に置き、
    要求は1回だけ使え、確認を求めたときと同じ系列と本人のセッションでだけ通る。断ればログインしたまま
  - ログインしていなければ、終えるものは無いので確かめない
  - 制限つきのセッション（2要素目の確認待ちなど）も、`POST /v1/logout` と同じくログアウトできる
- セッションの失効は `POST /v1/logout` と同じ（理由 `logout`）。ログインの系列が終わり、系列の認可が失効し、Back-Channel
  Logout が outbox に積まれる（0066）。Cookie を消す
- Front-Channel Logout 1.0
  - 連携先の登録に `frontchannel_logout_uri` と `frontchannel_logout_session_required` を足す。URI は連携先の URI の条件
    （https か loopback の http、フラグメントなし）に加え、scheme・ホスト・ポートが `redirect_uris` のどれかと同じであること
    （Front-Channel Logout 2）
  - 完了の画面で、終えた系列の認可を持つ連携先（認可の失効・期限は問わない。Back-Channel Logout と同じ）の
    `frontchannel_logout_uri` を iframe で開く。`session_required` なら `iss` と `sid` を問い合わせに足す。ログインしていない
    ときは、終えた系列が無いので開かない（漏れた ID トークンで、このブラウザの連携先のログインを終えさせられないように）
  - iframe を読み終えたら（最長 5 秒）、JS で戻り先に移る。JS が無くても戻れるようにリンクを置く。開くものが無ければ、
    戻り先にすぐ 302 で転送する
- 画面の CSP：`default-src 'none'`、`script-src 'self'`、`style-src 'self'`、`frame-ancestors 'none'`、`base-uri 'none'`。
  `frame-src` は開く連携先のオリジンだけ（無ければ `'none'`）。確認の画面の `form-action` には、`'self'` に加えて戻り先の
  オリジンを足す（ブラウザはフォームの送信の後の転送にも `form-action` を当てる）。Referrer-Policy は `no-referrer`
  （`id_token_hint` を含む URL を連携先に渡さない）
- 画面はホスト型ログイン画面と同じく、組み込みのテンプレート（`logout.html`）と文言（en・ja）を持ち、`server.login_templates`
  に `logout.html` があれば差し替える
- 回数の上限：接続元ごとに、ログインの `per_ip` と同じ値（バケットはログインと分ける）
- Discovery：`end_session_endpoint`、`frontchannel_logout_supported`、`frontchannel_logout_session_supported`、
  `ui_locales_supported`
- フィーチャーがオフのとき、`frontchannel_logout_uri` の登録は `invalid_client_metadata`。無効化の途中で残っている値は、
  変えなければほかの項目の変更を受け付ける。無効化では全 realm の連携先の Front-Channel Logout の登録を外す
  （`post_logout_redirect_uris` は前からある項目なので残す）
- 複数 realm（0083）：エンドポイントも確認の答えも realm ごとの App で動く。パスで指す realm では画面の URL に接頭辞を付ける。
  鍵・連携先・セッションは realm ごとなので、別の realm の ID トークンと連携先は受け付けない
- 監査ログは `POST /v1/logout` と同じ（`session.revoked`、理由 `logout`）

## 結果

- 連携先は標準の RP（zitadel/oidc の `rp.EndSession` など）で、IAM のセッションを終え、登録した戻り先に戻れる
- 連携先が示したセッションと合うときだけ確かめないので、別のサイトのリンクではログアウトさせられない。連携先が持つ
  ID トークンが漏れても、本人のブラウザのセッションと合わなければ確認の画面になる
- Front-Channel Logout はブラウザがサードパーティの Cookie を送らないと、連携先の側でセッションを見つけられないことがある
  （`session_required` の `iss` と `sid` で探せる連携先なら効く）。確実に知らせたい連携先には Back-Channel Logout を勧める
- 入れ替え前のセッションの ID の猶予（`rotation_grace`）は `POST /v1/logout` と同じ扱いで、ログアウトしても猶予の間は残る
  （Cookie は消す）

## 検討した代替案

- いつも確かめる：連携先の「ログアウト」で毎回画面が挟まり、多くの OP（Keycloak・Auth0 など）と違う。`id_token_hint` が
  セッションと合うことは、連携先が本人のログインから始めた要求であることの十分な印になる
- `id_token_hint` だけで（ブラウザのセッションが無くても）系列を終える：漏れた ID トークンで誰でもログアウトさせられる。
  系列を終えるのはブラウザのセッションだけにした
- zitadel/oidc の `op.Server.EndSession` を使う：転送先を返すだけで、確認の画面と Front-Channel Logout の画面を描けない。
  要求の解析も小さいので自前にした
- 確認の答えに専用の CSRF トークンの Cookie を使う：預けた要求の ID がフォームにしか無い秘密なので、それで足りる。
  Origin（Sec-Fetch-Site）の確認も重ねた
