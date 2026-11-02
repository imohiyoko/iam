# 0092. 認証方式のポートは汎用の認証情報のストアと封をしたフローで動かし、HOTP を最初の方式にする

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 3.1、4.1、4.6、9.5、11.0、[0011](0011-build-time-features.md)、[0014](0014-pii-encryption-minimization.md)、
  [0022](0022-deny-reason-disclosure.md)、[0050](0050-second-factor.md)、[0068](0068-storage-export-import.md)、[0073](0073-build-and-feature-toggle.md)、
  [0082](0082-account-merge.md)、[0090](0090-authenticator-plugins.md)

## 背景

0090 は、認証方式を共通のポート `Authenticator` を持つプラグインにし、認証情報を汎用のストア `authn_credentials` に置き、
HTTP を汎用にすると決めた。実装に当たっては、次を決める必要がある。

- ポートの形（方式に何を渡し、何を返させるか）と、方式が Storage を直接触らないための仕組み
- 汎用の認証情報の列、暗号化、検索キー、同時の使用（使い捨てのコードの再使用）の防ぎ方
- フローの状態をどこに置くか。1要素目・2要素目（0050）・登録を、既存のセッションと制限つきのセッションにどうつなぐか
- 無効化・アカウントの消去・統合（0082）・フィーチャーの無効化（0073）・書き出しと読み込み（0068）での扱い
- 既存の passkey・TOTP・パスワードをいつ・どう移すか

最初の方式には HOTP（RFC 4226）を選ぶ。秘密を持ち、カウンターを進める（使った値を2度通さない）ので、暗号化・同時の更新・
再同期というポートの難しいところを一通り使い、外部への送信も無いので試しやすい。

## 決定

### ポート

`shared/port/authenticator.go` に置く。

- `MethodInfo`：名前（`^[a-z][a-z0-9_]{0,31}$`）、動かすフィーチャー、要素の種類（知識・所持・生体）、`amr`、出せる AAL の上限、
  用途（`first_factor`・`second_factor`・`recovery`・`step_up`）、データの形のバージョン
- `Authenticator`：`Info`・`Begin`・`Complete`・`EnrollBegin`・`EnrollComplete`・`Revoke`。入力と出力の `Payload` は方式ごとの JSON、
  `State` はフローの間だけ持つ方式の状態（コアが封をして預かる）
- 方式に渡すのは `MethodEnv`（realm、ユーザー（1要素目の始めは空）、用途、時刻、発行者の名前、表示用のアカウント名）と、
  `CredentialStore`（`List`・`FindByLookup`・`Create`・`Update`）だけにする。方式は Storage・EphemeralStore・セッションを触らない
- 方式は `features/<name>` の `init` で `method.Register` に登録し、フィーチャーが動いているときだけ使う（`method.Active`）。
  組み込みとテストのために `app.Deps.Methods` でも渡せる（フィーチャーを問わずに動く）
- `Complete` は確かめた認証情報（と、方式が足す `amr`）を返す。セッションの AAL・`acr` は、この ADR では求めない（0090 の別の ADR）

### 汎用の認証情報

- テーブル `authn_credentials`（SQLite 00036、PostgreSQL 00019）：`id`、`public_id`（`crd_…`）、`realm_id`、`user_id`、`method`、
  `lookup`、`data`、`data_version`、`created_at`、`last_used_at`、`revoked_at`、`revoke_reason`。
  Storage のポートは `CredentialRepo`（`Tx.Credentials()`）で、方式を知らない
- `data` は方式固有のデータで、ユーザーのデータ鍵で暗号化する（9.5、0014）。AAD は `authn.credential.<方式>.<内部 ID>` にし、
  別の行・別の方式への差し替えを拒否する。平文の秘密は Storage に置かない
- `lookup` は方式が宣言した検索キー（passkey の credential ID など）のブラインドインデックス（`pii.Crypter.Index`、用途
  `authn.credential.<方式>`）。無効化していないものの中で `(realm_id, method, lookup)` を一意にする（部分一意インデックス）。
  インデックスの鍵の切り替えに追従する列（`lookup_key_id`）は、検索キーを使う方式を足すときに足す（HOTP は使わない）
- 更新は `UpdateData(realm, id, old, new)` の比較と交換にする。今の暗号文が `old` と同じで、無効化していないときだけ書く。
  使ったカウンターを進める更新が同時に2つ来ても1つしか通らないので、使い捨ての値の再使用を原子的に拒否できる
- ストアは realm と方式に閉じる（`authn/method.Store`）。他の realm・他の方式・無効化した認証情報は、方式からは見えない
- 消去（`AuthnRepo.Erase`）で行を消し、統合（0082）では、無効化していないものを統合先のデータ鍵で暗号化し直してから
  `MoveUser` で移す。書き出しと読み込み（0068）は表を列挙するので、そのまま運ぶ

### フロー

- `Begin`・`EnrollBegin` が返す方式の状態は、`Crypter.Seal`（用途 `flow.method`）で封をして EphemeralStore に置く。キーはフロー ID
  （ランダム）の SHA-256 で、フロー ID は平文で置かない
- フローは realm・ユーザー・方式・種類（`login`・`second_factor`・`enroll`）に結び付け、`Take` で1回限りにする。照合に失敗したら、
  回数の上限（`security.second_factor.max_attempts`）までは同じフロー ID を使えるように置き直す。期限は `security.second_factor.ttl`
- 1要素目：方式の `Complete` の後、コアがもう一度認証情報を読み、無効化していないこととユーザーの状態（`account.Check`）を確かめ、
  既存の `Issue` でセッションを発行する（2要素目が要れば制限つき）。理由は返さず `authentication_failed` にする（0022）
- 2要素目：制限つきのセッション（`second_factor`・`enroll`）で、0050 の `CompleteSecondFactor` に渡す。`amr` は方式の `amr` と `mfa`。
  照合はユーザーごとにレートリミットする（`security.login.rate_limit.per_account`）
- 登録：完了は1つのトランザクションで、最初の強い認証手段ならリカバリーコードを出す。登録だけのセッション（`next: enroll`）で
  完了すると、登録の確認を2要素目として通常のセッションに替える（TOTP と同じ）。復旧専用のセッションでも登録できる
- 2要素目の候補（`second_factor_methods`）には、2要素目に使える方式で、本人が無効化していない認証情報を持つものの名前を加える。
  セッションが使った認証情報は `crd_…` で記録し、無効化すると遅くとも `validity_max_delay` の後にそのセッションを使えなくする

### HTTP

- 0090 の汎用のパス（`/v1/login/methods/{method}:begin`・`:complete`、`/v1/login/second-factor/{method}:begin`・`:complete`、
  `/v1/me/credentials/{method}:enroll-begin`・`:enroll-complete`、`/v1/me/credentials/{id}:revoke`）を足す。
  `/v1/login/` の下なので、応答時間の下限と接続元ごとのレートリミットが効く
- 制限つきのセッションで使えるパスは、汎用のパスの形で判定する（2要素目のパスは `second_factor`・`enroll`、登録のパスは
  `enroll`・`recovery`）。登録だけのセッションでは、2要素目に使える方式だけを登録できる
- この ADR では、ペイロードを方式ごとの JSON（OpenAPI では任意のオブジェクト）にする。0090 の、方式が JSON Schema を宣言して
  OpenAPI に `oneOf` で載せる形は、方式が増えたときに足す
- `/v1/me/methods` と管理 API の `/v1/admin/users/{id}/credentials` に汎用の認証情報（`credentials`）を載せる。運営者の無効化は
  `crd_…` の ID で、一括の無効化は件数を `credentials` で返す
- 方式の `Revoke` は本人による無効化のときだけ呼ぶ。運営者の無効化・一括の無効化・消去では呼ばない（方式の失敗で、
  侵害への対応を止めない）。1要素目に使える方式の最後のログインの手段なら、本人は無効化できない（`409 last_method`）

### HOTP

- `authn/method/hotp`、フィーチャー `hotp`（既定オフ）。所持の要素、`amr` は `otp`、AAL の上限は 2、2要素目だけ
- データは種（20 バイト。16〜64 バイトを受け付ける）、次に期待するカウンター、桁数（6〜8）。種はデータごと暗号化する
- 照合は次に期待するカウンターから 10 個先まで（look-ahead）。窓の中の全部を定数時間で比べ、早く抜けない。通ったら
  カウンターをその次に進め、比較と交換で書く（同時の使用・使ったコードは通らない）
- 窓の外は、続けて出した2つのコード（`code`・`next_code`）で 200 個先まで探して再同期する
- 登録は、種を本人が渡すか（base32）、iam が作る。`otpauth://hotp/…` の URI を返し、カウンター 0 のコードで確かめて 1 から使う。
  1人 5 個まで（`409 credential_limit`）
- RFC 4226 付録 D のテストベクタで確かめる

### 既存の方式の移行（方針だけ。この ADR では移さない）

- passkey・TOTP・パスワードの順に、1 方式ずつ別の PR で移す。それぞれ、方式を `authn/method/<name>` に作り、
  既存のテーブルから `authn_credentials` へ写すマイグレーションを足す。移したことは台帳（0011、0073）に記録し、
  起動時の突き合わせで、移す前のバイナリが移した後の DB で動かないようにする
- 移す段では、読みは新しい表を先に見て、無ければ古い表を見る。書きは新しい表だけにする。古い表は、次のリリースで消す
- 戻すときは、移す前に `iam storage export` で書き出したものを `iam storage import` で読み込む。移した後の新しい登録は、
  戻した先では失われることを運用文書に書く
- 方式専用のパス（`/v1/me/passkeys` など）は互換のために残し、中で汎用の方式を呼ぶ

### この ADR の外

- 外部 Authenticator のアダプタ（HTTP・gRPC。信頼の境界は 0090）は、別の PR で足す
- セッションの AAL・`acr` と step-up は、別の ADR で決める
- ホスト型のログイン画面には、汎用の方式をまだ出さない

## 結果

- 方式を足す変更が `authn/method/<name>/` と `features/<name>` に閉じる。Storage アダプタ・コア・OpenAPI を変えずに方式を足せる
- 方式は秘密を平文で置けず、使い捨ての値の再使用を、方式ごとにロックを書かずに防げる
- 方式固有のデータは DB の上で検索・集計できない。検索の要るものは `lookup` に限る
- 方式の `Revoke` を運営者の無効化で呼ばないので、方式の外の資源（外部の登録など）が残ることがある。方式は、それを本人の無効化か
  外部の側で片付ける
- 既存の方式を移すまでは、方式専用の表と汎用の表の両方を扱うコードが残る

## 検討した代替案

- フローの状態を方式に EphemeralStore で持たせる：方式ごとに封・1回限り・回数の上限を書くことになり、間違えやすい
- 再使用の拒否を方式ごとのロックや `last_used` の列で行う：方式ごとに Storage の列が要り、0090 の「Storage は方式を知らない」に反する。
  暗号文の比較と交換なら、どの方式のデータにも使える
- カウンターを暗号化しない列に出す：HOTP にしか使えず、データの形が方式の外に漏れる
- 方式の `Revoke` を運営者の無効化でも呼ぶ：方式の失敗で、侵害への対応（一括の無効化）が止まりうる
- 既存の方式を一度に移す：戻しにくく、レビューも大きくなる
