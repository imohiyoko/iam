# 0106. passkey を認証方式のポートに載せ、方式専用の表から authn_credentials へ起動時に移す

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 3.1、4.1、4.4、4.6、11.6、11.12、[0011](0011-build-time-features.md)、[0050](0050-second-factor.md)、
  [0068](0068-storage-export-import.md)、[0082](0082-account-merge.md)、[0090](0090-authenticator-plugins.md)、
  [0092](0092-authenticator-port-implementation.md)、[0093](0093-acr-aal-step-up.md)、[0096](0096-passkey-attestation.md)、
  [0101](0101-port-totp-and-password.md)、[0103](0103-x509-client-certificates.md)

## 背景

0101 は TOTP とパスワードを認証方式のポート（0092）に載せ、方式専用の表から `authn_credentials` へ起動時に移した。残る passkey
（WebAuthn。`authn/passkey`）も同じ形に移す。passkey には TOTP・パスワードに無い事情がある。

- 無効化した credential ID は再登録させない（4.6）。今は `authn_revoked_passkey_credentials` に持ち、ユーザーを消しても残る。
  `authn_credentials` の行は消去で消えるので、行に頼ると消去の後に再登録できてしまう
- passkey ごとに「この passkey でログインしたときに入る Org」（`preferred_org_id`。4.4）を持つ。Org の統合・移動は SQL で
  付け替えるので、暗号化した方式のデータには置けない
- 1要素目（discoverable credential。本人が分からないまま始める）と 2要素目（本人の passkey を並べる）で、チャレンジの作り方が違う
- 登録の確認で attestation のポリシー（0096）を評価し、拒んだ理由（形式・AAGUID・信頼の起点）を監査ログに残す
- チャレンジは 1 回限り。失敗した後に同じチャレンジで試し直させない
- 公開 API（`/v1/login/passkey:*`、`/v1/login/second-factor/passkey:start` と `:verify`、`/v1/me/passkeys*`、
  `/.well-known/webauthn`）と、監査ログの種類（`passkey.registered` など）、amr（`hwk`・`user`）・AAL を変えない

## 決定

### 方式

- `authn/method/passkey`（方式 `passkey`）：所持の要素、`amr` は `hwk`（本人の確認（UV）があれば `user` を足す）、AAL の上限は 2。
  使い道は 1要素目・2要素目・step-up。コアの方式（`MethodInfo.Feature` は空）で、RP（`passkey.rp_id`・`origins`）を決められた
  ときだけ組み込みに加える（今までどおり）
- WebAuthn の確認は今までどおり go-webauthn に任せる。attestation の確認と評価（`authn/passkey/attestation`）は
  `authn/method/passkey/attestation` に移すだけで、中身は変えない。ポリシーはフィーチャー `passkey_attestation` が動いていれば
  方式に渡す（0096 のまま）
- データ（ユーザーのデータ鍵で暗号化した JSON）は credential ID・公開鍵（COSE）・アルゴリズム・署名の回数・フラグ・AAGUID・
  transports・ユーザーハンドル・名前・attestation の形式と確認の結果。ユーザーハンドルは必ず持つ（移す前の空は、持ち主の公開 ID を入れる）
- 検索キーは credential ID（base64url）で、方式ごとのブラインドインデックスにする（0092）。1要素目は、認証器が返した credential ID で
  引き、ユーザーハンドルが合うことを確かめる。2要素目は、本人の passkey の中から credential ID が合うものを使う
- 署名の回数が戻ったもの（複製の疑い）は拒む。署名の回数の更新は比較と交換で書き、同時の使用は片方が失敗する
- 名前の規則（空なら `Passkey`、前後の空白を除く、長さの上限）は方式に置き、方式専用の名前の変更も同じ規則を使う

### ポートに足すもの

- `MethodInfo.OneShot`：チャレンジを 1 回だけ試せる方式。コアは、失敗したフローを（回数の上限の内でも）作り直さずに消す。
  passkey は失敗した署名を同じチャレンジで試し直させない
- `MethodInfo.ReserveRevokedLookups` と `Credential.ReserveLookup`：無効化した認証情報の検索キーを、退役した検索キー
  （`authn_retired_credential_lookups`。realm・方式・検索キー・鍵の ID）に残し、再登録を `Conflict` で拒む。退役した検索キーは
  ユーザーの消去で消さない（credential ID は認証器が決める値で、個人情報を含まない）。インデックスの鍵を切り替えた後も、退役に使った
  鍵で確かめる（0103 の前の鍵の引き当てと同じ）。消した鍵で作ったものは確かめられない
- `Credential.PreferredOrgID`（`authn_credentials.preferred_org_id`）と `CredentialRepo.SetPreferredOrg`：passkey の既定の Org。
  Org の統合・移動の付け替えは `authn_credentials` を SQL で更新する
- `MethodEnv.UserPublicID`：登録の始めに、本人の公開 ID を渡す（WebAuthn の `user.id`。今までどおり公開 ID）
- `MethodResult.Details`・`MethodEnrollment.Details` と、エラーの `MethodAuditDetails`：方式が監査ログに足す値。コアは
  ログインの成功・失敗、登録の成功・失敗の監査ログに混ぜる（`passkey_id`、attestation の形式・AAGUID・拒んだ理由など。0096 のまま）

### コアのサービス

- 方式専用のパスも、汎用のパス（0092）と同じコアのサービス（`credential.Service`）を通す。フローの状態はコアが封をして預かり、
  1 回限りで、回数の上限・本人ごとの上限・ロックアウト（0105）が passkey の 2要素目と登録にも効く
- 登録の失敗（attestation のポリシーで拒んだもの、無効化した credential ID など）は `passkey.registration_failed` に残す
  （`credential.EnrollFailed`）。passkey の監査ログの種類は、汎用のパスでも `passkey.*` のまま
- 登録の完了は、1 つ目の passkey の登録で作る復旧コードと同じトランザクションで行う

### セッション

- passkey のセッションは、使った passkey に結び付ける（今までどおり）。移した passkey は内部 ID（`psk_…`）を保つので、
  移す前のセッションの結び付きがそのまま効く。新しく登録したものは `crd_…`
- 2要素目の候補は passkey を先に並べる（今までどおり）

### 移行

- 方式専用の表（`authn_passkeys`）の行は、起動のたびに `authn_credentials` へ移す（`credential.MigratePasskeys`。0101 の
  `MigrateLegacy` の後）。1 行ずつ、新しい行を作って古い行を消すのを同じトランザクションで行う。無効化したものも移す
  - 内部 ID と公開 ID（`psk_…`）、作成・最後の使用・無効化の時刻、既定の Org を保つ
  - 無効化した credential ID（`authn_revoked_passkey_credentials`）は、退役した検索キーへ移す。持ち主を消した後のものも移す
  - 移せなければ（持ち主が無く、ユーザーハンドルも無いなど）、移さずに起動を止める（fail-closed）。古い行は残る
- SQL のマイグレーションは、`authn_credentials` の列（`preferred_org_id`・`reserve_lookup`）と退役した検索キーの表を足す
  （SQLite 00050・00051、PostgreSQL 00033・00034）。古い表は形を変えず、次のリリースで消す
- 移したことは台帳に `migration:authn_credentials_passkey` として記録する（0101 の `migration:` の扱い）。移す前のバイナリは
  起動を拒む。移す前のサーバーを止めてから移した後のサーバーを起動し、戻すときは移す前の `iam storage export` を読み込む（0068）

### HTTP

- 方式専用のパスは残し、中で同じ方式とコアのサービスを呼ぶ。要求と応答の形は変えない
- 汎用のパスで passkey を使える。`/v1/login/methods/passkey:begin`・`:complete`、`/v1/login/second-factor/passkey:begin`・
  `:complete`、`/v1/me/credentials/passkey:enroll-begin`・`:enroll-complete`。payload は `{"credential": …, "name": …}`、
  チャレンジの payload は `navigator.credentials.get`・`create` に渡す options（`{"publicKey": …}`）
- `/v1/me/passkeys:finish` に `429`（本人ごとの回数の上限）を足す
- `/v1/me/methods` と管理 API の一覧は、passkey を今までどおり `passkeys` の欄に出し、汎用の `credentials` には載せない

### 片付け

- 消去は `authn_credentials` の passkey を消し、退役した検索キーは残す。統合（0082）は、passkey を同じ ID のまま統合先へ移す
  （汎用の認証情報として、統合先のデータ鍵で暗号化し直す）。ユーザーハンドルはデータにあるので、移した後も同じ認証器で使える

## 結果

- passkey の規則が `authn/method/passkey` に閉じ、方式専用のパスと汎用のパスが同じ処理で動く。`authn/passkey` は無くなる
- 方式専用の表を扱うコード（`authn_passkeys` の読み書き）は移行だけになる。0101 と合わせ、すべての方式が `authn_credentials` に載る
- passkey の 2要素目と登録に、ほかの方式と同じ回数の上限とロックアウトが効く（前は効いていなかった）
- フローの期限は、コアのフローの期限（`security.second_factor.ttl`）と方式の期限（5 分）の短い方になる
- 移す前のバイナリには戻せない（台帳が拒む）

### 追記（2026-11-02）：未公開のため移行を外した

このソフトウェアはまだ公開していないので、移す前のデータは無い。「移行」の節のうち、次を外した（`authn_credentials` の列
（`preferred_org_id`・`reserve_lookup`）と退役した検索キーの表、ほかの決定はそのまま）。

- 方式専用の表（`authn_passkeys`・`authn_revoked_passkey_credentials`）を消すマイグレーションを足した（SQLite 00061、PostgreSQL 00044）。
  Storage のポートとアダプタから `PasskeyRepo` と、移行でだけ使う `CredentialRepo.Retire` を消した（退役は無効化の中でだけ行う）
- 起動時の移行（`credential.MigratePasskeys`）と、台帳の `migration:` の記録の扱いを消した（0101 の追記と同じ）
- 移した passkey が保つはずだった `psk_` の ID の接頭辞と、その分岐（セッションの結び付き、Org の選択・ポリシー、運営者の無効化）を消した。
  passkey の ID は汎用の `crd_` だけ

## 検討した代替案

- **無効化した credential ID を `authn_credentials` の無効化した行で拒む**：消去で行が消えると再登録できる（4.6 に反する）
- **退役した検索キーを passkey 専用の表のまま使う**：方式ごとに表が要る。検索キーのブラインドインデックスで汎用にすれば、
  ほかの方式（ハードウェアのトークンなど）も同じ仕組みで再登録を拒める
- **既定の Org を方式のデータに置く**：Org の統合・移動の付け替えが、ユーザーごとの復号と暗号化し直しになる
- **新しく登録したものも `psk_…` にする**：方式ごとに ID の接頭辞を変える分岐がコアに要る。移したものの ID を保てば、
  セッションの結び付きと公開 ID はそのまま効く
- **方式専用のパスを、コアのサービスを通さずに残す**：0101 と同じ理由で、回数の上限・監査・セッションの扱いが二重になる
