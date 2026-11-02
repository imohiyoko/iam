# 0096. passkey の attestation と認証器のポリシー

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 2.8、3.1、4.1、4.4、9.4、11.0、11.12、[0010](0010-feature-toggles.md)、
  [0022](0022-deny-reason-disclosure.md)、[0033](0033-security-settings-hierarchy.md)、[0038](0038-library-selection.md)、
  [0049](0049-passkey-details.md)、[0062](0062-org-tier-settings.md)、[0069](0069-org-login-policy.md)、
  [0089](0089-enterprise-full-scope.md)、[0090](0090-authenticator-plugins.md)

## 背景

passkey の登録は attestation を求めていない（`none`）。認証器が名乗る AAGUID は自己申告で、どの機種かを確かめられない。
企業では「会社が配った認証器（特定の機種、FIDO の認定を受けたもの）だけを使わせたい」という要件が多い。
同期する passkey（クラウドの鍵）を禁じ、ハードウェアの鍵だけを許したい Org もある。

機種を確かめるには、登録のときに attestation を求め、その証明書の連なりを信頼の起点（認証器の製造元のルート証明書）まで
たどる必要がある。信頼の起点と機種の情報（名前、認定のレベル、脆弱性の報告）は FIDO Metadata Service（MDS3）の BLOB に
まとまっている。BLOB は FIDO Alliance が署名した JWT で、定期的に更新される。

制約：

- ホットパス（登録・ログイン）で外部を同期で呼ばない（0010）
- 拒否の理由は本人確認の後にだけ返す（0022）
- 設定は realm と Org の段に置く（0033、0062）。Org の入場の条件は 0069 のログインポリシーにある
- 既存の passkey は attestation を確かめずに登録されている

## 決定

### フィーチャーと attestation の要求

- フィーチャー `passkey_attestation`（既定オフ）。オフなら今までと同じで、登録は attestation を求めず、ポリシーも判定しない
- オンのとき、登録の開始で attestation を求める。求め方（conveyance）は設定 `passkey.attestation.conveyance`
  （`none` / `indirect` / `direct` / `enterprise`）。既定は `none`。`enterprise` は認証器が許した RP にだけ個体を識別できる
  attestation を返すもので、運営者が明示して選ぶ
- 形式（packed・tpm・android-key・apple・fido-u2f）の署名の検証は go-webauthn（0038）に任せる。信頼の起点までの連なりは
  IAM のメタデータで確かめる（go-webauthn の MDS の取得は使わない）

### 信頼の起点とメタデータ

- 信頼の起点は2つ。FIDO MDS3 の BLOB と、設定 `passkey.attestation.trusted_authenticators`（AAGUID・名前・ルート証明書の
  PEM）。後者は MDS に載っていない社内の認証器や、検証の環境に使う。同じ AAGUID が両方にあれば、ルートは両方を使い、名前は設定を優先する
- BLOB はポート `FIDOMetadataSource`（`Fetch`）から読む。アダプタは `file`（パス）と `http`（既定は FIDO の公開の URL、
  https のみ、30 秒のタイムアウト、64 MiB まで）。ホスト先が自分の取得の仕組みを持つなら、ポートを差し替える
- BLOB の署名を、設定のルート証明書（`metadata_root_file`。無ければ FIDO の本番のルート）で確かめる。確かめられない BLOB は捨てる
- 起動のときに一度読み（30 秒まで）、その後はバックグラウンドで `metadata_refresh`（既定 24 時間）ごとに読み直す。
  通し番号（`no`）が今のものより古い BLOB は捨てる。読めなければ前の BLOB を使い続け、警告を出す（`nextUpdate` を過ぎても同じ）
- 登録・ログインはメモリのメタデータだけを見る。外部を呼ばない

### 判定（認証器のポリシー）

ポリシーの項目：

| 項目 | 意味 |
|---|---|
| `allowed_aaguids` | 許可する AAGUID（空でなければ、このどれかであること） |
| `denied_aaguids` | 拒否する AAGUID |
| `min_certification_level` | 求める FIDO の認定レベル（`L1`〜`L3plus`）。MDS の status report で決める |
| `require_attestation` | 信頼の起点まで確かめた passkey だけを通す |

- 段は realm と Org。realm の段は設定ファイル `realm.passkey_policy` を既定に、realm の設定（管理 API）で上書きする。
  Org の段は Org のログインポリシー（0069）の `passkey` に置く。両方を満たすこと（厳しくする方向だけ）
- 判定の順：MDS の status report が望ましくないもの（`REVOKED`、`USER_VERIFICATION_BYPASS` など。go-webauthn の既定の一覧）なら、
  ポリシーに関わらず拒否する。次に段ごとに、attestation の要否、拒否の一覧、許可の一覧、認定のレベルの順に見る
- `require_attestation` が無ければ AAGUID は自己申告である。許可の一覧は「この機種を名乗るもの」を通す。強制したいなら
  `require_attestation` と組み合わせる
- 一覧はそれぞれ 200 件まで。AAGUID は小文字の UUID にそろえ、重複を除く

### 判定の場所

| 場所 | 段 | 外れたとき |
|---|---|---|
| 登録 | realm | `409 passkey_not_allowed`。passkey を保存しない |
| ログイン（1要素目） | realm | 署名を確かめた後に `403 passkey_not_allowed` |
| 2要素目 | realm | `403 passkey_not_allowed` |
| Org に入る（ログイン・切り替え） | Org | その Org に入れない。理由は `policy.passkey_authenticator`。passkey を使わない認証には効かない |

- 理由は `passkey_not_allowed` のコードだけ返す。どの条件に外れたか（`reason`）は監査ログにだけ残す（0022）
- 登録の拒否も、本人のセッションでの操作なので理由のコードを返す。ログインの拒否は署名を確かめた後なので返してよい

### 保存と既存の passkey

- `passkeys` に `attestation_format`（`none`、`packed` など）と `attested`（信頼の起点まで確かめたか）を足す。AAGUID は前から持っている
- 既存の passkey は `attestation_format = ''`、`attested = false` とする。AAGUID は自己申告として扱う
  - 許可・拒否の一覧と認定のレベルは、保存した AAGUID で判定する
  - `require_attestation` を入れると既存の passkey は通らない。利用者は登録し直す（入れる前に管理 API の一覧で `attested` を確かめる）
- 統合（0082）で移す passkey も、この2つの列を保つ
- 認証方式のプラグイン（0090）で passkey を `authn_credentials` に移すときは、この2つの列も移す

### 監査と管理 API

- `passkey.registered` / `passkey.registration_failed`、`login.succeeded` / `login.failed` に `aaguid`、`decision`（`allowed` /
  `denied`）、`reason`、`tier`、`authenticator_name`、`certification_level`、`status` を足す（分かるものだけ）。
  登録には `attestation_format` と `attested` も足す
- Org の段の拒否は `org.passkey_policy_denied`（Org、利用者、AAGUID、判定）。切り替えの拒否はトランザクションごと戻るため、
  別のトランザクションで判定し直して記録する
- 管理 API の利用者の認証情報の一覧（`/v1/admin/users/{id}/credentials`）の passkey に `aaguid`、`authenticator_name`、
  `attestation_format`、`attested` を足す

### フィーチャーの無効化

- 数えるものと片付け（11.12）：Org のログインポリシーの `passkey` と、realm の設定の `passkey_policy`。片付けで外す
- 設定ファイルの `realm.passkey_policy` は運営者が外す。フィーチャーがオフなら無視して警告する
- オフの間に、Org・realm にポリシーを新しく置く・変える更新は拒む（0069 の `require_sso` と同じ）

## 結果

- 企業が配った認証器だけを、realm と Org の段で強制できる。認定のレベルと脆弱性の報告も判定に使える
- MDS の取得はポートの裏にあり、ホットパスは外部を呼ばない。取得に失敗しても登録・ログインは止まらない
  （前の BLOB と設定の信頼の起点で動く）
- 既存の passkey は確かめていないので、`require_attestation` を入れると登録し直しが要る
- `require_attestation` が無いときの一覧は自己申告に頼る。強制にはならないことを文書で明示する
- attestation を求めると、利用者のブラウザが確認の画面を出すことがある。既定を `none` に保つ
- MDS の BLOB は数 MB あり、メモリに持つ

## 検討した代替案

- **go-webauthn の MDS の取得（`metadata/providers`）をそのまま使う**：取得が同期で、ホットパスから外部を呼びうる。
  取得の仕組みをホスト先が差し替えられない。採らない（検証の関数だけ使う）
- **ポリシーを Org の段だけに置く**：realm 全体で禁じたい機種（脆弱性の報告がある認証器など）を Org ごとに書く必要がある。採らない
- **既存の passkey を一律に拒む・一律に通す**：一律に拒むとポリシーを入れた瞬間に全員がログインできなくなる。
  一律に通すと許可の一覧が効かない。保存した AAGUID で判定し、`require_attestation` のときだけ登録し直しを求める
- **拒否の理由（どの条件か）を返す**：認証器の機種を探る手がかりになる。コードだけ返し、詳細は監査ログに残す（0022）
