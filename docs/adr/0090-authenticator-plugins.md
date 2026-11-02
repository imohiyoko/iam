# 0090. 認証方式を共通のポートを持つプラグインにし、1 方式 1 ディレクトリで持つ

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 2.2、2.4、4.1、[0003](0003-ports-and-adapters.md)、[0012](0012-extensible-data-model.md)、
  [0050](0050-second-factor.md)、[0073](0073-build-and-feature-toggle.md)、[0081](0081-flow-hooks.md)、[0089](0089-enterprise-full-scope.md)

## 背景

認証方式のロジックは `authn/passkey`・`authn/totp`・`authn/password` などに分かれている。ただ、方式を 1 つ足すと、次の場所すべてを変える必要がある。

- `shared/port` の方式専用の Repo（`PasskeyRepo`・`TOTPRepo`・`PasswordRepo`）
- すべての Storage アダプタ（メモリ・SQLite・PostgreSQL）の、方式専用のテーブルと実装
- `server/app` の方式専用のハンドラ
- `api/public.yaml` の方式専用のパス
- 2 要素目の確認（passkey と TOTP に固定）
- ホスト型ログイン画面

ポリシーも `amr` の文字列を直接見ていて、方式の強さを表す概念が無い。0089 で SAML・X.509・Kerberos・SMS・プッシュ・
Verifiable Credentials などを足し、まだ無い技術も後から足せるようにするには、方式をコアの外で足せる形が必要になる。

## 決定

- 方式は `authn/method/<name>/` に 1 方式 1 ディレクトリで置く。ロジック、方式固有のデータの形、HTTP のペイロード、画面の断片を、
  そのディレクトリの中に閉じる。`features/<name>` を import すると登録される（0073 と同じ）
- 共通のポート `Authenticator` を `shared/port` に置く
  - 宣言：名前、要素の種類（知識・所持・生体）、`amr` の値、到達できる AAL、使える用途（1 要素目・2 要素目・復旧・step-up）
  - ログイン：`Begin`（チャレンジを作る）と `Complete`（応答を確かめ、ユーザーと認証情報を返す）
  - 登録：`EnrollBegin` と `EnrollComplete`、無効化：`Revoke`
  - 方式は Storage を直接触らず、コアが渡す認証情報のストアとエフェメラルなストアだけを使う
- 認証情報は汎用のストア `authn_credentials` に置く。共通の列（方式、ユーザー、外部 ID、状態、作成・最終使用・無効化の時刻）と、
  方式固有のデータ（ユーザーのデータ鍵で暗号化した blob と、その形のバージョン）を持つ。Storage アダプタは方式を知らない。
  検索の必要な値（passkey の credential ID、X.509 の証明書の指紋など）は、方式が宣言したキーでブラインドインデックスにする
- 既存の passkey・TOTP・パスワードのテーブルは、方式ごとに `authn_credentials` へ移す。移行は 1 方式ずつ行い、
  `iam storage export / import` と台帳（0011）で戻せるようにする
- HTTP は汎用にする：`/v1/login/methods/{method}:begin`・`:complete`、`/v1/login/second-factor/{method}:begin`・`:complete`、
  `/v1/me/credentials/{method}:enroll-begin`・`:enroll-complete`・`/{id}:revoke`。ペイロードは方式が JSON Schema で宣言し、
  OpenAPI には方式ごとの schema を `oneOf` で載せる。今の方式専用のパスは、互換のために残す
- ポリシーは方式の名前でなく強さで書く。セッションに `acr` と AAL（SP 800-63B）を持たせ、Org のログインポリシー、
  OIDC の `acr_values`、認可の条件（0084）で「AAL2 以上」「所持の要素を含む」のように指定できるようにする
- AAL の求め方：方式が宣言するのは、その方式が出せる AAL の**上限**と、その前提（UV が要る、ハードウェアの鍵に限る、など）だけにする。
  セッションの AAL と `acr` は、コアが**その認証で実際に確かめた要素**（`Complete` が返す、要素の種類・前提を満たしたか）から求める。
  セッションは、認証のときの AAL を引き継ぎ、それより高くみなさない（SP 800-63B-4 のセッション管理）。step-up で要素を足したときは、足した後の要素の組で求め直す。
  具体的な対応表と `acr` の値は、別の ADR（acr・AAL と step-up）で決める
- 別のプロセスの方式：外部 Authenticator のアダプタを足す。Go 以外の実装や、iam のリリースを待たない方式を足せる。信頼の境界は次のとおり
  - HTTP：TLS の上で、フロー フック（0081）と同じ HMAC の署名（`"<時刻>." + 本文`、時刻の許容幅と、要求 ID による再送の拒否）を両方向に付ける。mTLS も選べる
  - gRPC：mTLS を必須にし、相手の証明書を設定で固定する。0081 の署名はそのまま使わず、メッセージの中に要求 ID・時刻・realm・方式名を入れ、
    応答はその要求 ID に結び付ける（別の要求の応答の使い回しを拒否する）
  - どちらも、呼べるメソッドは `Begin`・`Complete`・`EnrollBegin`・`EnrollComplete`・`Revoke` に限り、要求と応答にスキーマのバージョンを持つ。
    タイムアウト（5 秒まで）・キャンセルを付け、失敗・タイムアウト・形の誤りは認証の失敗にする（fail-closed）
  - 外部の方式は、宣言した AAL の上限を超えられない。上限は iam の設定で決め、外部の応答では上げられない

## 結果

- 方式を足す変更が `authn/method/<name>/` と `features/<name>` に閉じ、Storage アダプタとコアを変えなくてよくなる
- 方式固有のデータを暗号化した blob にするので、DB の上では検索・集計できない。必要な検索キーは宣言してインデックスにする
- 移行の間は、新旧の両方の形を扱うコードが残る
- 外部 Authenticator は、ネットワークの遅延と障害の面が増える。ホットパス（トークンの検証、認可の判定）には入らないので、0010 には反しない

## 検討した代替案

- 方式ごとのテーブルのまま、生成で Repo を足す：Storage アダプタの変更は無くならず、外部の方式を足せない
- Go の `plugin` パッケージで実行時に読み込む：OS・ビルド条件の制約が大きく、ビルド時に選ぶ方針（0011）とも合わない
- 方式固有のデータを平文の JSON で持つ：秘密（TOTP の種など）があり、0014 の暗号化の方針に反する
