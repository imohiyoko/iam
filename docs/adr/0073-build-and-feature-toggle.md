# 0073. iam build は imports.go を差し替えてビルドし、フィーチャーの無効化はデータが 0 件になって完了する

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 11.11、11.12、13.8、[0010](0010-feature-toggles.md)、[0011](0011-build-time-features.md)

## 背景

ホスト先は使うフィーチャーとアダプタだけを含むバイナリを作り（11.11）、構成の変更を台帳と突き合わせて安全に進める（11.12）。
公式イメージには署名・SBOM・provenance を付ける（13.8）。

## 決定

- フィーチャーの登録を実装から分ける。実装のパッケージ（`authn/org` など）は宣言（`org.Feature` など）を公開するだけにし、
  `features/<name>` を import したときに登録される。アダプタはこれまでどおりパッケージ自身が登録する
- `cmd/iam/imports.go` がバイナリに含めるものを決める。リポジトリのものは全部入りで、`iam build -all -print` の出力と一致することをテストで確かめる
- `iam build -f build.yaml -o iam`：build.yaml（`features`、`adapters`）を確かめ（既知の名前、起動に要るアダプタの種類、
  フィーチャーの依存）、生成した imports.go を `go build -overlay` で差し替えてビルドする。ソースは書き換えない。Go とリポジトリのソースが要る
- `iam features plan -build build.yaml`：台帳・設定と次のバイナリを突き合わせ、起動を拒否する理由（台帳にあるのに含まない、
  設定で有効なのに含まない、データ形式が新しすぎる）と、配った後の手順を表示する。拒否する理由があれば終了コード 1
- `iam features disable [-purge] <name>`：依存するフィーチャーが台帳にあれば拒否する。台帳を disabling にし（再起動したサーバーは書き込まない）、
  データの件数を数える。`-purge` なら片付けてから数える。0 件なら台帳から消して完了、残れば disabling のまま終了コード 1
- データ：password はパスワード、quota は付与、org_login_policy は Org の設定のポリシー（ほかの設定は残す）、org は削除されていない共有 Org。
  共有 Org は CLI では片付けず、運営者が管理 API で削除する。個人 Org と Membership は残し、再び有効にしたときに使う
- 公式イメージは全部入りと最小構成（`build/minimal.yaml`：org・warnings、PostgreSQL・Redis・env の KeyStore・stdout と OTLP・Webhook の通知）。
  distroless の nonroot。タグで GHCR に push し、cosign のキーレス署名、BuildKit の SBOM と provenance、GitHub の attestation を付ける。
  バイナリにも SPDX の SBOM、cosign の署名、provenance を付ける

## 理由

- `-overlay` ならソースの書き換えも build tag も要らず、手元と CI とイメージのビルドが同じ手順になる
- 登録を分ければ、含めないフィーチャーは台帳との突き合わせでも動かない。実装のコードはリンクされるが、
  データの読み書きのコードが残るため、無効化した後に残ったデータ（個人 Org など）も扱える
- 共有 Org の削除は猶予期間・招待の取り消し・鍵の削除を伴うため、既存の削除の手順を通す

## 影響

- テストでフィーチャーを使うパッケージは `features/all` を import する
- フィーチャーを足したら、`features/<name>` とカタログ（`server/buildspec`）に足し、imports.go を作り直す
- 実装のコードを含めない（サイズと攻撃面を減らす）には、サーバーの組み立てをフィーチャーごとに分ける必要があり、後に回す

## 検討した代替案

- build tag：組み合わせが増えるとテストできず、11.11 で使わないと決めている
- imports.go を書き換えてビルド：作業ツリーが汚れ、並行のビルドがぶつかる
