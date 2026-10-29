# iam

セルフホストできる認証・認可基盤（実験段階）。

- 設計: [docs/design.md](docs/design.md)
- ロードマップ: [docs/roadmap.md](docs/roadmap.md)
- 設計判断の記録（ADR）: [docs/adr/](docs/adr/README.md)
- 運用: [docs/operations.md](docs/operations.md)
- セキュリティ: [SECURITY.md](SECURITY.md)
- ライセンス: [Apache-2.0](LICENSE)

## 動かす（開発用）

Go 1.27 以上が必要です。

```sh
cp iam.example.yaml iam.yaml
go run ./cmd/iam keys generate -out keys.json
go run ./cmd/iam serve -config iam.yaml
curl localhost:8080/healthz   # 公開 API
curl localhost:8081/healthz   # 管理 API
```

## 構成を選んでビルドする

使うフィーチャーとアダプタだけを含むバイナリは `iam build` で作ります（[build/minimal.yaml](build/minimal.yaml) が例）。

```sh
cd cmd/iam
go run . build -f ../../build/minimal.yaml -o iam
cd ../..
docker build --build-arg BUILD_SPEC=build/minimal.yaml -t iam:minimal .   # リポジトリの直下で
```

## テスト

アダプタは別の Go モジュールなので、モジュールごとに実行します。

```sh
scripts/modules.sh go test -race ./...
```
