# iam

セルフホストできる認証・認可基盤（実験段階）。

- 設計: [docs/design.md](docs/design.md)
- ロードマップ: [docs/roadmap.md](docs/roadmap.md)
- 設計判断の記録（ADR）: [docs/adr/](docs/adr/README.md)
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

## テスト

アダプタは別の Go モジュールなので、モジュールごとに実行します。

```sh
scripts/modules.sh go test -race ./...
```
