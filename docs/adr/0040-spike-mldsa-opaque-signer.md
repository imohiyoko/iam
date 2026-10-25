# 0040. ML-DSA-65 の ID トークンは go-jose の OpaqueSigner で署名でき、kid は自前で付ける

- 状態: 承認
- 日付: 2026-10-25
- 関連: [design.md](../design.md) 9.3、[0038](0038-library-selection.md)、roadmap M0 のスパイク

## 背景

0038 では、zitadel/oidc（内部で go-jose v4 を使う）に `OpaqueSigner` で `crypto/mldsa` を差し込み、ML-DSA-65 の ID トークンを署名する方針にした。M5 の前に、これが本当に動くかを確かめる必要があった。

## 検証（`spikes/mldsa_jose_test.go`。Go 1.27.0、go-jose v4.1.6、zitadel/oidc v3.51.16）

| 確かめたこと | 結果 |
|---|---|
| `jose.NewSigner` に `OpaqueSigner`（alg `ML-DSA-65`）を渡して署名できるか | できる。署名は 3309 バイト（FIPS 204 の ML-DSA-65） |
| go-jose の `OpaqueVerifier` で検証できるか | できる。改ざんも検出する |
| go-jose を使わず `crypto/mldsa` だけで検証できるか（署名入力 `header.payload`、純粋な ML-DSA、空のコンテキスト） | できる |
| zitadel/oidc の OP が使う `op.SignerFromKey` を通して署名できるか | **署名はできるが `kid` ヘッダーが付かない** |
| `OpaqueSigner.Public()` で ML-DSA の公開鍵を返せるか | **できない**。go-jose の `JSONWebKey.IsPublic` が ECDSA / RSA / Ed25519 しか認めず `ErrNotPublic` になる。`nil` を返す必要がある |

`kid` が付かない理由：`op.SignerFromKey` は `SigningKey.Key()` を `JSONWebKey{Key, KeyID}` に包み、go-jose はその `KeyID` を、内側の鍵の公開鍵（`OpaqueSigner.Public()`）が取れたときにだけヘッダーに入れる。上のとおり ML-DSA では `Public()` が `nil` しか返せないため、`kid` が落ちる。`SignerOptions.WithHeader("kid", …)` を使えば付くが、`op.SignerFromKey` はオプションを外から渡せない。

## 決定

- ML-DSA-65 の署名は 0038 のとおり go-jose の `OpaqueSigner` + `crypto/mldsa` で行う（前提は成り立つ）
- ID トークンには必ず `kid` を付ける。M5 では次の順で対応する
  1. zitadel/oidc に、`SignerFromKey` が `WithHeader("kid", key.ID())` を付けるか、署名器を差し替えられるようにする変更を提案する（go-jose 側の `IsPublic` の拡張も併せて検討）
  2. 取り込まれるまでは、ID トークンの署名を IAM 側で行う（zitadel/oidc の `op` の外で `jose.NewSigner` を `WithHeader("kid", …)` 付きで呼ぶ経路を用意する）
- 署名の入力は JWS の規定どおり `BASE64URL(header) || "." || BASE64URL(payload)`。ML-DSA は事前ハッシュなし・空のコンテキストで使う

## 結果

- ML-DSA-65 の ID トークンについて、Go 本体や JOSE ライブラリを改造する必要はない（0038 の結論を確認）
- `kid` のために、M5 で上流への変更か、署名の経路の自前実装が要る
- スパイクのテストは、上流で挙動が変わったら失敗するように書いてある（変わったらこの ADR を見直す）

## 検討した代替案

- `kid` を付けない：JWKS に複数の鍵（ES256 と ML-DSA-65、ローテーション中の新旧）が並ぶため、RP が鍵を選べなくなる
- `Public()` に ECDSA などの偽の公開鍵を返して `IsPublic` を通す：JWKS や埋め込みの JWK に誤った鍵が出る危険があり採らない
