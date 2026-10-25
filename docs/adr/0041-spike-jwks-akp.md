# 0041. AKP（ML-DSA-65）の鍵を含む JWKS は jwx で出力し、主要な Go の RP がそのまま読める

- 状態: 提案
- 日付: 2026-10-25
- 関連: [design.md](../design.md) 9.3、[0038](0038-library-selection.md)、roadmap M0 のスパイク

## 背景

9.3 では、JWKS に ML-DSA-65（`kty: AKP`、RFC 9964）と ES256 の鍵を並べて公開する。AKP を知らない RP が JWKS 全体を読めなくなると、ES256 だけを使う既存の RP まで壊れる。jwx で出力できるか、ほかの実装で読めるかを確かめた。

## 検証（`spikes/jwks_akp_test.go`、`spikes/gooidc_test.go`。jwx v4.6.0、go-jose v4.1.6、coreos/go-oidc v3.21.0、zitadel/oidc v3.51.16）

| 確かめたこと | 結果 |
|---|---|
| jwx で `*mldsa.PublicKey` を JWK にし、ES256 と並べた JWKS を出力できるか | できる。`{"kty":"AKP","alg":"ML-DSA-65","pub":…}`。`priv` は出ない。2鍵で約 2.8KB |
| ライブラリを使わず（素の JSON + `crypto/mldsa`）に JWKS の鍵を読み、go-jose で作った ID トークンを検証できるか | できる |
| jwx で JWKS を読み直し、go-jose で作ったトークンを検証できるか | できる |
| **coreos/go-oidc**（Go で最も広く使われる RP ライブラリ）が、AKP の混ざった JWKS で ES256 のトークンを検証できるか | できる（未知の kty を読み飛ばす） |
| **zitadel/oidc の rp** が同じ条件で検証できるか | できる（未知の kty を読み飛ばす） |
| go-jose の `JSONWebKeySet` を直接 `json.Unmarshal` した場合 | **失敗する**（`unsupported key type/format`） |

## 決定

- JWKS は 9.3 のとおり1つにし、AKP と ES256 を並べて jwx で組み立てる
- go-jose を直接使う RP など、未知の kty で JWKS 全体の読み込みに失敗する実装がありうることを、利用者向けの文書の「既知の差異」に書く
- M5 で、主要な言語の RP ライブラリ（Go 以外も含む）で AKP の混ざった JWKS を読めるかを確かめる。問題が多ければ、ES256 だけの JWKS を別の URL で出す設定を追加する（Discovery の `jwks_uri` を連携先ごとに選べるようにする案）

## 結果

- 9.3 の方針（JWKS は1つ）を変えずに進められる
- 一部の RP の実装では JWKS の読み込みに失敗しうる。その場合の回避策は M5 で用意する

## 検討した代替案

- AKP の鍵を最初から別の JWKS に分ける：主要な Go の RP は混ざった JWKS を読めるため、今は複雑にしない
- ML-DSA の鍵を JWKS に載せず、連携先ごとに手で配る：鍵のローテーションが運用頼みになる
