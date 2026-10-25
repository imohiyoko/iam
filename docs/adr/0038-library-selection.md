# 0038. OIDC は zitadel/oidc、JOSE は jwx、WebAuthn は go-webauthn を使う

- 状態: 承認
- 日付: 2026-10-25
- 関連: [design.md](../design.md) 9.3, 13.2, 2.5

## 背景

暗号とプロトコルは自前で書かない方針（0030）のため、土台にするライブラリを選ぶ必要がある。特に、ML-DSA でのトークン署名（0005）、不透明なアクセストークンとイントロスペクション（0021）、Back-Channel Logout（5.2）、別ドメインでの passkey（Related Origin Requests）に対応できるかを確認した。

## 調査結果（2026年10月25日時点。各リポジトリのソースを確認）

| ライブラリ | 最終更新 | 確認できたこと |
|---|---|---|
| zitadel/oidc | 2026-10 | OP として、認可コード + PKCE、クライアントクレデンシャル、リフレッシュ、Discovery、イントロスペクション、失効、end_session に対応。アクセストークンはクライアントごとに Bearer（不透明）/ JWT を選べる。署名は go-jose 経由。Back-Channel Logout は型と Discovery の項目のみで、送信は利用側の実装。v3 が安定版、v4 はプレリリース |
| ory/fosite | 2025-07 | 不透明トークンとイントロスペクションに対応。以降の更新が止まっている |
| go-jose | 2026-10 | ML-DSA は未対応。`OpaqueSigner` で任意のアルゴリズム名の署名処理を差し込める |
| lestrrat-go/jwx | 2026-10 | v4 で ML-DSA-44/65/87 と `AKP` 鍵に対応（Go 1.27 以上） |
| go-webauthn | 2026-10 | 複数 origin の検証、RS256、ML-DSA（`AKP`）の COSE 鍵に対応 |

Related Origin Requests のブラウザ対応（passkeys.dev の対応表）：Chrome / Edge 128 以降、Safari 18 以降、Firefox 152 以降。関連付けられるドメインは実質5種類まで。

## 決定

- OIDC の土台に zitadel/oidc の v3 を使い、v4 の正式版を追う
- ML-DSA の ID トークン署名は、go-jose の `OpaqueSigner` に Go 標準の `crypto/mldsa` を差し込んで行う。JWKS の `AKP` 鍵の出力は jwx を使って自前で組み立てる
- JWT / JWK の扱いには jwx（v4）を使う
- Back-Channel Logout のログアウトトークンの送信は自前で実装する
- WebAuthn は go-webauthn を使う
- ory/fosite は保守が止まっているため採らない

## 結果

- ML-DSA への対応で Go 本体や JOSE ライブラリに手を入れる必要はない（当初の懸念は解消）
- go-jose と jwx の2つの JOSE ライブラリを併用することになる。どちらで何を扱うかを境界として決めておく
- zitadel/oidc の v4 で API が変わる可能性がある

## 検討した代替案

- ory/fosite（保守が止まっている）
- jwx だけで OP を自作する（自前のプロトコル実装が増え、0030 に反する）
