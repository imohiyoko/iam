# 0065. OIDC の連携先の登録と ID トークンの署名鍵

- 状態: 承認
- 日付: 2026-10-27
- 関連: [design.md](../design.md) 3.1、5.5、9.3、[0026](0026-first-party-clients.md)、[0040](0040-spike-mldsa-opaque-signer.md)、[0041](0041-spike-jwks-akp.md)、[0045](0045-internal-and-external-ids.md)

## 背景

M5 で OIDC Provider を作る。その土台として、連携先（クライアント）の登録と、ID トークンの署名鍵の持ち方を決める。

## 決定

- 連携先（`authn_clients`）
  - ホスト先が管理 API（`/v1/admin/clients`、権限 `clients:manage`。realm:owner）で登録するファーストパーティだけ（0026）
  - `client_id` は外部 ID（`cli_…`。0045）。内部 ID は出さない
  - 認証方式は `client_secret`（basic / post）・`private_key_jwt`（公開鍵だけの JWKS を登録）・`none`（公開クライアント。PKCE 必須）
  - `client_secret` は 256 bit の乱数で、作成とローテーションのときに1度だけ返す。保存するのは SHA-256 だけで、照合は定数時間
  - `redirect_uris` は https か loopback の http（フラグメント・userinfo なし）。完全一致で照合する
  - `id_token_signed_response_alg` は `ES256`（既定）か `ML-DSA-65`。ML-DSA-65 を検証できる RP がまだ少ないため既定は ES256
- 署名鍵（`authn_signing_keys`）
  - realm ごとに ES256 と ML-DSA-65 の鍵を1つずつ使う。秘密鍵はマスター鍵から用途ごとに導いた鍵で暗号化して Storage に置く
    （KeyStore はマスター鍵とインデックス鍵だけを持つ）
  - kid は外部 ID（`sgk_…`）。JWS のヘッダーに必ず kid を付ける（0040。zitadel/oidc の署名の経路は使わず IAM が署名する）
  - ローテーション（`/v1/admin/signing-keys:rotate`、権限 `signing_keys:rotate`。realm:owner）で新しい鍵に切り替え、古い鍵は
    `oidc.retired_key_ttl`（既定7日、`id_token_ttl` より長い）の間 JWKS に残す。期限の後は消す
  - JWKS は AKP（ML-DSA-65）と EC（ES256）を並べて jwx で組み立てる（0041）。起動時に鍵が無ければ作る

## 理由

- 秘密を保存しない・1度だけ返すのは、セッションのトークンと同じ扱い（5.2）
- 署名鍵を Storage に置けば、複数のインスタンスが同じ鍵で署名でき、ローテーションも DB の更新だけで済む
- 退役した鍵を残す期間を ID トークンの寿命より長くすれば、ローテーションの直後に発行済みのトークンが検証できなくなることはない

## 影響

- 連携先と署名鍵の管理の操作は監査ログに残す（`client.*`、`signing_key.rotated`）
- 設定に `oidc`（`code_ttl`・`id_token_ttl`・`access_token_ttl`・`refresh_token_ttl`・`retired_key_ttl`）を足す
