# 0122. RS256 の ID トークンは既定オフのフィーチャーにし、realm ごとに RSA 3072 の鍵を足して連携先ごとに選ばせる

- 状態: 承認
- 日付: 2026-11-11
- 関連: [design.md](../design.md) 5.5、9.1、9.3、11.0、[0005](0005-crypto-no-rsa-pqc.md)、[0065](0065-oidc-clients-and-signing-keys.md)、
  [0089](0089-enterprise-full-scope.md)、[0117](0117-fapi2-security-profile.md)

## 背景

OIDC Discovery は `id_token_signing_alg_values_supported` に RS256 を含めることを求め、多くの RP（SaaS、古いライブラリ、
zitadel/oidc の rp の既定など）は RS256 の ID トークンしか確かめない。ADR 0005 で自前の鍵の RSA を使わないと決めたため、
こうした RP とはつながらず、OIDC の適合試験（Basic OP）も RS256 を前提にしている。ADR 0089 は、RS256 を連携先ごとに選べる
フィーチャーにし、ホスト先の鍵で RSA を使うときは警告の対象にすると決めた。この ADR はその中身を決める。

## 決定

- フィーチャー `rs256`（既定オフ）。オフなら今までと同じ（ES256 と ML-DSA-65 だけ）
- オンなら realm ごとに RS256 の鍵を 1 つ足す（起動時の `Ensure`。ES256・ML-DSA-65 と同じく Storage に、マスター鍵から導いた鍵で
  暗号化して置く）。大きさは 3072 bit（P-256 と同じ 128 bit の強さ。NIST SP 800-57 で 2030 年より後も使える）
- JWKS に `kty: RSA`・`alg: RS256`・`use: sig` で載せ、Discovery の `id_token_signing_alg_values_supported` に `RS256` を足す
- 連携先の `id_token_signed_response_alg` に `RS256` を選べる（オフなら `400 invalid_client_metadata`）。既定は ES256 のまま。
  ID トークンと Logout Token を同じアルゴリズムで署名する
- 署名鍵のローテーション（`/v1/admin/signing-keys:rotate`）は、オンのときだけ `RS256` を受ける
- FAPI 2.0 の連携先は今までどおり ES256 だけ（RS256 は FAPI 2.0 で使えない。ADR 0117）
- オンのとき、起動で警告をログに出す（ADR 0089）
- 無効化（disabling）：RS256 の連携先を ES256 に戻し、RS256 の鍵を退役させて完了。退役した鍵は `oidc.retired_key_ttl` の間
  JWKS に残る。片付けまでの間は、RS256 を選んだ連携先に RS256 で署名し続ける（黙って ES256 にすると RP の検証が通らなくなるため）。
  その間は Discovery にも RS256 を載せる。片付けで鍵が退役した後は RS256 の鍵を作り直さず、片付けの前に読んだ連携先にも ES256 で署名する

## 結果

- RS256 しか確かめない RP・SaaS とつながる。OIDC の適合試験の既知の差異が 1 つ減る
- 自前の RSA の鍵を持つことになる。耐量子でなく、鍵と署名が大きい。既定オフ・連携先ごとの選択・警告で範囲を限る
- SAML の IdP と WS-Federation の XML 署名（RSA-SHA256）はこのフィーチャーに含めない（別に決める）

## 検討した代替案

- RSA 2048：互換性はわずかに広いが、2030 年以降の強さが足りない。3072 を扱えない JOSE のライブラリは主要なものに無い
- PS256 も足す：RS256 しか扱えない RP のためのフィーチャーなので要らない。必要になれば同じ鍵で足せる
- realm の設定で RS256 を既定にする：既定を安全側に保つ方針（ADR 0089）に反する。連携先ごとの選択で足りる
