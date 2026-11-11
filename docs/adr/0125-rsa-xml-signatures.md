# 0125. SAML の IdP と WS-Federation の RSA-SHA256 の署名は、フィーチャー rs256 で SP・RP ごとに選べるようにする

- 状態: 承認
- 日付: 2026-11-11
- 関連: [design.md](../design.md) 5.8、5.9、9.3、11.0、[0110](0110-ws-federation.md)、[0115](0115-saml-idp.md)、
  [0122](0122-rs256-id-tokens.md)

## 背景

SAML の IdP（ADR 0115）と WS-Federation（ADR 0110）は、realm の ES256 の鍵で ECDSA-SHA256 の XML 署名だけをしてきた。
古い SaaS の SAML の SP や、.NET Framework の WIF（Windows Identity Foundation）で作った RP は RSA-SHA256 しか確かめられず、
つながらなかった。ADR 0122 で RSA 3072 の鍵（フィーチャー `rs256`）を足したので、同じ鍵で XML 署名もできる。

## 決定

- SAML の SP と WS-Federation の RP の登録に `signing_alg`（`ES256`（既定）か `RS256`）を足す。`RS256` はフィーチャー `rs256` が
  動いているときだけ選べる（オフなら `400`）
- `RS256` の SP・RP には、realm の RS256 の鍵で RSA-SHA256（`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`）の XML 署名をする。
  SAML の Response・Assertion・LogoutResponse（HTTP-Redirect の `SigAlg` も RSA-SHA256、値は PKCS #1 v1.5）、WS-Federation の
  Assertion（SAML 1.1・2.0）が対象。正規化・ダイジェストは今までどおり（Exclusive C14N・SHA-256）
- 鍵ごとの自己署名の証明書は今までと同じ表に置く。メタデータの KeyDescriptor には、公開している ES256 と RS256 の鍵の証明書を
  並べる（フィーチャーがオンなら、使っている RS256 の鍵の証明書も用意する）。メタデータ自体の署名は ES256 のまま
- 無効化（`rs256` の片付け）では、OIDC の連携先に加えて `RS256` の SP・RP を `ES256` に戻してから RSA の鍵を退役させる。
  片付けの前に読んだ SP・RP への署名は、鍵が退役していれば ES256 にする（ADR 0122 と同じ）。退役した鍵の証明書は
  `oidc.retired_key_ttl` の間メタデータに残る

## 結果

- RSA-SHA256 しか確かめない SP・RP（古い SaaS、WIF）につながる
- メタデータに証明書が 2 種類並ぶ。メタデータから証明書を取り込む SP・RP は、どちらでも署名を確かめられる
- 証明書や指紋を 1 つだけ手で登録する SP・RP は、`signing_alg` に合う方の証明書を登録する必要がある

## 検討した代替案

- 別のフィーチャーにする：RSA の鍵の管理（作成・ローテーション・退役・片付け）は `rs256` と同じで、分ける利点が無い
- メタデータの署名も SP ごとに変える：メタデータは realm に 1 つで、SP を区別できない
