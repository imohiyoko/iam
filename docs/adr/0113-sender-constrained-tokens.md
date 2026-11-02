# 0113. 送信者制約トークンは DPoP と OAuth の mTLS の 2 つのフィーチャーにし、iam の資源でも結び付けを確かめる

- 状態: 承認
- 日付: 2026-11-02
- 関連: [design.md](../design.md) 5.1、5.5、5.9、11.12、[0005](0005-crypto-no-rsa-pqc.md)、[0066](0066-oidc-authorization-code-flow.md)、
  [0073](0073-build-and-feature-toggle.md)、[0074](0074-service-accounts.md)、[0083](0083-multi-realm.md)、[0089](0089-enterprise-full-scope.md)、
  [0095](0095-device-authorization-grant.md)、[0099](0099-token-exchange.md)、[0103](0103-x509-client-certificates.md)

## 背景

iam のアクセストークン・リフレッシュトークンは Bearer で、漏れれば誰でも使える。金融・公共の API（FAPI 2.0）や、端末に鍵を持つ
ネイティブアプリ・SPA では、トークンを連携先の鍵に結び付ける送信者制約トークンを求められる（scope.md の「DPoP（RFC 9449）、
mTLS（RFC 8705）」。S）。決めることは次のとおり。

- DPoP の証明（proof）の確かめ方と、再送の防止・nonce の置き場所（複数のインスタンス）
- mTLS の連携先の認証（tls_client_auth・self_signed_tls_client_auth）と、証明書の受け取り。ADR 0103 で X.509 の方式のために作った
  mTLS の専用の待ち受けとプロキシのヘッダーを使えるか
- トークンのどこに結び付けを持つか（iam のアクセストークンは不透明）。リフレッシュトークン、Token Exchange、Device Authorization Grant
- iam 自身の資源（UserInfo、管理 API）での確かめ。フィーチャーを止めたときの結び付けたトークンの扱い

## 決定

### フィーチャー

- `dpop`（DPoP。依存なし、既定オフ）と `mtls_client_auth`（OAuth の mTLS の連携先の認証と、証明書に結び付けたトークン。依存なし、既定オフ）。
  どちらも認証方式（ADR 0090 の `authn/method`）ではなく、OAuth のトークンの性質なので、DPoP は `authn/dpop`、mTLS は `authn/provider` に置く
- オフなら Discovery に出さず、連携先の設定（`dpop_bound_access_tokens`・`tls_client_certificate_bound_access_tokens`・mTLS の認証方式）を
  新しく入れられない（`invalid_client_metadata`。今の値のままの変更と、外すのは受け付ける）

### 結び付けの持ち方

- `oidc_tokens` に `jkt`（DPoP の鍵の JWK SHA-256 Thumbprint。RFC 7638）と `x5t`（クライアント証明書の DER の SHA-256。`x5t#S256`）を足す
  （SQLite 00064、PostgreSQL 00047）。アクセストークンは不透明のままで、結び付けはイントロスペクションの `cnf`（`jkt`・`x5t#S256`）で返す。
  JWT のアクセストークン（M11）を入れるときは `cnf` をクレームにする
- アクセストークンは要求で示した鍵・証明書に結び付ける。リフレッシュトークンは公開クライアント（`none`）だけ結び付け
  （RFC 9449 5、RFC 8705 4）、次のリフレッシュで同じ鍵・証明書を求める。合わなければ使用済みにせずに `invalid_grant`
  （鍵を持たない盗んだ人にトークンを焼かせない）。機密の連携先のリフレッシュトークンは連携先の認証が守るので結び付けない
- 認可コードの交換・リフレッシュ・Device Authorization Grant・Token Exchange のどれでも同じ。Token Exchange は結び付けた
  `subject_token`・`actor_token` に同じ鍵・証明書を求める（盗んだトークンを交換で Bearer にさせない）
- 認可要求の `dpop_jkt`（RFC 9449 10）を受け、認可コードの交換で同じ鍵の証明を求める
- 監査ログ `oidc.authorized` に `dpop_jkt`・`x5t#S256` を残す

### DPoP（RFC 9449）

- 証明は `go-jose/v4` で JWS のコンパクト形式として読み、次をすべて確かめる（どれかが欠ければ拒む）：DPoP ヘッダーが 1 つ、8 KiB 以下、
  `typ` が `dpop+jwt`、`alg` が `ES256`・`ES384`・`EdDSA`・`PS256`・`RS256`（RSA は 2048 bit 以上。iam が署名するのではなく
  連携先の鍵を確かめるだけなので 0005 の対象外。private_key_jwt と同じ）、ヘッダーの `jwk` が公開鍵だけ、署名、`jti`（256 文字以下）・
  `htm`・`htu`・`iat`。`htu` は scheme とホストの大文字小文字・既定のポートを揃え、クエリとフラグメントを除いて iam の URL と比べる。
  `iat` は 5 分（`oidc.dpop.proof_max_age`）より古いか 30 秒より先なら拒む
- 再送の防止：鍵と `jti` の組を EphemeralStore の `Incr` で、`iat` の許す幅の間だけ覚える（複数のインスタンスでは共有の EphemeralStore）
- nonce（`oidc.dpop.require_nonce`）：iam が乱数の nonce を作って EphemeralStore に寿命（`nonce_ttl`、既定 5 分）付きで置き、寿命の半分で
  新しくする。証明を付けた要求の応答に `DPoP-Nonce` を付け、無い・知らない nonce は `use_dpop_nonce`。どのインスタンスが出した nonce でも通る
- token エンドポイント：証明があれば確かめて結び付け、`token_type` を `DPoP` にする。誤りは `400 invalid_dpop_proof`。
  `dpop_bound_access_tokens` の連携先（RFC 9449 5.2）は証明が要る。フィーチャーがオフなら証明を見ずに Bearer を出す（RFC 9449 で許される）が、
  `dpop_bound_access_tokens` の連携先には出さない
- Discovery の `dpop_signing_alg_values_supported`。CORS で `DPoP` の要求ヘッダーと `DPoP-Nonce` の応答ヘッダーを許す
- 証明の解析は `FuzzParse` でファジングする

### OAuth の mTLS（RFC 8705）

- 証明書は ADR 0103 のコアの経路でだけ受ける（mTLS の専用の待ち受けか、`proxies` に書いたプロキシのヘッダー）。秘密鍵の所持は TLS の
  CertificateVerify で確かめてある。フィーチャーが動いていれば、専用の待ち受けは token・introspect・revoke・userinfo・device_authorization も通す
  （オフなら今までどおり方式のパスだけ）
- `tls_client_auth`（2.1）：`oidc.mtls.trust_anchors`（と `intermediates`）までの連鎖、`clientAuth` の用途、期限（Clock）を確かめ、
  登録した 1 つの項目（`tls_client_auth_subject_dn`・`_san_dns`・`_san_uri`・`_san_ip`・`_san_email`）と照合する。DN は RFC 4514 の文字列の完全一致
  （Go の `pkix.Name.String()` の形）。CA が設定に無ければ認証できない
- `self_signed_tls_client_auth`（2.2）：登録の JWKS の鍵と証明書の公開鍵が同じなら通す（自己署名の証明書の期限は見ない）
- `tls_client_certificate_bound_access_tokens` の連携先は、token エンドポイントでクライアント証明書が要り（無ければ `invalid_request`）、
  トークンを証明書に結び付ける
- Discovery に `tls_client_auth`・`self_signed_tls_client_auth`（token・introspection・revocation）と `tls_client_certificate_bound_access_tokens`。
  `oidc.mtls.endpoint_url`（専用の待ち受けの外から見たオリジン）があれば `mtls_endpoint_aliases`。ホスト名で決める realm（0083）は専用の
  待ち受けで realm を引けないので別名を出さない
- 失効（OCSP・CRL）は確かめない。連携先の証明書は運営者の CA が短い期限で出すことを勧める（X.509 の方式の失効の確かめを使い回すのは後で）

### iam の資源での確かめ

- UserInfo：結び付けたトークンは、DPoP なら `Authorization: DPoP` と、同じ鍵・`ath`・`htm`・`htu` の証明（再送は拒む）、証明書なら
  同じクライアント証明書の要求でだけ通す。結び付けの無いトークンを `DPoP` の方式で示すのも拒む（RFC 9449 7.1）。401 の `WWW-Authenticate` は
  DPoP が動いていれば `DPoP error=…, algs=…`
- 管理 API：Bearer で受けるもののうち結び付けられるのは、サービスアカウントのアクセストークン（ADR 0074）。`POST /v1/admin/token` の
  `DPoP` ヘッダーの証明で鍵に結び付け（`token_type: DPoP`）、管理 API はそのトークンに `Authorization: DPoP` と同じ鍵の証明を求める。
  `htu` は `oidc.dpop.admin_url`（管理 API の外から見たオリジン）とパス（realm の接頭辞を含む）。設定が無ければ管理 API では DPoP を受けない
  （証明を見ずに Bearer を出す。結び付けたトークンは通らない）。運営者のセッション・PAT・API キーを `DPoP` の方式で示しても通らない。
  管理 API の待ち受けには証明書の経路が無いので、証明書に結び付けたサービスアカウントのトークンは作らない
- 判定の API の `access_token`（文脈。ADR 0084）は資源サーバーが確かめた後に渡すものとして、結び付けを見ない

### fail-closed と無効化

- フィーチャーが止まっていれば、結び付けたトークンは確かめられないので、資源でも Token Exchange でもリフレッシュでも通さない。
  mTLS の連携先は認証できない
- 無効化（11.12）：`dpop` は連携先の `dpop_bound_access_tokens` を外し、DPoP に結び付けたトークン（OIDC とサービスアカウント）を消して完了。
  `mtls_client_auth` は連携先の `tls_client_certificate_bound_access_tokens` と照合の項目を外し、証明書に結び付けたトークンを消して完了。
  `tls_client_auth` の連携先は照合の項目が無くなるので、認証方式を変えるまで認証できない。`self_signed_tls_client_auth` の JWKS は
  private_key_jwt と同じ連携先の鍵なので残す（フィーチャーがオフなら認証できない）

## 結果

- トークンが漏れても、連携先の鍵・証明書が無ければ iam の資源でも資源サーバー（イントロスペクションの `cnf`）でも使えない
- 公開クライアント（SPA・ネイティブ）のリフレッシュトークンを DPoP の鍵に結び付けられる
- X.509 の方式の証明書の経路を、連携先の認証にも使える。運営者が書く設定は CA と、専用の待ち受けの外の URL だけ
- nonce と再送の防止は EphemeralStore を使うので、複数のインスタンスでは共有の EphemeralStore が要る（今までと同じ）
- 資源サーバーは `cnf` を見て証明を自分で確かめる必要がある（iam はイントロスペクションで結び付けを返すだけ）

## 検討した代替案

- **DPoP のライブラリ（AxisCommunications/go-dpop など）を使う**：保守が細く、nonce と再送の防止をストアに合わせられない。
  JWS の検証は保守の厚い go-jose に任せ、RFC 9449 4.3 の確かめは短く自前で書いてファジングする
- **結び付けを認可（Grant）に持つ**：機密の連携先では要求ごとに鍵を変えられ（RFC 9449）、Token Exchange は別の鍵に結び付く。トークンごとに持つ
- **nonce を HMAC で状態なしに作る**：鍵の配布と切り替えが要る。EphemeralStore は既に共有の前提なので置く
- **フィーチャーがオフでも結び付けたトークンを Bearer として通す**：止めた途端に盗んだトークンが使えるようになる。通さない
- **公開 API の待ち受けで証明書を求める**：ブラウザが全部の画面で証明書を選ばせる（0103 と同じ）。専用の待ち受けとプロキシのヘッダーに限る
- **mTLS の連携先の CA を realm ごとに持つ**：連携先は運営者が登録し、照合の項目で区別できる。まずはインスタンスで 1 つにする
