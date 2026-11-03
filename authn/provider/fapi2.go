package provider

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"net/url"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// FAPI 2.0 Security Profile（ADR 0117）。連携先か realm の単位で有効にし、PAR・送信者制約・機密の連携先の認証・
// 署名のアルゴリズム・短い認可コードを強いる。連携先の条件は CheckFAPI2 が 1 か所で確かめる（登録と実行の両方）。

// FAPI2Feature は FAPI 2.0 Security Profile のフィーチャー（既定オフ）。前提（par と、dpop か mtls_client_auth）は依存に書かず、
// 連携先と realm の設定に入れるときに確かめる（依存は AND しか書けず、前提のフィーチャーを先に止めても実行で fail-closed になる）。
var FAPI2Feature = feature.Feature{Name: feature.FAPI2, DataVersion: 1}

// FAPI2Algs は FAPI 2.0 の JWS に使えるアルゴリズム（FAPI 2.0 Security Profile 5.4.1）。client assertion と DPoP の証明に求める。
var FAPI2Algs = []string{"PS256", "ES256", "EdDSA"}

// FAPI2CodeTTL は FAPI 2.0 の連携先の認可コードの寿命の上限（5.3.2.1）。
const FAPI2CodeTTL = time.Minute

// fapi2AuthMethods は FAPI 2.0 の連携先に許す認証方式（機密の連携先だけ）。
var fapi2AuthMethods = []string{port.ClientAuthPrivateKeyJWT, port.ClientAuthTLS, port.ClientAuthSelfSignedTLS}

// CheckFAPI2 は連携先の登録が FAPI 2.0 Security Profile の条件を満たすかを確かめる。満たさなければ理由を付けた
// invalid_client_metadata（実行のときは呼び出し側が invalid_client にする）。フィーチャーが動いているかは見ない。
func CheckFAPI2(cl port.Client) error {
	if !slices.Contains(fapi2AuthMethods, cl.AuthMethod) {
		return invalidClient("fapi2_security_profile requires token_endpoint_auth_method private_key_jwt, tls_client_auth or self_signed_tls_client_auth")
	}
	if !cl.DPoPBoundAccessTokens && !cl.TLSBoundAccessTokens {
		return invalidClient("fapi2_security_profile requires dpop_bound_access_tokens or tls_client_certificate_bound_access_tokens")
	}
	if cl.IDTokenAlg != port.AlgES256 {
		return invalidClient("fapi2_security_profile requires id_token_signed_response_alg ES256")
	}
	if cl.DeviceGrant {
		return invalidClient("fapi2_security_profile does not allow device_authorization_grant")
	}
	for _, u := range cl.RedirectURIs {
		if p, err := url.Parse(u); err != nil || p.Scheme != "https" {
			return invalidClient("fapi2_security_profile requires https redirect_uris")
		}
	}
	if cl.AuthMethod == port.ClientAuthPrivateKeyJWT && !fapi2Keys(cl.JWKS) {
		return invalidClient("fapi2_security_profile requires jwks keys for PS256 (RSA 2048 bit or more), ES256 (P-256) or EdDSA (Ed25519)")
	}
	return nil
}

// fapi2Keys は JWKS の鍵がすべて FAPI 2.0 のアルゴリズムで使える公開鍵かを返す（鍵の alg を書くなら、その種類のアルゴリズム）。
func fapi2Keys(raw []byte) bool {
	set, err := jwk.Parse(raw)
	if err != nil || set.Len() == 0 {
		return false
	}
	for i := range set.Len() {
		k, _ := set.Key(i)
		pub, err := jwk.Export[any](k)
		if err != nil {
			return false
		}
		var want string
		switch p := pub.(type) {
		case *rsa.PublicKey:
			if p.N.BitLen() < 2048 {
				return false
			}
			want = "PS256"
		case *ecdsa.PublicKey:
			if p.Curve != elliptic.P256() {
				return false
			}
			want = "ES256"
		case ed25519.PublicKey:
			want = "EdDSA"
		default:
			return false
		}
		if alg, ok := k.Algorithm(); ok && alg.String() != want {
			return false
		}
	}
	return true
}

// FAPI2Assertion は client_assertion（検証済みのもの）の alg が FAPI 2.0 のアルゴリズムかを返す。
func FAPI2Assertion(assertion string) bool {
	msg, err := jws.Parse([]byte(assertion))
	if err != nil || len(msg.Signatures()) != 1 {
		return false
	}
	alg, ok := msg.Signatures()[0].ProtectedHeaders().Algorithm()
	return ok && slices.Contains(FAPI2Algs, alg.String())
}
