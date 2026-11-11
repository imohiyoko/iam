package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	oidcrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// フィーチャー rs256（ADR 0122）を HTTP で確かめる。

func discoveryAlgs(t *testing.T, l *loginEnv) []string {
	t.Helper()
	d := metadataAt(t, l, "/.well-known/openid-configuration")
	var out []string
	for _, v := range d["id_token_signing_alg_values_supported"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestRS256Off(t *testing.T) {
	l := senderEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if algs := discoveryAlgs(t, l); slices.Contains(algs, "RS256") {
		t.Fatalf("discovery while off: %v", algs)
	}
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "Legacy", "redirect_uris": []string{"https://legacy.example.com/cb"},
		"token_endpoint_auth_method": "client_secret", "id_token_signed_response_alg": "RS256"}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("RS256 client while off: %d %v", code, out)
	}
	if code, _ := l.admin(t, "/v1/admin/signing-keys:rotate", owner, map[string]any{"alg": "RS256"}); code != 400 {
		t.Fatalf("rotate RS256 while off: %d", code)
	}
	w := l.oidcDo(t, "GET", oidcKeys, nil, "")
	if strings.Contains(w.Body.String(), `"RSA"`) {
		t.Fatalf("jwks while off: %s", w.Body)
	}
}

// TestRS256E2EStandardRP は、RS256 しか確かめない RP（zitadel/oidc の rp の既定と同じ）が、Discovery から始めて
// RS256 の ID トークンを受け取り、JWKS の RSA の鍵で検証できることを、本物の HTTPS のサーバーで確かめる。
func TestRS256E2EStandardRP(t *testing.T) {
	e := newE2E(t, feature.RS256)
	ctx := context.Background()
	_, owner := e.l.operator(t, "root@example.com", role.RealmOwner)
	if algs := discoveryAlgs(t, e.l); !slices.Contains(algs, "RS256") || !slices.Contains(algs, "ES256") {
		t.Fatalf("discovery: %v", algs)
	}
	w := e.l.oidcDo(t, "GET", oidcKeys, nil, "")
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	rsaKeys := 0
	for _, k := range jwks.Keys {
		if k["kty"] != "RSA" {
			continue
		}
		rsaKeys++
		if k["alg"] != "RS256" || k["use"] != "sig" || k["d"] != nil || k["p"] != nil {
			t.Fatalf("rsa jwk: %v", k)
		}
		n, _ := base64.RawURLEncoding.DecodeString(k["n"].(string))
		if len(n)*8 != provider.RSAKeyBits {
			t.Fatalf("modulus = %d bits", len(n)*8)
		}
	}
	if rsaKeys != 1 {
		t.Fatalf("jwks: %s", w.Body)
	}

	web := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "id_token_signed_response_alg": "RS256"})
	relying, err := oidcrp.NewRelyingPartyOIDC(ctx, e.issuer, web.clientID, web.secret, web.redirect, []string{"openid", "email"}, oidcrp.WithHTTPClient(e.http),
		oidcrp.WithVerifierOpts(oidcrp.WithSupportedSigningAlgorithms("RS256"),
			oidcrp.WithNonce(func(ctx context.Context) string { n, _ := ctx.Value(nonceKey{}).(string); return n })))
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier, challenge := pkce()
	authURL := oidcrp.AuthURL("rs-state", relying, oidcrp.WithCodeChallenge(challenge), func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", "rs-nonce")}
	})
	code := e.browse(t, authURL, "alice@example.com", web.redirect)
	tokens, err := oidcrp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(ctx, nonceKey{}, "rs-nonce"), code, relying, oidcrp.WithCodeVerifier(verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	if tokens.IDTokenClaims.Subject != e.l.userID(t, "alice@example.com") {
		t.Fatalf("claims: %+v", tokens.IDTokenClaims)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(tokens.IDToken, ".")[0])
	if !strings.Contains(string(hdr), `"alg":"RS256"`) {
		t.Fatalf("header = %s", hdr)
	}
	// リフレッシュの ID トークンも RS256。
	if _, err := oidcrp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, tokens.RefreshToken, "", ""); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// ES256 の連携先は今までどおり ES256。
	other := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://other.example.com/cb"}})
	if other.clientID == "" {
		t.Fatal("register")
	}
	if code, out := e.l.admin(t, "/v1/admin/signing-keys:rotate", owner, map[string]any{"alg": "RS256"}); code != 200 || out["alg"] != "RS256" {
		t.Fatalf("rotate: %d %v", code, out)
	}
}

func TestDisableRS256WithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "id_token_signed_response_alg": "RS256"})
	// 片付けるのは RS256 の連携先 1 つと、使っている RS256 の鍵 1 つ。
	disableWithData(t, l, feature.RS256, 2)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Clients().List(ctx, l.a.realm.ID)
		if err != nil {
			return err
		}
		if len(cs) != 1 || cs[0].IDTokenAlg != port.AlgES256 {
			t.Fatalf("clients after disable: %+v", cs)
		}
		ks, err := tx.SigningKeys().List(ctx, l.a.realm.ID)
		for _, k := range ks {
			if k.Alg == port.AlgRS256 && k.RetiredAt == nil {
				t.Fatalf("rsa key still active: %+v", k.ID)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
