package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	oidcrp "github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// フィーチャー jwt_access_tokens（RFC 9068。ADR 0123）を HTTP で確かめる。

func TestJWTAccessTokensOff(t *testing.T) {
	l := senderEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "API", "redirect_uris": []string{"https://api.example.com/cb"},
		"token_endpoint_auth_method": "client_secret", "jwt_access_tokens": true}); code != 400 || out["error"] != "invalid_client_metadata" {
		t.Fatalf("jwt_access_tokens while off: %d %v", code, out)
	}
}

// jwtParts は JWT のヘッダーとクレームを返す（署名は確かめない）。
func jwtParts(t *testing.T, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	var hdr, claims map[string]any
	for i, v := range []*map[string]any{&hdr, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(b, v) != nil {
			t.Fatalf("decode part %d: %v", i, err)
		}
	}
	return hdr, claims
}

// TestJWTAccessTokensE2E は、標準の RP（zitadel/oidc）が RS256 の ID トークンと JWT のアクセストークンを受け取り、リソースサーバーが
// JWKS だけで署名を確かめられること、UserInfo・イントロスペクション・失効が JWT でも今までどおり効くことを、本物の HTTPS で確かめる。
func TestJWTAccessTokensE2E(t *testing.T) {
	e := newE2E(t, feature.JWTAccessTokens, feature.RS256)
	ctx := context.Background()
	_, owner := e.l.operator(t, "root@example.com", role.RealmOwner)
	web := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "id_token_signed_response_alg": "RS256",
		"jwt_access_tokens": true})
	api := e.l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "redirect_uris": []string{"https://api.example.com/cb"}})
	relying, err := oidcrp.NewRelyingPartyOIDC(ctx, e.issuer, web.clientID, web.secret, web.redirect, []string{"openid", "email"}, oidcrp.WithHTTPClient(e.http),
		oidcrp.WithVerifierOpts(oidcrp.WithSupportedSigningAlgorithms("RS256"),
			oidcrp.WithNonce(func(ctx context.Context) string { n, _ := ctx.Value(nonceKey{}).(string); return n })))
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier, challenge := pkce()
	authURL := oidcrp.AuthURL("jwt-state", relying, oidcrp.WithCodeChallenge(challenge), func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", "jwt-nonce")}
	})
	code := e.browse(t, authURL, "alice@example.com", web.redirect)
	tokens, err := oidcrp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(ctx, nonceKey{}, "jwt-nonce"), code, relying, oidcrp.WithCodeVerifier(verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	alice := e.l.userID(t, "alice@example.com")
	hdr, claims := jwtParts(t, tokens.AccessToken)
	if hdr["typ"] != "at+jwt" || hdr["alg"] != "RS256" || hdr["kid"] == nil {
		t.Fatalf("header = %v", hdr)
	}
	aud, _ := claims["aud"].([]any)
	if claims["iss"] != e.issuer || claims["sub"] != alice || claims["client_id"] != web.clientID || len(aud) != 1 || aud[0] != web.clientID ||
		claims["jti"] == nil || claims["scope"] != "openid email" || claims["exp"] == nil || claims["iat"] == nil || claims["sid"] == nil {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := claims["email"]; ok {
		t.Fatalf("email in access token: %v", claims)
	}
	// リソースサーバーは JWKS だけで確かめられる。
	resp, err := e.http.Get(e.issuer + oidcKeys)
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwk.ParseReader(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if _, err := jwt.Parse([]byte(tokens.AccessToken), jwt.WithKeySet(set), jwt.WithIssuer(e.issuer), jwt.WithAudience(web.clientID)); err != nil {
		t.Fatalf("verify with jwks: %v", err)
	}
	// UserInfo とイントロスペクションは JWT のままでも使える。
	info, err := oidcrp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, oidc.BearerToken, alice, relying)
	if err != nil || info.Email != "alice@example.com" {
		t.Fatalf("userinfo: %+v %v", info, err)
	}
	server, err := rs.NewResourceServerClientCredentials(ctx, e.issuer, api.clientID, api.secret, rs.WithClient(e.http))
	if err != nil {
		t.Fatalf("resource server: %v", err)
	}
	if in, err := rs.Introspect[*oidc.IntrospectionResponse](ctx, server, tokens.AccessToken); err != nil || !in.Active || in.Subject != alice {
		t.Fatalf("introspect: %+v %v", in, err)
	}
	// 書き換えた JWT（署名を付け替えた別のクレーム）はどこでも通らない。
	parts := strings.Split(tokens.AccessToken, ".")
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"`+claims["jti"].(string)+`","sub":"x"}`)) + "." + parts[2]
	if in, err := rs.Introspect[*oidc.IntrospectionResponse](ctx, server, forged); err != nil || in.Active {
		t.Fatalf("forged introspect: %+v %v", in, err)
	}
	if _, err := oidcrp.Userinfo[*oidc.UserInfo](ctx, forged, oidc.BearerToken, alice, relying); err == nil {
		t.Fatal("forged userinfo accepted")
	}
	// リフレッシュでも JWT。失効させるとイントロスペクションと UserInfo はすぐ止まる。
	refreshed, err := oidcrp.RefreshTokens[*oidc.IDTokenClaims](ctx, relying, tokens.RefreshToken, "", "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if h, _ := jwtParts(t, refreshed.AccessToken); h["typ"] != "at+jwt" {
		t.Fatalf("refreshed header = %v", h)
	}
	if err := oidcrp.RevokeToken(ctx, relying, refreshed.RefreshToken, "refresh_token"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if in, err := rs.Introspect[*oidc.IntrospectionResponse](ctx, server, refreshed.AccessToken); err != nil || in.Active {
		t.Fatalf("introspect after revoke: %+v %v", in, err)
	}
	if _, err := oidcrp.Userinfo[*oidc.UserInfo](ctx, refreshed.AccessToken, oidc.BearerToken, alice, relying); err == nil {
		t.Fatal("userinfo after revoke")
	}
}

func TestDisableJWTAccessTokensWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret", "jwt_access_tokens": true})
	disableWithData(t, l, feature.JWTAccessTokens, 1)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Clients().List(ctx, l.a.realm.ID)
		if err == nil && (len(cs) != 1 || cs[0].JWTAccessTokens) {
			t.Fatalf("clients after disable: %+v", cs)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
