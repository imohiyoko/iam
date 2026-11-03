package sdjwt_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt/sdjwttest"
)

// 組み立てた SD-JWT（ADR 0119）が検証（ADR 0108）に通り、開示しなかったクレームが見えないこと。
func TestBuildVerifies(t *testing.T) {
	iss := sdjwttest.NewIssuer("https://issuer.example", "k1")
	h := sdjwttest.NewHolder()
	claims := map[string]any{"iss": iss.ISS, "vct": "urn:example:employee", "iat": now.Unix(), "exp": now.Unix() + 3600,
		"cnf": map[string]any{"jwk": h.JWK()}, "email": "pat@example.com", "employee_no": "E-1", "department": "R&D"}
	b, err := sdjwt.Build(claims, []string{"email", "department"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Payload["email"]; ok {
		t.Fatal("disclosable claim kept in the payload")
	}
	if b.Payload["employee_no"] != "E-1" || b.Payload["_sd_alg"] != "sha-256" {
		t.Fatalf("payload = %v", b.Payload)
	}
	if n := len(b.Payload["_sd"].([]any)); n < 3 || n > 6 {
		t.Fatalf("_sd has %d digests (2 claims and 1-4 decoys)", n)
	}
	if _, ok := claims["_sd"]; ok {
		t.Fatal("input changed")
	}
	jwt := sdjwttest.Sign(iss.Key, sdjwt.TypeVC, map[jose.HeaderKey]any{"kid": iss.KID}, b.Payload)
	c := sdjwttest.Credential{JWT: jwt, Disclosures: map[string]string{}}
	for _, d := range b.Disclosures {
		raw, _ := base64.RawURLEncoding.DecodeString(d)
		var a []any
		if err := json.Unmarshal(raw, &a); err != nil || len(a) != 3 {
			t.Fatalf("disclosure %s", raw)
		}
		if salt, _ := base64.RawURLEncoding.DecodeString(a[0].(string)); len(salt) != sdjwt.SaltSize {
			t.Fatal("salt size")
		}
		c.Disclosures[a[1].(string)] = d
	}
	got, err := sdjwt.Verify(h.Present(c, aud, nonce, now, "department"), opts(iss))
	if err != nil {
		t.Fatal(err)
	}
	if got.Claims["department"] != "R&D" || got.Claims["employee_no"] != "E-1" {
		t.Fatalf("claims = %v", got.Claims)
	}
	if _, ok := got.Claims["email"]; ok {
		t.Fatal("undisclosed claim visible")
	}
	if s := sdjwt.Serialize(jwt, b.Disclosures); !strings.HasPrefix(s, jwt+"~") || !strings.HasSuffix(s, "~") || strings.Count(s, "~") != 3 {
		t.Fatalf("serialize = %s", s)
	}
}

func TestBuildRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		claims map[string]any
		sd     []string
	}{
		"missing":      {map[string]any{"a": 1}, []string{"b"}},
		"reserved sd":  {map[string]any{"cnf": map[string]any{}}, []string{"cnf"}},
		"status sd":    {map[string]any{"status": map[string]any{}}, []string{"status"}},
		"_sd claim":    {map[string]any{"_sd": []any{}}, nil},
		"_sd_alg":      {map[string]any{"_sd_alg": "sha-512"}, nil},
		"dots in name": {map[string]any{"...": 1}, nil},
	} {
		if _, err := sdjwt.Build(tc.claims, tc.sd); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	b, err := sdjwt.Build(map[string]any{"a": 1}, nil)
	if err != nil || b.Payload["_sd"] != nil || len(b.Disclosures) != 0 {
		t.Fatalf("no sd: %v %v", b, err)
	}
}
