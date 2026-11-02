package sdjwt_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt/sdjwttest"
)

var now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

const (
	aud   = "redirect_uri:https://id.example/v1/login/methods/openid4vp/endpoints/response"
	nonce = "n-0S6_WzA2Mj"
)

func opts(iss *sdjwttest.Issuer) sdjwt.Options {
	return sdjwt.Options{Now: now, Skew: time.Minute, KBMaxAge: 5 * time.Minute, Audience: aud, Nonce: nonce,
		IssuerKey: func(s string, h jose.Header) (any, error) {
			if s != iss.ISS {
				return nil, errors.New("untrusted issuer")
			}
			return iss.Key.Public(), nil
		}}
}

func issue(t *testing.T) (*sdjwttest.Issuer, *sdjwttest.Holder, sdjwttest.Credential) {
	t.Helper()
	iss := sdjwttest.NewIssuer("https://issuer.example", "k1")
	h := sdjwttest.NewHolder()
	c := iss.Issue("urn:eudi:pid:1", h, map[string]any{"sub": "user-1"},
		map[string]any{"given_name": "Pat", "family_name": "Doe", "address": map[string]any{"country": "JP"}}, now)
	return iss, h, c
}

func TestVerify(t *testing.T) {
	iss, h, c := issue(t)
	got, err := sdjwt.Verify(h.Present(c, aud, nonce, now, "given_name", "address"), opts(iss))
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != iss.ISS || got.VCT != "urn:eudi:pid:1" || got.Claims["given_name"] != "Pat" || got.Claims["sub"] != "user-1" {
		t.Fatalf("claims = %+v", got)
	}
	if _, ok := got.Claims["family_name"]; ok {
		t.Fatal("undisclosed claim present")
	}
	if _, ok := got.Claims["_sd"]; ok {
		t.Fatal("_sd kept")
	}
	if got.Claims["address"].(map[string]any)["country"] != "JP" {
		t.Fatal("object claim")
	}
	if got.HasStatus {
		t.Fatal("status")
	}
}

func TestVerifyRejects(t *testing.T) {
	iss, h, c := issue(t)
	good := h.Present(c, aud, nonce, now, "given_name")
	other := sdjwttest.NewHolder()
	mallory := sdjwttest.NewIssuer("https://issuer.example", "k1")
	forged := mallory.Issue("urn:eudi:pid:1", h, nil, map[string]any{"given_name": "Eve"}, now)
	signed := good[:strings.LastIndexByte(good, '~')+1]
	cases := map[string]struct {
		raw string
		o   func(*sdjwt.Options)
	}{
		"no key binding":     {raw: signed},
		"wrong audience":     {raw: h.Present(c, "x509_hash:abc", nonce, now)},
		"wrong nonce":        {raw: h.Present(c, aud, "other", now)},
		"old key binding":    {raw: h.Present(c, aud, nonce, now.Add(-10*time.Minute))},
		"future key binding": {raw: h.Present(c, aud, nonce, now.Add(10*time.Minute))},
		"other holder key":   {raw: other.Present(c, aud, nonce, now)},
		"forged issuer key":  {raw: h.Present(forged, aud, nonce, now)},
		"untrusted issuer": {raw: good, o: func(o *sdjwt.Options) {
			o.IssuerKey = func(string, jose.Header) (any, error) { return nil, errors.New("no") }
		}},
		"expired":                {raw: good, o: func(o *sdjwt.Options) { o.Now = now.Add(48 * time.Hour) }},
		"disclosure added later": {raw: strings.Replace(good, "~", "~"+c.Disclosures["family_name"]+"~", 1)},
		"extra foreign disclosure": {raw: func() string {
			p := signed + sdjwttest.Disclosure("given_name", "Eve") + "~"
			return p + kb(h, p)
		}()},
		"duplicate disclosure": {raw: func() string {
			p := signed + c.Disclosures["given_name"] + "~"
			return p + kb(h, p)
		}()},
		"not compact":   {raw: "a.b~"},
		"no separator":  {raw: c.JWT},
		"too large":     {raw: strings.Repeat("a", sdjwt.MaxSize+1)},
		"bad character": {raw: c.JWT + "~a+b~"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := opts(iss)
			if tc.o != nil {
				tc.o(&o)
			}
			if _, err := sdjwt.Verify(tc.raw, o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func kb(h *sdjwttest.Holder, signed string) string {
	return sdjwttest.Sign(h.Key, sdjwt.TypeKB, nil, map[string]any{"aud": aud, "nonce": nonce, "iat": now.Unix(), "sd_hash": sdjwt.SDHash(signed)})
}

// present は payload に署名して、開示を付けて提示する。
func present(iss *sdjwttest.Issuer, h *sdjwttest.Holder, typ string, payload map[string]any, discs ...string) string {
	if _, ok := payload["cnf"]; !ok {
		payload["cnf"] = map[string]any{"jwk": h.JWK()}
	}
	signed := sdjwttest.Sign(iss.Key, typ, nil, payload) + "~"
	for _, d := range discs {
		signed += d + "~"
	}
	return signed + sdjwttest.Sign(h.Key, sdjwt.TypeKB, nil, map[string]any{"aud": aud, "nonce": nonce, "iat": now.Unix(), "sd_hash": sdjwt.SDHash(signed)})
}

func TestVerifyRejectsPayloads(t *testing.T) {
	iss := sdjwttest.NewIssuer("https://issuer.example", "k1")
	h := sdjwttest.NewHolder()
	base := func() map[string]any {
		return map[string]any{"iss": iss.ISS, "vct": "urn:x", "iat": now.Unix()}
	}
	with := func(k string, v any) map[string]any {
		m := base()
		m[k] = v
		return m
	}
	issDisc := sdjwttest.Disclosure("vct", "urn:other")
	arrayDisc := sdjwttest.Disclosure("", "x")
	named := sdjwttest.Disclosure("n", "x")
	cases := map[string]struct {
		typ     string
		payload map[string]any
		discs   []string
	}{
		"wrong typ":               {typ: "JWT", payload: base()},
		"no vct":                  {payload: map[string]any{"iss": iss.ISS}},
		"no cnf":                  {payload: with("cnf", "x")},
		"private cnf":             {payload: with("cnf", map[string]any{"jwk": privateJWK(h)})},
		"symmetric cnf":           {payload: with("cnf", map[string]any{"jwk": map[string]any{"kty": "oct", "k": "AAAA"}})},
		"sd_alg":                  {payload: with("_sd_alg", "sha-512")},
		"not yet valid":           {payload: with("nbf", now.Add(time.Hour).Unix())},
		"bad exp":                 {payload: with("exp", "tomorrow")},
		"reserved disclosure":     {payload: with("_sd", []any{sdjwt.Digest(issDisc)}), discs: []string{issDisc}},
		"array disclosure in _sd": {payload: with("_sd", []any{sdjwt.Digest(arrayDisc)}), discs: []string{arrayDisc}},
		"named disclosure in array": {payload: with("list", []any{map[string]any{"...": sdjwt.Digest(named)}}),
			discs: []string{named}},
		"overwrite": {payload: func() map[string]any {
			m := with("n", "clear")
			m["_sd"] = []any{sdjwt.Digest(named)}
			return m
		}(), discs: []string{named}},
		"digest twice": {payload: func() map[string]any {
			m := with("_sd", []any{sdjwt.Digest(named)})
			m["obj"] = map[string]any{"_sd": []any{sdjwt.Digest(named)}}
			return m
		}(), discs: []string{named}},
		"unreferenced":    {payload: base(), discs: []string{named}},
		"nested sd_alg":   {payload: with("obj", map[string]any{"_sd_alg": "sha-256"})},
		"_sd not array":   {payload: with("_sd", "x")},
		"... with others": {payload: with("list", []any{map[string]any{"...": "x", "y": 1}})},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			typ := tc.typ
			if typ == "" {
				typ = sdjwt.TypeVC
			}
			if _, err := sdjwt.Verify(present(iss, h, typ, tc.payload, tc.discs...), opts(iss)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// 配列の要素の開示と、旧い typ は受ける。
	ok := with("list", []any{map[string]any{"...": sdjwt.Digest(arrayDisc)}, "y", map[string]any{"...": sdjwt.Digest("decoy")}})
	got, err := sdjwt.Verify(present(iss, h, sdjwt.TypeVCLegacy, ok, arrayDisc), opts(iss))
	if err != nil {
		t.Fatal(err)
	}
	if l := got.Claims["list"].([]any); len(l) != 2 || l[0] != "x" || l[1] != "y" {
		t.Fatalf("list = %v", l)
	}
}

func privateJWK(h *sdjwttest.Holder) map[string]any {
	b, _ := json.Marshal(jose.JSONWebKey{Key: h.Key})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func TestDuplicateMembers(t *testing.T) {
	iss := sdjwttest.NewIssuer("https://issuer.example", "k1")
	h := sdjwttest.NewHolder()
	// 同じ名前の項目を持つ payload に署名する（Sign は JSON を作り直すので、生の JSON を署名する）。
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: iss.Key}, (&jose.SignerOptions{}).WithType(sdjwt.TypeVC))
	jwk, _ := json.Marshal(h.JWK())
	obj, _ := s.Sign([]byte(`{"iss":"` + iss.ISS + `","vct":"a","vct":"b","cnf":{"jwk":` + string(jwk) + `}}`))
	jwt, _ := obj.CompactSerialize()
	signed := jwt + "~"
	raw := signed + kb(h, signed)
	if _, err := sdjwt.Verify(raw, opts(iss)); err == nil {
		t.Fatal("accepted duplicate members")
	}
}

func TestDisclosureForms(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, d := range map[string]string{
		"not array":    enc(`{"a":1}`),
		"one element":  enc(`["salt"]`),
		"four":         enc(`["s","n","v","x"]`),
		"salt number":  enc(`[1,"n","v"]`),
		"name number":  enc(`["s",1,"v"]`),
		"reserved _sd": enc(`["s","_sd","v"]`),
		"reserved ...": enc(`["s","...","v"]`),
		"trailing":     enc(`["s","n","v"] 1`),
		"not base64":   "!!",
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{"_sd": []any{sdjwt.Digest(d)}}
			if _, err := sdjwt.Disclose(claims, []string{d}, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
