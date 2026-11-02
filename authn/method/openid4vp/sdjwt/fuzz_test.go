package sdjwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// FuzzParse は提示の解析が、どんな入力でも panic せず、受けたものは形の約束を守ることを確かめる。
func FuzzParse(f *testing.F) {
	f.Add("eyJhIjoxfQ.eyJiIjoxfQ.c2ln~WyJzIiwibiIsInYiXQ~")
	f.Add("a.b.c~d~e.f.g")
	f.Add("~~~")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err != nil {
			return
		}
		if !isCompactJWS(p.IssuerJWT) || len(p.Disclosures) > MaxDisclosures || !strings.HasSuffix(p.Signed, "~") ||
			p.Signed+p.KBJWT != s {
			t.Fatalf("parse broke its contract: %q", s)
		}
		// 署名を確かめる前の段で、検証の全体も panic しない。
		_, _ = Verify(s, Options{Now: time.Unix(1_800_000_000, 0), Skew: time.Minute, KBMaxAge: time.Minute, Audience: "a", Nonce: "n",
			IssuerKey: func(string, jose.Header) (any, error) { return nil, ErrVerification }})
	})
}

// FuzzDisclose は開示の処理が、どんな payload と開示でも panic せず、受けたものに _sd・_sd_alg と `...` の要素が残らないことを確かめる。
func FuzzDisclose(f *testing.F) {
	d := base64.RawURLEncoding.EncodeToString([]byte(`["salt","name","value"]`))
	e := base64.RawURLEncoding.EncodeToString([]byte(`["salt",{"_sd":["x"]}]`))
	f.Add(`{"_sd":["`+Digest(d)+`"],"_sd_alg":"sha-256"}`, d, "")
	f.Add(`{"a":[{"...":"`+Digest(e)+`"}]}`, e, "")
	f.Add(`{"_sd":["`+Digest(d)+`","`+Digest(d)+`"]}`, d, d)
	f.Add(`{"a":{"b":{"c":[1,2,{"...":"x"}]}}}`, "", "")
	f.Fuzz(func(t *testing.T, payload, d1, d2 string) {
		claims, err := decodeObject([]byte(payload))
		if err != nil {
			return
		}
		var discs []string
		for _, x := range []string{d1, d2} {
			if x != "" {
				discs = append(discs, x)
			}
		}
		out, err := Disclose(claims, discs, Reserved)
		if err != nil {
			return
		}
		var walk func(v any, top bool)
		walk = func(v any, top bool) {
			switch v := v.(type) {
			case map[string]any:
				if _, ok := v["_sd"]; ok {
					t.Fatalf("_sd left in %q", payload)
				}
				if _, ok := v["_sd_alg"]; ok {
					t.Fatalf("_sd_alg left in %q", payload)
				}
				for _, x := range v {
					walk(x, false)
				}
			case []any:
				for _, x := range v {
					if m, ok := x.(map[string]any); ok {
						if _, ok := m["..."]; ok && len(m) == 1 {
							t.Fatalf("array digest left in %q", payload)
						}
					}
					walk(x, false)
				}
			}
		}
		walk(out, true)
	})
}
