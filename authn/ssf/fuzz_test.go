package ssf_test

import (
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/internal/testkit"
)

// FuzzParseSET は受け取った SET の読み取り（ヘッダー・署名・クレーム）がどんな入力でも panic しないことを確かめる。
func FuzzParseSET(f *testing.F) {
	key := newSigner(f, "k")
	now := testkit.T0
	good := key.sign(f, ssf.SETType, map[string]any{"iss": txIss, "aud": rpAud, "iat": now.Unix(), "jti": "1",
		"sub_id": map[string]any{"format": "complex", "user": map[string]any{"format": "email", "email": "a@example.com"},
			"device": map[string]any{"format": "opaque", "id": "d"}},
		"events": map[string]any{ssf.EventDeviceComplianceChange: map[string]any{"current_status": "compliant"}}})
	f.Add(good)
	f.Add([]byte("eyJhbGciOiJub25lIiwidHlwIjoic2VjZXZlbnQrand0In0.e30."))
	f.Add([]byte(`{"iss":"x","aud":["a"],"iat":1,"jti":"1","sub_id":{"format":"email","email":"a"},"events":{"e":{}}}`))
	f.Add([]byte(`{"events":{"e":{"subject":{"format":"complex","user":{"format":"opaque","id":"1"}}}}}`))
	f.Add([]byte(".."))
	keys := key.keys(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := ssf.ParseHeader(b); err == nil {
			if payload, err := ssf.VerifySignature(b, h, keys); err == nil {
				if _, err := ssf.ParseClaims(payload, now, time.Hour); err != nil && string(b) == string(good) {
					t.Fatal("valid SET rejected")
				}
			}
		}
		// 署名を確かめた後のクレームの読み取りも、そのまま試す。
		if set, err := ssf.ParseClaims(b, now, 24*time.Hour); err == nil {
			if set.Subject == nil || !set.Subject.Valid() || set.Event == "" || set.JTI == "" || set.Issuer == "" {
				t.Fatalf("accepted an incomplete SET: %+v", set)
			}
			_ = set.EventTime()
			_ = set.Subject.UserPart()
		}
		_, _ = ssf.PublicKeys(b)
	})
}
