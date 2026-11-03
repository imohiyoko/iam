package vci_test

import (
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/vci"
)

// FuzzVerifyProof は proof の JWT の解析と確かめが、どの入力でも panic せず、通ったものは nonce と公開鍵を持つことを確かめる。
func FuzzVerifyProof(f *testing.F) {
	k := newKey(f)
	f.Add(proofJWT(f, k, jose.ES256, nil, nil))
	f.Add(proofJWT(f, k, jose.ES256, map[jose.HeaderKey]any{"kid": "x"}, nil))
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := vci.VerifyProof(raw, vci.ProofOptions{Audience: issuer, Now: now, ClientID: "wallet"})
		if err != nil {
			if code, _ := vci.CodeOf(err); code != vci.CodeInvalidProof && code != vci.CodeInvalidNonce {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if p.Nonce == "" || !p.Key.IsPublic() || p.Thumbprint == "" {
			t.Fatalf("accepted proof without nonce or public key: %+v", p)
		}
	})
}

// FuzzParseCredentialRequest は credential の要求の解析が、どの入力でも panic せず、通ったものは定義と proof を持つことを確かめる。
func FuzzParseCredentialRequest(f *testing.F) {
	f.Add([]byte(`{"credential_configuration_id":"employee","proofs":{"jwt":["a.b.c"]}}`))
	f.Add([]byte(`{"credential_identifier":"x"}`))
	f.Add([]byte(`{"proofs":{"jwt":[1,2]}}`))
	f.Add([]byte(`[[[[[[`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := vci.ParseCredentialRequest(b)
		if err != nil {
			if code, _ := vci.CodeOf(err); code == "" {
				t.Fatalf("error without code: %v", err)
			}
			return
		}
		if r.ConfigurationID == "" || r.Proof == "" {
			t.Fatalf("accepted %q as %+v", b, r)
		}
	})
}
