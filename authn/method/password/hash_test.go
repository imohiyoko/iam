package password_test

import (
	"crypto/sha1" // #nosec G505 -- テストの偽の確認
	"encoding/hex"
	"strings"
	"testing"

	password "github.com/imohiyoko/iam/authn/method/password"
)

var fast = password.Params{Memory: 8, Time: 1, Threads: 1}

func TestHashAndVerify(t *testing.T) {
	h, err := password.Hash("correct horse battery staple", fast)
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=8,t=1,p=1$") {
		t.Fatalf("hash = %q, %v", h, err)
	}
	if h2, _ := password.Hash("correct horse battery staple", fast); h2 == h {
		t.Fatal("salt not random")
	}
	if ok, rehash, err := password.Verify("correct horse battery staple", h, fast); !ok || rehash || err != nil {
		t.Fatalf("verify = %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := password.Verify("wrong", h, fast); ok {
		t.Fatal("wrong password accepted")
	}
	if _, rehash, _ := password.Verify("correct horse battery staple", h, password.Params{Memory: 16, Time: 1, Threads: 1}); !rehash {
		t.Fatal("changed params should ask for rehash")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"} {
		if _, _, err := password.Verify("x", bad, fast); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func sha(s string) string {
	sum := sha1.Sum([]byte(s)) // #nosec G401 -- テストの偽の確認
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
