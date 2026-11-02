package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 の付録 B の試験値（SHA1、8 桁のうち下 6 桁）。
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		if got := Code(secret, Step(time.Unix(unix, 0))); got != want {
			t.Errorf("%d: got %s want %s", unix, got, want)
		}
	}
}

func TestVerifyWindow(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	for d, want := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		step, ok := Verify(secret, Code(secret, Step(now)+d), now)
		if ok != want || (ok && step != Step(now)+d) {
			t.Errorf("offset %d: step %d ok %v", d, step, ok)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(secret, bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestURI(t *testing.T) {
	u := URI([]byte("12345678901234567890"), "Example", "alice@example.com")
	if !strings.HasPrefix(u, "otpauth://totp/Example:alice@example.com?") || !strings.Contains(u, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") {
		t.Fatal(u)
	}
}
