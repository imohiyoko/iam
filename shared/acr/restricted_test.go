package acr

import "testing"

// SMS・音声の OTP は制限付きの認証器（ADR 0104）。所持として数えるので、パスワードと合わせて AAL2 で、AAL3 には届かない。
func TestRestricted(t *testing.T) {
	for _, amr := range [][]string{{"otp", "sms", "mfa"}, {"pwd", "tel"}} {
		if !Restricted(amr) {
			t.Fatalf("%v should be restricted", amr)
		}
	}
	for _, amr := range [][]string{{"otp", "swk", "mfa"}, {"pwd", "otp"}, nil, {"fed:sms"}} {
		if Restricted(amr) {
			t.Fatalf("%v should not be restricted", amr)
		}
	}
	if AAL([]string{"pwd", "sms"}) != 2 || AAL([]string{"pwd", "tel"}) != 2 || AAL([]string{"sms"}) != 1 {
		t.Fatal("sms and tel count as possession")
	}
}
