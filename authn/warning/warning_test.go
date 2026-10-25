package warning_test

import (
	"errors"
	"testing"

	"github.com/imohiyoko/iam/authn/warning"
)

func codes(ws []warning.Warning) []string {
	var out []string
	for _, w := range ws {
		out = append(out, w.Code+":"+string(w.Action))
	}
	return out
}

func TestSingleFactor(t *testing.T) {
	ev, err := warning.New(map[string]warning.Action{warning.CodeSingleFactor: warning.Warn})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		amr  []string
		want bool
	}{
		{[]string{"otp"}, true},
		{[]string{"fed"}, true},
		{[]string{"pwd"}, true},
		{[]string{"pwd", "pin"}, true}, // 同じ種類の要素は1つと数える
		{[]string{"pwd", "otp"}, false},
		{[]string{"hwk", "user"}, false},
		{[]string{"mfa"}, false},
		{nil, true},
	} {
		ws, err := ev.Evaluate(warning.Evidence{AMR: c.amr})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(ws) == 1 && ws[0].Code == warning.CodeSingleFactor; got != c.want {
			t.Errorf("amr %v: single_factor = %v, want %v", c.amr, got, c.want)
		}
	}
}

func TestDefaults(t *testing.T) {
	ev, err := warning.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := ev.Evaluate(warning.Evidence{AMR: []string{"fed"}, OAuthEmailVerified: new(false)})
	if err != nil {
		t.Fatal(err)
	}
	// single_factor は既定で ignore（返さない）、oauth_email_unverified は warn。
	if got := codes(ws); len(got) != 1 || got[0] != "oauth_email_unverified:warn" {
		t.Fatalf("warnings = %v", got)
	}
	ws, _ = ev.Evaluate(warning.Evidence{AMR: []string{"fed"}, OAuthEmailVerified: new(true)})
	if len(ws) != 0 {
		t.Fatalf("verified: %v", codes(ws))
	}
	if ws, _ := ev.Evaluate(warning.Evidence{AMR: []string{"otp"}}); len(ws) != 0 {
		t.Fatalf("not oauth: %v", codes(ws))
	}
}

func TestDeny(t *testing.T) {
	ev, _ := warning.New(map[string]warning.Action{warning.CodeSingleFactor: warning.Deny, warning.CodeOAuthEmailUnverified: warning.Deny})
	ws, err := ev.Evaluate(warning.Evidence{AMR: []string{"fed"}, OAuthEmailVerified: new(false)})
	d, ok := errors.AsType[*warning.DeniedError](err)
	if !ok || len(d.Reasons()) != 2 || d.Reasons()[0] != "warning_denied.single_factor" || d.Reasons()[1] != "warning_denied.oauth_email_unverified" {
		t.Fatalf("err = %v", err)
	}
	if len(ws) != 2 {
		t.Fatalf("warnings = %v", codes(ws))
	}
}

func TestNilEvaluatorDoesNothing(t *testing.T) {
	var ev *warning.Evaluator
	if ws, err := ev.Evaluate(warning.Evidence{AMR: []string{"otp"}}); ws != nil || err != nil {
		t.Fatalf("%v %v", ws, err)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []map[string]warning.Action{
		{"no_such_code": warning.Warn},
		{warning.CodeSingleFactor: "block"},
	} {
		if _, err := warning.New(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
