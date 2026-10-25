package id

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRoundTrip(t *testing.T) {
	for range 1000 {
		s := New(User)
		u, err := Parse(User, s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if got := FromUUID(User, u); got != s {
			t.Fatalf("round trip: %q != %q", got, s)
		}
	}
}

func TestPrefixMismatch(t *testing.T) {
	s := New(User)
	if _, err := Parse(Org, s); err == nil {
		t.Fatal("want error for wrong prefix")
	}
}

func TestOrdered(t *testing.T) {
	prev := New(Event)
	for range 1000 {
		next := New(Event)
		if next <= prev {
			t.Fatalf("not ordered: %q <= %q", next, prev)
		}
		prev = next
	}
}

func TestInvalid(t *testing.T) {
	for _, s := range []string{
		"", "usr", "usr_", "usr_" + strings.Repeat("0", 25), "usr_" + strings.Repeat("Z", 26),
		"usr_" + strings.Repeat("U", 26), FromUUID(User, uuid.New()), // v4 は受け付けない
	} {
		if Valid(User, s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}

func TestLowercaseAccepted(t *testing.T) {
	s := New(Session)
	if !Valid(Session, "ses_"+strings.ToLower(s[4:])) {
		t.Fatal("lowercase should be accepted")
	}
}
