package id

import (
	"strings"
	"testing"
	"time"

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

// 内部 ID はミリ秒が違えば作成の順に並ぶ（同じミリ秒の中は乱数で、順序は付けない）。
func TestOrdered(t *testing.T) {
	prev := New(Event)
	for range 20 {
		time.Sleep(2 * time.Millisecond)
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
		"usr_" + strings.Repeat("U", 26), "org_" + New(User)[4:],
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

// 方式を変えても既存の ID は有効なまま（形は同じ）。
func TestGeneratorsInterchangeable(t *testing.T) {
	old := New(User)
	SetGenerators(Random{}, Random{})
	defer SetGenerators(UUIDv7{}, Random{})
	fresh := New(User)
	if !Valid(User, old) || !Valid(User, fresh) || len(old) != len(fresh) {
		t.Fatalf("old %q / new %q", old, fresh)
	}
	u, _ := Parse(User, fresh)
	if u.Version() != 4 {
		t.Fatalf("generator not switched: v%d", u.Version())
	}
}

func TestExternalIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		s := NewExternal(Session)
		u, err := Parse(Session, s)
		if err != nil || u.Version() != 4 || seen[s] {
			t.Fatalf("external id %q: %v", s, err)
		}
		seen[s] = true
	}
}

// UUIDv7 は時刻の 48bit 以外をすべて乱数で埋める（同じミリ秒でも連番にしない。ADR 0045）。
func TestUUIDv7RandomBits(t *testing.T) {
	before := time.Now().UnixMilli()
	a, err := UUIDv7{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Version() != 7 || a.Variant() != uuid.RFC4122 {
		t.Fatalf("version %d variant %v", a.Version(), a.Variant())
	}
	ms := int64(a[0])<<40 | int64(a[1])<<32 | int64(a[2])<<24 | int64(a[3])<<16 | int64(a[4])<<8 | int64(a[5])
	if ms < before || ms > time.Now().UnixMilli() {
		t.Fatalf("timestamp %d not in [%d, now]", ms, before)
	}
	// rand_a（12bit）が連番でないこと：続けて作った ID の rand_a が 1 ずつ増えたりしない。
	randA := func(u uuid.UUID) int { return int(u[6]&0x0f)<<8 | int(u[7]) }
	prev, steps := a, 0
	for range 64 {
		u, _ := UUIDv7{}.Generate()
		if randA(u) == randA(prev)+1 {
			steps++
		}
		prev = u
	}
	if steps > 4 {
		t.Fatalf("rand_a looks like a counter: %d of 64 steps were +1", steps)
	}
}
