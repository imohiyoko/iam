package audit

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func chain(t *testing.T, n int) []Record {
	t.Helper()
	var out []Record
	var last *Record
	for i := range n {
		r, err := Next(last, Event{ID: "evt_" + string(rune('a'+i)), Time: time.Unix(int64(i), 0), Type: "test", Result: ResultSuccess})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
		last = &out[len(out)-1]
	}
	return out
}

func TestVerify(t *testing.T) {
	rs := chain(t, 5)
	if _, err := Verify(Genesis, 1, rs); err != nil {
		t.Fatal(err)
	}
	// 途中からでも、直前のハッシュ（チェックポイント）があれば検証できる。
	if _, err := Verify(rs[1].Hash, 3, rs[2:]); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetected(t *testing.T) {
	cases := map[string]func([]Record){
		"payload": func(rs []Record) {
			rs[2].Payload = bytes.Replace(rs[2].Payload, []byte("success"), []byte("failure"), 1)
		},
		"delete": func(rs []Record) { copy(rs[2:], rs[3:]) },
		"hash":   func(rs []Record) { rs[2].Hash[0] ^= 1 },
		"realm":  func(rs []Record) { rs[2].RealmID = "rlm_other" },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			rs := chain(t, 5)
			tamper(rs)
			if _, err := Verify(Genesis, 1, rs); !errors.Is(err, ErrChainBroken) {
				t.Fatalf("want ErrChainBroken, got %v", err)
			}
		})
	}
}

func TestMarshalDeterministic(t *testing.T) {
	e := Event{ID: "evt_x", Time: time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("JST", 9*3600)), Details: map[string]any{"b": 1, "a": 2}}
	a, _ := Marshal(e)
	b, _ := Marshal(e)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	got, err := Unmarshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if got.Time.Location() != time.UTC {
		t.Fatalf("time not UTC: %v", got.Time)
	}
}

func TestExternalDropsClient(t *testing.T) {
	// 切り詰めた値は残し（出し方は出力先が選ぶ）、全文の暗号文は外す。
	e := External(Event{IP: "192.0.2.0/24", UserAgent: "Chrome on Windows", Client: "sealed"})
	if e.Client != "" || e.IP != "192.0.2.0/24" || e.UserAgent != "Chrome on Windows" {
		t.Fatalf("external = %+v", e)
	}
}
