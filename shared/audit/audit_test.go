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

// 鍵付きのチェーン（ADR 0086）。鍵を入れる前の鍵なしのレコードに続けられ、鍵が無ければ作り直せない。
func TestKeyedChain(t *testing.T) {
	keys := map[string][]byte{"ak_1": bytes.Repeat([]byte{1}, 32), "ak_2": bytes.Repeat([]byte{2}, 32)}
	lookup := func(id string) ([]byte, error) {
		if k, ok := keys[id]; ok {
			return k, nil
		}
		return nil, errors.New("no such key")
	}
	build := func(ids ...string) []Record {
		var out []Record
		var last *Record
		for i, kid := range ids {
			r, err := NextKeyed(last, Event{ID: "evt_" + string(rune('a'+i)), Type: "test"}, kid, keys[kid])
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
			last = &out[len(out)-1]
		}
		return out
	}
	verify := func(rs []Record, page int) error {
		c := Chain{Prev: Genesis, Next: 1, Keys: lookup}
		for len(rs) > 0 {
			n := min(page, len(rs))
			if err := c.Verify(rs[:n]); err != nil {
				return err
			}
			rs = rs[n:]
		}
		return nil
	}

	// 鍵なしから鍵付きへ、鍵の入れ替えをまたいでつながる。ページの境目でも同じ。
	rs := build("", "", "ak_1", "ak_1", "ak_2")
	for _, page := range []int{1, 2, 5} {
		if err := verify(rs, page); err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
	}
	if _, err := Verify(Genesis, 1, rs); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("keyed records without keys: %v", err)
	}

	cases := map[string]func([]Record) []Record{
		// 鍵の無い人が後ろを書き換えて、鍵なしのハッシュで作り直す。
		"rebuild unkeyed": func(rs []Record) []Record {
			out := append([]Record(nil), rs[:3]...)
			last := &out[2]
			for i := 3; i < len(rs); i++ {
				e, _ := Unmarshal(rs[i].Payload)
				e.Type = "forged"
				r, _ := Next(last, e)
				out = append(out, r)
				last = &out[len(out)-1]
			}
			return out
		},
		"wrong key":   func(rs []Record) []Record { rs[3].KeyID = "ak_2"; return rs },
		"unknown key": func(rs []Record) []Record { rs[3].KeyID = "ak_x"; return rs },
		"payload": func(rs []Record) []Record {
			rs[3].Payload = bytes.Replace(rs[3].Payload, []byte("test"), []byte("tost"), 1)
			return rs
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verify(tamper(build("", "", "ak_1", "ak_1", "ak_2")), 2); !errors.Is(err, ErrChainBroken) {
				t.Fatalf("want ErrChainBroken, got %v", err)
			}
		})
	}
}
