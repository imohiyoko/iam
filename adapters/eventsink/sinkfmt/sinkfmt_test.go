package sinkfmt

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
)

var event = audit.Event{Version: 1, ID: "evt_1", Time: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC), Type: "login.succeeded",
	Result: audit.ResultSuccess, Actor: audit.Actor{Type: "user", ID: "usr_1"}, RealmID: "rlm_1", SessionID: "ses_1",
	IP: "203.0.113.0/24", UserAgent: "Chrome on Windows", Client: "sealed", RequestID: "req_1", Details: map[string]any{"method": "passkey"},
	Chain: &audit.ChainRef{Seq: 3, Hash: "ab"}}

func encoder(t *testing.T, opts map[string]string) *Encoder {
	t.Helper()
	e, err := New(plugin.Config{Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPIIModes(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 32))
	t.Setenv("IAM_TEST_PSEUDONYM", key)
	raw := encoder(t, map[string]string{"pii": "raw"}).Redact(event)
	if raw.IP != event.IP || raw.UserAgent != event.UserAgent || raw.Client != "" {
		t.Fatalf("raw = %+v", raw)
	}
	omit := encoder(t, map[string]string{"pii": "omit"}).Redact(event)
	if omit.IP != "" || omit.UserAgent != "" || omit.Client != "" {
		t.Fatalf("omit = %+v", omit)
	}
	p := encoder(t, map[string]string{"pseudonym_key_env": "IAM_TEST_PSEUDONYM"})
	a, b := p.Redact(event), p.Redact(event)
	if !strings.HasPrefix(a.IP, "p_") || a.IP != b.IP || a.IP == event.IP || a.UserAgent != event.UserAgent {
		t.Fatalf("pseudonymized = %+v", a)
	}
	// 既定は鍵があれば仮名化、無ければ出さない。
	if e := encoder(t, nil); e.PII != PIIOmit {
		t.Fatalf("default without key = %s", e.PII)
	}
	if p.PII != PIIPseudonymize {
		t.Fatalf("default with key = %s", p.PII)
	}
	for _, opts := range []map[string]string{{"pii": "nope"}, {"format": "cef"}, {"pseudonym_key_env": "IAM_TEST_MISSING"}, {"pii": "pseudonymize"}} {
		if _, err := New(plugin.Config{Options: opts}); err == nil {
			t.Fatalf("%v must be rejected", opts)
		}
	}
	t.Setenv("IAM_TEST_SHORT", "abcd")
	if _, err := New(plugin.Config{Options: map[string]string{"pseudonym_key_env": "IAM_TEST_SHORT"}}); err == nil {
		t.Fatal("short key must be rejected")
	}
}

func TestOCSF(t *testing.T) {
	b, err := encoder(t, map[string]string{"format": "ocsf", "pii": "raw"}).Encode(event)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	meta := got["metadata"].(map[string]any)
	if got["class_uid"] != float64(3002) || got["type_uid"] != float64(300201) || got["status_id"] != float64(1) ||
		meta["uid"] != "evt_1" || meta["version"] != OCSFVersion || meta["correlation_uid"] != "req_1" ||
		got["time"] != float64(event.Time.UnixMilli()) {
		t.Fatalf("ocsf = %s", b)
	}
	if src := got["src_endpoint"].(map[string]any); src["ip"] != "203.0.113.0/24" {
		t.Fatalf("src_endpoint = %v", src)
	}
	un := got["unmapped"].(map[string]any)
	if un["realm_id"] != "rlm_1" || un["chain"] == nil || un["details"] == nil {
		t.Fatalf("unmapped = %v", un)
	}
	if strings.Contains(string(b), "sealed") {
		t.Fatal("client ciphertext leaked")
	}
	for typ, class := range map[string]int{"user.created": 3001, "role.granted": 3005, "org.created": 3004, "session.revoked": 3002} {
		if c := classOf(typ); c != class {
			t.Errorf("classOf(%s) = %d, want %d", typ, c, class)
		}
	}
	if a := activityOf(3001, "user.created"); a != 1 {
		t.Errorf("activity = %d", a)
	}
}

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{"https://siem.example/x": true, "http://localhost:4318/v1/logs": true, "http://siem.example": false,
		"ftp://x": false, "https://u:p@siem.example": false, "": false} {
		if _, err := CheckURL(plugin.Config{}, raw); (err == nil) != ok {
			t.Errorf("CheckURL(%q) = %v", raw, err)
		}
	}
	if _, err := CheckURL(plugin.Config{Dev: true}, "http://siem.example"); err != nil {
		t.Errorf("dev http: %v", err)
	}
}
