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
	if !strings.HasPrefix(a.IP, "p_") || a.IP != b.IP || a.IP == event.IP ||
		!strings.HasPrefix(a.UserAgent, "p_") || a.UserAgent == event.UserAgent {
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
	// 切り詰めた IP はアドレスではないので ip に入れない。
	if src := got["src_endpoint"].(map[string]any); src["ip"] != nil || src["subnet_uid"] != "203.0.113.0/24" {
		t.Fatalf("src_endpoint = %v", src)
	}
	if u := got["user"].(map[string]any); u["uid"] != event.Actor.ID {
		t.Fatalf("user = %v", u)
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
	for typ, want := range map[string]int{
		"user.created": 300101, "user.deleted": 300106, "password.changed": 300103, "passkey.registered": 300110,
		"totp.removed": 300111, "login.succeeded": 300201, "session.revoked": 300202, "org.created": 300401,
		"org.settings_changed": 300403, "org.deleted": 300404, "org.suspended": 300412, "org.suspension_lifted": 300413,
		"role.created": 300401, "role.granted": 300501, "role.revoked": 300502, "group.created": 300606,
		"group.deleted": 300605, "group.member_added": 300603, "group.member_removed": 300604, "group.renamed": 300699,
	} {
		c := classOf(typ)
		if got := c*100 + activityOf(c, typ); got != want {
			t.Errorf("type_uid(%s) = %d, want %d", typ, got, want)
		}
	}
}

func TestOCSFTargets(t *testing.T) {
	enc := encoder(t, map[string]string{"format": "ocsf", "pii": "omit"})
	get := func(e audit.Event) map[string]any {
		t.Helper()
		b, err := enc.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	base := audit.Event{ID: "evt_2", Time: event.Time, Result: audit.ResultSuccess, Actor: audit.Actor{Type: "service_account", ID: "sa_1"}}
	g := base
	g.Type, g.Details = "group.member_added", map[string]any{"group_id": "grp_1", "name": "ops", "member_id": "usr_2"}
	if m := get(g); m["group"].(map[string]any)["uid"] != "grp_1" || m["user"].(map[string]any)["uid"] != "usr_2" {
		t.Fatalf("group = %v", m)
	}
	r := base
	r.Type, r.Details = "role.granted", map[string]any{"role": "viewer", "principal_type": "user", "principal_id": "usr_3"}
	if m := get(r); m["user"].(map[string]any)["uid"] != "usr_3" || m["privileges"].([]any)[0] != "viewer" {
		t.Fatalf("access = %v", m)
	}
	o := base
	o.Type, o.OrgID = "org.suspended", "org_1"
	if ent := get(o)["entity"].(map[string]any); ent["uid"] != "org_1" || ent["type"] != "org" {
		t.Fatalf("entity = %v", ent)
	}
	// 対象の識別子が無くても対象は省かない（name を unknown にする）。
	l := base
	l.Type, l.Actor = "login.failed", audit.Actor{Type: "system"}
	if u := get(l)["user"].(map[string]any); u["name"] != "unknown" {
		t.Fatalf("unknown user = %v", u)
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
