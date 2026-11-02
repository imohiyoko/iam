package app

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"go.yaml.in/yaml/v3"

	kt "github.com/imohiyoko/iam/authn/method/kerberos/kerberostest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// Kerberos / SPNEGO（HTTP の Negotiate。ADR 0107）を HTTP で通して確かめる。

const krbRealm = "EXAMPLE.COM"

func newKerberosEnv(t *testing.T, mapping string, features ...string) (*loginEnv, *kt.KDC) {
	t.Helper()
	k := kt.New(t, kt.Entry{SPN: kt.SPN, Realm: krbRealm, EType: etypeID.AES256_CTS_HMAC_SHA1_96})
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Features = &features
		var n map[string]yaml.Node
		src := "kerberos:\n  realms:\n    " + c.Realm.Slug + ":\n      keytab: " + k.Path + "\n      service_principal: " + kt.SPN + "\n" +
			"      mapping: {rule: " + mapping + "}\n"
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		c.Methods = n
	}, feature.Registered())
	return l, k
}

// negotiate は Negotiate のトークン（と Cookie のセッション）を付けた要求。
func (l *loginEnv) negotiate(t *testing.T, cookie, path string, body any, token []byte) (int, map[string]any, string, http.Header) {
	t.Helper()
	w := l.doReq(t, l.a.PublicHandler(), "POST", path, body, func(r *http.Request) {
		if token != nil {
			r.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
		}
		if cookie != "" {
			r.Header.Set("Cookie", sessionCookie+"="+cookie)
		}
	})
	status, out, c := decodeResult(w.Code, w.Body.Bytes(), w.Result().Cookies())
	return status, out, c, w.Header()
}

func (l *loginEnv) kerberosBegin(t *testing.T) string {
	t.Helper()
	status, st, _, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:begin", map[string]any{}, nil)
	if status != 200 {
		t.Fatalf("begin: %d %v", status, st)
	}
	return st["flow_id"].(string)
}

func TestKerberosEnrollAndLogin(t *testing.T) {
	l, k := newKerberosEnv(t, "enrollment", feature.Org, feature.Warnings, feature.Kerberos)
	_, full := l.login(t, "pat@example.com")
	tok := func() []byte { return k.Token(t, kt.Opts{CName: []string{"pat"}, CRealm: krbRealm, SRealm: krbRealm}) }

	// 登録：Cookie のセッションと Negotiate。トークンが無ければ 401 とチャレンジ。
	status, st, _, h := l.negotiate(t, full, "/v1/me/credentials/kerberos:enroll-begin", map[string]any{}, nil)
	if status != 401 || st["error"] != "negotiate" || h.Get("WWW-Authenticate") != "Negotiate" {
		t.Fatalf("enroll-begin without token: %d %v %v", status, st, h)
	}
	status, st, _, _ = l.negotiate(t, full, "/v1/me/credentials/kerberos:enroll-begin", map[string]any{}, tok())
	if status != 200 || st["payload"].(map[string]any)["principal"] != "pat@"+krbRealm {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	status, res, _, _ := l.negotiate(t, full, "/v1/me/credentials/kerberos:enroll-complete", map[string]any{"flow_id": st["flow_id"]}, nil)
	if status != 200 || res["credential"].(map[string]any)["method"] != "kerberos" {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}

	// ログイン：完了をトークンなしで呼ぶと 401 とチャレンジ（回数に数えず、失敗の監査ログにも残さない）。同じフローで送り直す。
	flow := l.kerberosBegin(t)
	for range 6 {
		status, st, _, h = l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow}, nil)
		if status != 401 || st["error"] != "negotiate" || h.Get("WWW-Authenticate") != "Negotiate" {
			t.Fatalf("complete without token: %d %v %v", status, st, h)
		}
	}
	if n := len(l.auditOf(t, "login.failed")); n != 0 {
		t.Fatalf("negotiate challenges recorded as failures: %d", n)
	}
	status, login, cookie, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow}, tok())
	if status != 200 || cookie == "" || login["next"] != nil {
		t.Fatalf("kerberos login: %d %v", status, login)
	}
	status, sessions := l.me(t, cookie)
	var amr []string
	for _, s := range sessions {
		if s["current"] == true {
			amr = anyStrings(s["auth_methods"])
		}
	}
	if status != 200 || strings.Join(amr, ",") != "wia" {
		t.Fatalf("session after kerberos login: %d %v", status, sessions)
	}
	if ev := l.lastAudit(t, "login.succeeded"); ev.Details["method"] != "kerberos" {
		t.Fatalf("audit: %v", ev)
	}

	// 登録していないプリンシパルは 401（チャレンジを付けない）と失敗の監査ログ。
	flow = l.kerberosBegin(t)
	status, _, _, h = l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"mallory"}, CRealm: krbRealm, SRealm: krbRealm}))
	if status != 401 || h.Get("WWW-Authenticate") != "" {
		t.Fatalf("unenrolled: %d %v", status, h)
	}
	if n := len(l.auditOf(t, "login.failed")); n != 1 {
		t.Fatalf("login.failed = %d", n)
	}

	// Negotiate のヘッダーは、ほかのパスでも Cookie のセッションを妨げない（読まずに消す）。
	w := l.doReq(t, l.a.PublicHandler(), "GET", "/v1/me/sessions", nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(tok()))
		r.Header.Set("Cookie", sessionCookie+"="+cookie)
	})
	if w.Code != 200 {
		t.Fatalf("sessions with a negotiate header: %d", w.Code)
	}
}

func anyStrings(v any) []string {
	var out []string
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func TestKerberosEmailMapping(t *testing.T) {
	l, k := newKerberosEnv(t, "email", feature.Org, feature.Warnings, feature.Kerberos)
	l.login(t, "pat@example.com")
	flow := l.kerberosBegin(t)
	status, login, cookie, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"pat"}, CRealm: krbRealm, SRealm: krbRealm}))
	if status != 200 || cookie == "" {
		t.Fatalf("kerberos login: %d %v", status, login)
	}
	// 確認済みのメールの無いプリンシパル。
	flow = l.kerberosBegin(t)
	if status, _, _, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"nobody"}, CRealm: krbRealm, SRealm: krbRealm})); status != 401 {
		t.Fatalf("unmapped: %d", status)
	}
	// 規則 email では本人の登録を使わない。
	if status, st, _, _ := l.negotiate(t, cookie, "/v1/me/credentials/kerberos:enroll-begin", map[string]any{},
		k.Token(t, kt.Opts{CName: []string{"pat"}, CRealm: krbRealm, SRealm: krbRealm})); status != 400 || st["error"] != "enrollment_not_supported" {
		t.Fatalf("enroll: %d %v", status, st)
	}
}

// 規則 ldap で、フィーチャー ldap が動いていなければ、ログインは 503 で止まる（誰も通さない）。
func TestKerberosLDAPMappingWithoutDirectory(t *testing.T) {
	l, k := newKerberosEnv(t, "ldap, ldap: {connection: corp}", feature.Org, feature.Warnings, feature.Kerberos)
	flow := l.kerberosBegin(t)
	status, st, _, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"pat"}, CRealm: krbRealm, SRealm: krbRealm}))
	if status != 503 || st["error"] != "directory_unavailable" {
		t.Fatalf("ldap mapping without the directory: %d %v", status, st)
	}
}

func TestKerberosFeatureOff(t *testing.T) {
	l, _ := newKerberosEnv(t, "enrollment", feature.Org, feature.Warnings)
	if status, _, _, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:begin", map[string]any{}, nil); status != 404 {
		t.Fatalf("kerberos with the feature off: %d", status)
	}
}

func TestNegotiateToken(t *testing.T) {
	for h, want := range map[string]string{
		"Negotiate YWJj":   "abc",
		"negotiate  YWJj ": "abc",
		"Negotiate":        "",
		"Negotiate !!":     "",
	} {
		tok, ok := negotiateToken(h)
		if !ok || string(tok) != want {
			t.Errorf("%q = %q, %v", h, tok, ok)
		}
	}
	for _, h := range []string{"Bearer abc", "NegotiateYWJj", "Basic YWJj", ""} {
		if _, ok := negotiateToken(h); ok {
			t.Errorf("%q treated as negotiate", h)
		}
	}
	if tok, ok := negotiateToken("Negotiate " + strings.Repeat("A", maxNegotiateHeader+4)); !ok || tok != nil {
		t.Error("too large token accepted")
	}
}

func FuzzNegotiateToken(f *testing.F) {
	f.Add("Negotiate YWJj")
	f.Add("Bearer x")
	f.Fuzz(func(t *testing.T, h string) {
		tok, ok := negotiateToken(h)
		if !ok {
			return
		}
		if tok != nil && base64.StdEncoding.EncodeToString(tok) != strings.TrimSpace(strings.SplitN(h, " ", 2)[1]) {
			t.Fatalf("token does not round-trip: %q", h)
		}
	})
}

// 規則 ldap：プリンシパルの名前で LDAP の connection を探し、その外部 ID のユーザーでログインする。
func TestKerberosLDAPMapping(t *testing.T) {
	k := kt.New(t, kt.Entry{SPN: kt.SPN, Realm: krbRealm, EType: etypeID.AES256_CTS_HMAC_SHA1_96})
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "sso", "admin", "invitation"}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.LDAP, feature.Kerberos)
		c.Features = &names
		var n map[string]yaml.Node
		src := "kerberos:\n  realms:\n    " + c.Realm.Slug + ":\n      keytab: " + k.Path + "\n      service_principal: " + kt.SPN + "\n" +
			"      mapping: {rule: ldap, ldap: {connection: corp, attribute: uid, value: name}}\n"
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		c.Methods = n
	}, feature.Registered())
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	srv := newDirectory(t)
	addPerson(srv, "alice", "11111111-1111-1111-1111-111111111111", "alice@corp.example", "alice-pw")
	addPerson(srv, "bob", "22222222-2222-2222-2222-222222222222", "bob@corp.example", "bob-pw")
	body := ldapBody(srv)
	body["slug"], body["trust_email"] = "corp", true
	if code, out := l.admin(t, "/v1/admin/connections:ldap", owner, body); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	code, res, _ := l.ldapLogin(t, "corp", "alice", "alice-pw")
	if code != 200 {
		t.Fatalf("ldap login: %d %v", code, res)
	}
	flow := l.kerberosBegin(t)
	status, login, cookie, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"alice"}, CRealm: krbRealm, SRealm: krbRealm}))
	if status != 200 || cookie == "" {
		t.Fatalf("kerberos login: %d %v", status, login)
	}
	// 同じユーザー（LDAP でのログインのセッションが一覧に並ぶ）。
	_, sessions := l.me(t, cookie)
	var amrs []string
	for _, s := range sessions {
		amrs = append(amrs, strings.Join(anyStrings(s["auth_methods"]), "+"))
	}
	if !slices.Contains(amrs, "pwd") || !slices.Contains(amrs, "wia") {
		t.Fatalf("sessions of the kerberos user: %v", amrs)
	}
	// ディレクトリにいても iam に紐付いていない人は入れない（自動の登録はしない）。
	flow = l.kerberosBegin(t)
	if status, _, _, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"bob"}, CRealm: krbRealm, SRealm: krbRealm})); status != 401 {
		t.Fatalf("unlinked: %d", status)
	}
	srv.SetDown(true)
	flow = l.kerberosBegin(t)
	if status, st, _, _ := l.negotiate(t, "", "/v1/login/methods/kerberos:complete", map[string]any{"flow_id": flow},
		k.Token(t, kt.Opts{CName: []string{"alice"}, CRealm: krbRealm, SRealm: krbRealm})); status != 503 || st["error"] != "directory_unavailable" {
		t.Fatalf("directory down: %d %v", status, st)
	}
}
