package app

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/wsfed"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// WS-Federation のパッシブ要求者プロファイル（フィーチャー wsfed、ADR 0110）を HTTP で確かめる。

func newWSFedEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.WSFed)
		}
		c.Features = &names
	}, feature.Registered())
}

const (
	wsfedRealm = "urn:sharepoint:portal"
	wsfedReply = "https://portal.example.com/_trust/"
)

func (l *loginEnv) registerWSFed(t *testing.T, owner string, body map[string]any) map[string]any {
	t.Helper()
	code, out := l.admin(t, "/v1/admin/wsfed/relying-parties", owner, body)
	if code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
	return out
}

var (
	formAction = regexp.MustCompile(`<form id="wsfed" method="post" action="([^"]*)">`)
	formField  = regexp.MustCompile(`<input type="hidden" name="(\w+)" value="([^"]*)">`)
)

// wsfedForm は自動で POST する画面から、送り先と値を読む。
func wsfedPosted(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	m := formAction.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form: %s", body)
	}
	vals := url.Values{}
	for _, f := range formField.FindAllStringSubmatch(body, -1) {
		vals.Set(f[1], htmlUnescape(f[2]))
	}
	return htmlUnescape(m[1]), vals
}

func htmlUnescape(s string) string { return html.UnescapeString(s) }

func signinURL(q url.Values) string {
	if q.Get("wa") == "" {
		q.Set("wa", "wsignin1.0")
	}
	return wsfed.PassivePath + "?" + q.Encode()
}

func TestWSFedSignIn(t *testing.T) {
	l := newWSFedEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	rp := l.registerWSFed(t, owner, map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply, "https://portal.example.com/b"},
		"claims": []map[string]string{
			{"source": "email", "type": wsfed.ClaimEmailAddress},
			{"source": "org_id", "type": "http://schemas.example.com/claims/org"},
		}})
	if rp["token_type"] != "saml11" || rp["token_lifetime"] != float64(3600) {
		t.Fatalf("defaults: %v", rp)
	}

	// ログインしていなければ、要求を預けてログイン画面へ。
	u := location(t, l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {wsfedRealm}, "wctx": {"rm=0&id=abc"}}), nil, ""))
	back := u.Query().Get("return_to")
	if u.Path != "/login" || !strings.HasPrefix(back, wsfed.ResumePath+"?request=") || safeReturnTo(back) != back {
		t.Fatalf("login redirect: %s", u)
	}
	_, cookie := l.login(t, "alice@example.com")
	w := l.oidcDo(t, "GET", back, nil, cookie)
	if w.Code != 200 {
		t.Fatalf("resume: %d %s", w.Code, w.Body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action https://portal.example.com;") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp: %s", csp)
	}
	action, vals := wsfedPosted(t, w.Body.String())
	if action != wsfedReply || vals.Get("wa") != "wsignin1.0" || vals.Get("wctx") != "rm=0&id=abc" {
		t.Fatalf("form: %s %v", action, vals)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(vals.Get("wresult")); err != nil {
		t.Fatal(err)
	}
	a := doc.FindElement("//RequestedSecurityToken/Assertion")
	alice := l.userID(t, "alice@example.com")
	if a == nil || a.SelectAttrValue("Issuer", "") != testIssuer ||
		a.FindElement("./Conditions/AudienceRestrictionCondition/Audience").Text() != wsfedRealm ||
		a.FindElement("./AuthenticationStatement/Subject/NameIdentifier").Text() != alice {
		t.Fatalf("assertion: %s", vals.Get("wresult"))
	}
	attrs := map[string]string{}
	for _, at := range a.FindElements("./AttributeStatement/Attribute") {
		attrs[at.SelectAttrValue("AttributeName", "")] = at.FindElement("./AttributeValue").Text()
	}
	if attrs["emailaddress"] != "alice@example.com" || !strings.HasPrefix(attrs["org"], "org_") {
		t.Fatalf("attributes: %v", attrs)
	}
	// 預けた要求は 1 回だけ。
	if w := l.oidcDo(t, "GET", back, nil, cookie); w.Code != 400 {
		t.Fatalf("resume twice: %d", w.Code)
	}

	// セッションがあれば、そのまま渡す。登録した別の wreply にも返せる。
	w = l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {wsfedRealm}, "wreply": {"https://portal.example.com/b"}}), nil, cookie)
	if action, vals := wsfedPosted(t, w.Body.String()); action != "https://portal.example.com/b" || vals.Has("wctx") {
		t.Fatalf("second sign-in: %s %v", action, vals)
	}
	// wfresh=0 は今からのログインを求める。
	l.advance(time.Second)
	if u := location(t, l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {wsfedRealm}, "wfresh": {"0"}}), nil, cookie)); u.Path != "/login" {
		t.Fatalf("wfresh=0: %s", u)
	}

	// 知らないもの・応えられないものは RP に戻さず 400（fail closed）。
	for name, q := range map[string]url.Values{
		"unknown realm":   {"wtrealm": {"urn:other"}},
		"realm case":      {"wtrealm": {"urn:sharepoint:Portal"}},
		"unknown reply":   {"wtrealm": {wsfedRealm}, "wreply": {"https://evil.example/"}},
		"reply prefix":    {"wtrealm": {wsfedRealm}, "wreply": {wsfedReply + "x"}},
		"reply query":     {"wtrealm": {wsfedRealm}, "wreply": {wsfedReply + "?next=https://evil.example/"}},
		"no realm":        {},
		"wauth":           {"wtrealm": {wsfedRealm}, "wauth": {"urn:oasis:names:tc:SAML:1.0:am:password"}},
		"wreq":            {"wtrealm": {wsfedRealm}, "wreq": {"<x/>"}},
		"duplicate realm": {"wtrealm": {wsfedRealm, "urn:other"}},
		"bad wfresh":      {"wtrealm": {wsfedRealm}, "wfresh": {"x"}},
	} {
		w := l.oidcDo(t, "GET", signinURL(q), nil, cookie)
		if w.Code != 400 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "evil.example") || strings.Contains(w.Body.String(), "wresult") {
			t.Errorf("%s: %d %q %s", name, w.Code, w.Header().Get("Location"), w.Body)
		}
	}
	if w := l.oidcDo(t, "GET", wsfed.PassivePath+"?wa=wsignoutcleanup1.0", nil, cookie); w.Code != 400 {
		t.Fatalf("cleanup: %d", w.Code)
	}
	// HEAD・POST ではトークンを出さない。
	for _, m := range []string{"HEAD", "POST"} {
		if w := l.oidcDo(t, m, signinURL(url.Values{"wtrealm": {wsfedRealm}}), nil, cookie); w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d", m, w.Code)
		}
	}
	issued := 0
	for _, e := range l.auditTypes(t) {
		if e.Type == "wsfed.token_issued" {
			issued++
			if e.Actor.ID != alice || e.Details["realm"] != wsfedRealm || e.Details["relying_party_id"] != rp["id"] {
				t.Fatalf("audit: %+v", e)
			}
		}
	}
	if issued != 2 {
		t.Fatalf("token_issued events: %d", issued)
	}

	// メタデータ（署名付き）。トークンの証明書と同じものを載せる。
	w = l.oidcDo(t, "GET", wsfed.MetadataPath, nil, "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/samlmetadata+xml" {
		t.Fatalf("metadata: %d %v", w.Code, w.Header())
	}
	md := etree.NewDocument()
	if err := md.ReadFromBytes(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if md.Root().SelectAttrValue("entityID", "") != testIssuer ||
		md.FindElement("//PassiveRequestorEndpoint/EndpointReference/Address").Text() != testIssuer+wsfed.PassivePath ||
		md.FindElement("//KeyDescriptor//X509Certificate").Text() != a.FindElement(".//X509Certificate").Text() {
		t.Fatalf("metadata: %s", w.Body)
	}
}

func TestWSFedSignOut(t *testing.T) {
	l := newWSFedEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerWSFed(t, owner, map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply}})
	_, cookie := l.login(t, "alice@example.com")
	alive := func() bool {
		code, _ := l.meDo(t, "GET", cookie, "/v1/me/sessions", nil)
		return code == 200
	}
	// 知らない wtrealm・wreply ではセッションを終えない。
	for _, q := range []url.Values{
		{"wa": {"wsignout1.0"}},
		{"wa": {"wsignout1.0"}, "wtrealm": {"urn:other"}},
		{"wa": {"wsignout1.0"}, "wtrealm": {wsfedRealm}, "wreply": {"https://evil.example/"}},
	} {
		if w := l.oidcDo(t, "GET", wsfed.PassivePath+"?"+q.Encode(), nil, cookie); w.Code != 400 || !alive() {
			t.Fatalf("%v: %d alive=%v", q, w.Code, alive())
		}
	}
	q := url.Values{"wa": {"wsignout1.0"}, "wtrealm": {wsfedRealm}, "wreply": {wsfedReply}}
	if u := location(t, l.oidcDo(t, "GET", wsfed.PassivePath+"?"+q.Encode(), nil, cookie)); u.String() != wsfedReply {
		t.Fatalf("sign-out redirect: %s", u)
	}
	if alive() {
		t.Fatal("session still alive after sign-out")
	}
	if countType(l.auditTypes(t), "wsfed.signed_out") != 1 {
		t.Fatal("no wsfed.signed_out")
	}
	// wreply が無ければ完了の文言。
	q.Del("wreply")
	if w := l.oidcDo(t, "GET", wsfed.PassivePath+"?"+q.Encode(), nil, ""); w.Code != 200 {
		t.Fatalf("sign-out without wreply: %d", w.Code)
	}
}

func TestWSFedAdminAPI(t *testing.T) {
	l := newWSFedEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, auditor := l.operator(t, "audit@example.com", role.RealmSupport)
	body := map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply}}
	if code, _ := l.admin(t, "/v1/admin/wsfed/relying-parties", auditor, body); code != 403 {
		t.Fatalf("auditor create: %d", code)
	}
	rp := l.registerWSFed(t, owner, body)
	id := rp["id"].(string)
	if code, out := l.admin(t, "/v1/admin/wsfed/relying-parties", owner, body); code != 409 || out["error"] != "realm_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	for name, b := range map[string]map[string]any{
		"http reply":   {"realm": "urn:x", "name": "X", "reply_urls": []string{"http://x.example/"}},
		"no reply":     {"realm": "urn:x", "name": "X", "reply_urls": []string{}},
		"bad source":   {"realm": "urn:x", "name": "X", "reply_urls": []string{wsfedReply}, "claims": []map[string]string{{"source": "secret", "type": "urn:a/b"}}},
		"zero life":    {"realm": "urn:x", "name": "X", "reply_urls": []string{wsfedReply}, "token_lifetime": 0},
		"relative uri": {"realm": "portal", "name": "X", "reply_urls": []string{wsfedReply}},
		"token type":   {"realm": "urn:x", "name": "X", "reply_urls": []string{wsfedReply}, "token_type": "jwt"},
	} {
		if code, out := l.admin(t, "/v1/admin/wsfed/relying-parties", owner, b); code != 400 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	code, list := l.adminDo(t, "GET", owner, "/v1/admin/wsfed/relying-parties", nil)
	if code != 200 || len(list["relying_parties"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	code, got := l.adminDo(t, "PUT", owner, "/v1/admin/wsfed/relying-parties/"+id, map[string]any{"realm": "urn:portal2", "name": "Portal 2",
		"reply_urls": []string{wsfedReply}, "token_type": "saml20", "claims": []map[string]string{}, "token_lifetime": 600})
	if code != 200 || got["realm"] != "urn:portal2" || got["token_type"] != "saml20" || len(got["claims"].([]any)) != 0 {
		t.Fatalf("update: %d %v", code, got)
	}
	if code, got := l.adminDo(t, "GET", owner, "/v1/admin/wsfed/relying-parties/"+id, nil); code != 200 || got["token_lifetime"] != float64(600) {
		t.Fatalf("get: %d %v", code, got)
	}
	// SAML 2.0 の RP には SAML 2.0 の Assertion。
	_, cookie := l.login(t, "alice@example.com")
	w := l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {"urn:portal2"}}), nil, cookie)
	if _, vals := wsfedPosted(t, w.Body.String()); !strings.Contains(vals.Get("wresult"), `Version="2.0"`) ||
		!strings.Contains(vals.Get("wresult"), "urn:oasis:names:tc:SAML:2.0:assertion</t:TokenType>") {
		t.Fatalf("saml20: %s", vals.Get("wresult"))
	}
	if code, _ := l.admin(t, "/v1/admin/wsfed/relying-parties/"+id+":delete", owner, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/wsfed/relying-parties/"+id, nil); code != 404 {
		t.Fatalf("get deleted: %d", code)
	}
	if w := l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {"urn:portal2"}}), nil, cookie); w.Code != 400 {
		t.Fatalf("deleted rp: %d", w.Code)
	}
	var types []string
	for _, e := range l.auditTypes(t) {
		if strings.HasPrefix(e.Type, "wsfed.relying_party.") {
			types = append(types, e.Type)
		}
	}
	if strings.Join(types, ",") != "wsfed.relying_party.created,wsfed.relying_party.updated,wsfed.relying_party.deleted" {
		t.Fatalf("audit: %v", types)
	}
}

// 待つ間に RP の登録が変わったら、戻ってもトークンを渡さない。
func TestWSFedResumeRechecksRegistration(t *testing.T) {
	l := newWSFedEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	rp := l.registerWSFed(t, owner, map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply, "https://portal.example.com/b"}})
	back := location(t, l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {wsfedRealm}, "wreply": {"https://portal.example.com/b"}}), nil, "")).Query().Get("return_to")
	code, _ := l.adminDo(t, "PUT", owner, "/v1/admin/wsfed/relying-parties/"+rp["id"].(string), map[string]any{"realm": wsfedRealm, "name": "Portal",
		"reply_urls": []string{wsfedReply}})
	if code != 200 {
		t.Fatalf("update: %d", code)
	}
	_, cookie := l.login(t, "alice@example.com")
	if w := l.oidcDo(t, "GET", back, nil, cookie); w.Code != 400 || strings.Contains(w.Body.String(), "wresult") {
		t.Fatalf("resume after reply removed: %d %s", w.Code, w.Body)
	}
}

func TestWSFedDisabled(t *testing.T) {
	l := newWSFedEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, p := range []string{signinURL(url.Values{"wtrealm": {wsfedRealm}}), wsfed.MetadataPath, wsfed.ResumePath + "?request=x"} {
		if w := l.oidcDo(t, "GET", p, nil, ""); w.Code != 404 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/wsfed/relying-parties", nil); code != 404 || out["error"] != "wsfed_disabled" {
		t.Fatalf("admin: %d %v", code, out)
	}
}

func TestDisableWSFedWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		if err := tx.WSFed().CreateRelyingParty(ctx, port.WSFedRelyingParty{ID: "wrp_1", RealmID: l.a.realm.ID, Realm: wsfedRealm, Name: "P",
			ReplyURLs: []string{wsfedReply}, TokenType: wsfed.TokenSAML11, Claims: []byte("[]"), TokenLifetime: 3600}); err != nil {
			return err
		}
		return tx.WSFed().CreateCertificate(ctx, port.WSFedCertificate{RealmID: l.a.realm.ID, KeyID: "k", DER: []byte{1}})
	})
	if err != nil {
		t.Fatal(err)
	}
	disableWithData(t, l, feature.WSFed, 2)
}
