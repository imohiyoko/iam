package app

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/saml/samltest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// newSAMLEnv は saml と Org 専用 SSO のフィーチャーを動かす（ADR 0098）。
func newSAMLEnv(t *testing.T, extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "sso", "admin", "invitation"}
		c.Server.PublicURL = "https://iam.example"
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
	}, feature.Registered())
}

// samlFlow は始めたフロー（IdP に渡した AuthnRequest の ID と RelayState）。
type samlFlow struct {
	flowID, requestID, relay string
}

// samlStart は path（:start）でフローを始め、AuthnRequest を読む。
func (l *loginEnv) samlStart(t *testing.T, path, cookie string) samlFlow {
	t.Helper()
	var hdr []string
	if cookie != "" {
		hdr = []string{"Cookie", sessionCookie + "=" + cookie}
	}
	w := l.do(t, l.a.PublicHandler(), "POST", path, map[string]string{}, hdr...)
	if w.Code != 200 {
		t.Fatalf("saml start %s: %d %s", path, w.Code, w.Body)
	}
	var st struct {
		FlowID string `json:"flow_id"`
		URL    string `json:"redirect_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	u, _ := url.Parse(st.URL)
	deflated, _ := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return samlFlow{flowID: st.FlowID, requestID: doc.Root().SelectAttrValue("ID", ""), relay: u.Query().Get("RelayState")}
}

// samlACS は IdP からの POST（別サイト）を ACS に送り、画面に渡った値を返す。
func (l *loginEnv) samlACS(t *testing.T, response, relay string) (string, string) {
	t.Helper()
	form := url.Values{"SAMLResponse": {response}, "RelayState": {relay}}
	r := httptest.NewRequest("POST", "/login/saml/acs", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://idp.acme.example")
	w := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("acs: %d %s", w.Code, w.Body)
	}
	attr := func(name string) string {
		m := regexp.MustCompile(` ` + name + `="([^"]*)"`).FindStringSubmatch(w.Body.String())
		if m == nil {
			return ""
		}
		return html.UnescapeString(m[1])
	}
	if attr("data-page") != "saml_callback" {
		t.Fatalf("acs page: %s", w.Body)
	}
	return attr("data-saml-response"), attr("data-relay-state")
}

// samlLogin は connection でのログインを通す（IdP が sub と email を返す）。
func (l *loginEnv) samlLogin(t *testing.T, idp *samltest.IdP, conn, spEntityID, sub, email string) *httptest.ResponseRecorder {
	t.Helper()
	f := l.samlStart(t, "/v1/login/saml/"+conn+":start", "")
	resp, relay := l.samlACS(t, idp.Encoded(l.samlResponse(f, spEntityID, sub, email)), f.relay)
	return l.do(t, l.a.PublicHandler(), "POST", "/v1/login/saml:complete", map[string]string{"saml_response": resp, "relay_state": relay},
		"Cookie", samlCookie+"="+f.flowID)
}

func (l *loginEnv) samlResponse(f samlFlow, spEntityID, sub, email string) samltest.Response {
	acs := "https://iam.example/login/saml/acs"
	return samltest.Response{Destination: acs, Recipient: acs, InResponseTo: f.requestID, Audience: spEntityID, NameID: sub,
		NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", Attributes: map[string]string{"email": email},
		Now: l.a.deps.Clock.Now()}
}

func TestSAMLDisabled(t *testing.T) {
	l := newSAMLEnv(t, feature.OrgManagedUsers)
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	if code, out := l.admin(t, "/v1/admin/connections:saml", owner, map[string]any{"slug": "corp"}); code != 404 || out["error"] != "saml_disabled" {
		t.Fatalf("admin create: %d %v", code, out)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/saml/corp:start", map[string]string{}); w.Code != 404 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/login/saml/metadata/corp", nil); w.Code != 404 {
		t.Fatalf("metadata: %d", w.Code)
	}
	r := httptest.NewRequest("POST", "/login/saml/acs", strings.NewReader("SAMLResponse=x&RelayState=y"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("acs: %d", w.Code)
	}
}

func TestSAMLOrgSSO(t *testing.T) {
	l := newSAMLEnv(t, feature.OrgManagedUsers, feature.OrgLoginPolicy, feature.SAML)
	dns := &fakeDNS{txt: map[string][]string{}}
	l.a.orgs.Resolver = dns
	idp := samltest.New("https://idp.acme.example/entity", "https://idp.acme.example/sso", l.a.deps.Clock.Now())

	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	base := "/v1/me/orgs/" + acme + "/connections"

	// メタデータの誤りは 400。
	if code, out := l.mePost(t, owner, base+":saml", map[string]any{"metadata_xml": "<x/>"}); code != 400 || out["error"] != "invalid_connection" {
		t.Fatalf("bad metadata: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, base+":saml", map[string]any{}); code != 400 {
		t.Fatalf("no metadata: %d %v", code, out)
	}
	code, out := l.mePost(t, owner, base+":saml", map[string]any{"metadata_xml": string(idp.Metadata()), "sign_requests": true})
	if code != 201 || out["type"] != "saml" {
		t.Fatalf("add saml connection: %d %v", code, out)
	}
	conn := out["id"].(string)
	info := out["saml"].(map[string]any)
	sp := info["sp_entity_id"].(string)
	if info["acs_url"] != "https://iam.example/login/saml/acs" || sp != "https://iam.example/login/saml/metadata/"+conn ||
		info["idp_entity_id"] != idp.EntityID || info["idp_certificate_expires_at"] == nil {
		t.Fatalf("saml info: %v", info)
	}
	if code, out := l.meDo(t, "GET", owner, base, nil); code != 200 || out["connections"].([]any)[0].(map[string]any)["type"] != "saml" {
		t.Fatalf("list: %d %v", code, out)
	}
	// 個人 Org には置けない（メタデータを取りに行く前に断る）。
	personal := ""
	if code, out := l.meDo(t, "GET", owner, "/v1/me/orgs", nil); code == 200 {
		for _, o := range out["orgs"].([]any) {
			if m := o.(map[string]any); m["kind"] == "personal" {
				personal = m["id"].(string)
			}
		}
	}
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+personal+"/connections:saml", map[string]any{"metadata_url": "https://idp.invalid/md"}); code != 409 ||
		out["error"] != "personal_org" {
		t.Fatalf("personal org: %d %v", code, out)
	}

	// SP のメタデータ。
	w := l.do(t, l.a.PublicHandler(), "GET", "/login/saml/metadata/"+conn, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `entityID="`+sp+`"`) || !strings.Contains(w.Body.String(), `AuthnRequestsSigned="true"`) {
		t.Fatalf("sp metadata: %d %s", w.Code, w.Body)
	}

	// ドメインから見つかる（種類つき）。
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/login/sso:discover", map[string]string{"email": "x@acme.example"})
	var disc struct {
		Entries []struct{ Connection, Type string } `json:"entries"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	if len(disc.Entries) != 1 || disc.Entries[0].Connection != conn || disc.Entries[0].Type != "saml" {
		t.Fatalf("discover: %s", w.Body)
	}

	// 証明済みドメインの人は登録すると管理ユーザーになり、その Org に入る。
	w = l.samlLogin(t, idp, conn, sp, "u-1", "sam@acme.example")
	if w.Code != 200 {
		t.Fatalf("saml signup: %d %s", w.Code, w.Body)
	}
	sam := sessionOf(w)
	if e := l.myOrgEntry(t, sam, acme); e["managed"] != true || e["active"] != true {
		t.Fatalf("not managed or not in the org: %v", e)
	}
	if w := l.samlLogin(t, idp, conn, sp, "u-1", "sam@acme.example"); w.Code != 200 {
		t.Fatalf("saml login: %d %s", w.Code, w.Body)
	}
	// 証明していないドメイン、個人ユーザーのアドレス。
	if w := l.samlLogin(t, idp, conn, sp, "u-2", "eve@other.example"); w.Code != 400 || !strings.Contains(w.Body.String(), "email_domain_not_verified") {
		t.Fatalf("outside domain: %d %s", w.Code, w.Body)
	}
	if w := l.samlLogin(t, idp, conn, sp, "u-3", "boss@acme.example"); w.Code != 409 {
		t.Fatalf("personal user's email: %d %s", w.Code, w.Body)
	}
	if code, out := l.mePost(t, owner, "/v1/me/identities/saml/"+conn+":start", map[string]string{}); code != 409 || out["error"] != "not_managed_by_org" {
		t.Fatalf("personal user links: %d %v", code, out)
	}

	// 1 回限り：同じ応答の再送、別のフローの Cookie、別の IdP の鍵、別の SP 宛ては受けない。
	f := l.samlStart(t, "/v1/login/saml/"+conn+":start", "")
	enc := idp.Encoded(l.samlResponse(f, sp, "u-1", "sam@acme.example"))
	complete := func(resp, relay, flowID string) int {
		return l.do(t, l.a.PublicHandler(), "POST", "/v1/login/saml:complete", map[string]string{"saml_response": resp, "relay_state": relay},
			"Cookie", samlCookie+"="+flowID).Code
	}
	other := l.samlStart(t, "/v1/login/saml/"+conn+":start", "")
	if c := complete(enc, f.relay, other.flowID); c != 401 {
		t.Fatalf("another flow's cookie: %d", c)
	}
	f = l.samlStart(t, "/v1/login/saml/"+conn+":start", "")
	enc = idp.Encoded(l.samlResponse(f, sp, "u-1", "sam@acme.example"))
	if c := complete(enc, f.relay, f.flowID); c != 200 {
		t.Fatalf("login: %d", c)
	}
	if c := complete(enc, f.relay, f.flowID); c != 401 {
		t.Fatalf("replay: %d", c)
	}
	f = l.samlStart(t, "/v1/login/saml/"+conn+":start", "")
	evil := samltest.New(idp.EntityID, idp.SSOURL, l.a.deps.Clock.Now())
	if c := complete(evil.Encoded(l.samlResponse(f, sp, "u-1", "sam@acme.example")), f.relay, f.flowID); c != 401 {
		t.Fatalf("another key: %d", c)
	}
	f = l.samlStart(t, "/v1/login/saml/"+conn+":start", "")
	if c := complete(idp.Encoded(l.samlResponse(f, "https://other.example/sp", "u-1", "sam@acme.example")), f.relay, f.flowID); c != 401 {
		t.Fatalf("another audience: %d", c)
	}
	// 連携のフローの応答はログインに使えない。
	f = l.samlStart(t, "/v1/me/identities/saml/"+conn+":start", sam)
	if !strings.HasPrefix(f.relay, "link.") {
		t.Fatalf("link relay = %s", f.relay)
	}
	if c := complete(idp.Encoded(l.samlResponse(f, sp, "u-1", "sam@acme.example")), f.relay, f.flowID); c != 401 {
		t.Fatalf("link flow used for login: %d", c)
	}
	// 管理ユーザーは連携できる（同じ外部 ID は 409）。
	f = l.samlStart(t, "/v1/me/identities/saml/"+conn+":start", sam)
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/me/identities/saml:complete",
		map[string]string{"saml_response": idp.Encoded(l.samlResponse(f, sp, "u-1", "sam@acme.example")), "relay_state": f.relay},
		"Cookie", sessionCookie+"="+sam+"; "+samlCookie+"="+f.flowID)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "identity_exists") {
		t.Fatalf("link existing: %d %s", w.Code, w.Body)
	}
	f = l.samlStart(t, "/v1/me/identities/saml/"+conn+":start", sam)
	w = l.do(t, l.a.PublicHandler(), "POST", "/v1/me/identities/saml:complete",
		map[string]string{"saml_response": idp.Encoded(l.samlResponse(f, sp, "u-9", "sam@acme.example")), "relay_state": f.relay},
		"Cookie", sessionCookie+"="+sam+"; "+samlCookie+"="+f.flowID)
	if w.Code != 200 || !strings.Contains(w.Body.String(), conn) {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}

	// require_sso：SAML の connection で認証したセッションも Org の connection によるものとして入れる。
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"require_sso": true}}); code != 200 {
		t.Fatalf("require_sso: %d %v", code, out)
	}
	if w := l.samlLogin(t, idp, conn, sp, "u-1", "sam@acme.example"); w.Code != 200 {
		t.Fatalf("login with require_sso: %d %s", w.Code, w.Body)
	}

	// connection を消すと、その connection ではログインできない。
	if code, out := l.mePost(t, owner, base+"/"+conn+":delete", nil); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/saml/"+conn+":start", map[string]string{}); w.Code != 404 {
		t.Fatalf("start deleted: %d %s", w.Code, w.Body)
	}
}

func TestSAMLRealmConnection(t *testing.T) {
	l := newSAMLEnv(t, feature.SAML)
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	idp := samltest.New("https://idp.corp.example/entity", "https://idp.corp.example/sso", l.a.deps.Clock.Now())
	body := map[string]any{"slug": "corp", "metadata_xml": string(idp.Metadata()), "trust_email": true}
	code, out := l.admin(t, "/v1/admin/connections:saml", owner, body)
	if code != 201 || out["sp_entity_id"] != "https://iam.example/login/saml/metadata/corp" || out["acs_url"] != "https://iam.example/login/saml/acs" {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/connections:saml", owner, body); code != 409 {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	body["slug"], body["metadata_url"] = "corp2", "https://idp.corp.example/md"
	if code, out := l.admin(t, "/v1/admin/connections:saml", owner, body); code != 400 || out["error"] != "invalid_connection" {
		t.Fatalf("both metadata: %d %v", code, out)
	}
	delete(body, "metadata_url")
	body["trust_email"] = false
	if code, out := l.admin(t, "/v1/admin/connections:saml", owner, body); code != 201 {
		t.Fatalf("create untrusted: %d %v", code, out)
	}
	// ホスト型の画面に種類つきで出る。
	w := l.do(t, l.a.PublicHandler(), "GET", "/login", nil)
	if !strings.Contains(w.Body.String(), `data-connection="corp" data-type="saml"`) {
		t.Fatalf("hosted login: %s", w.Body)
	}
	sp := "https://iam.example/login/saml/metadata/corp"
	w = l.samlLogin(t, idp, "corp", sp, "emp-1", "emp@corp.example")
	if w.Code != 200 {
		t.Fatalf("signup: %d %s", w.Code, w.Body)
	}
	// trust_email でなければ登録には使えない。
	if w := l.samlLogin(t, idp, "corp2", "https://iam.example/login/saml/metadata/corp2", "emp-2", "two@corp.example"); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "email_unverified") {
		t.Fatalf("untrusted signup: %d %s", w.Code, w.Body)
	}
	linked := false
	for _, e := range l.auditTypes(t) {
		if e.Type == "login.succeeded" && e.Details["method"] == "saml" {
			linked = true
		}
	}
	if !linked {
		t.Fatal("no saml login in the audit log")
	}

	// フィーチャーを無効にすると、connection を消して外部 ID を無効化する。
	res, err := l.a.DisableFeature(context.Background(), feature.SAML, true)
	if err != nil || !res.Done || res.Purged != 2 {
		t.Fatalf("disable: %+v %v", res, err)
	}
	err = l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Connections().List(ctx, l.a.realm.ID)
		if len(cs) != 0 {
			t.Errorf("connections left: %v", cs)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ACS は IdP からの別サイトの POST を受ける（CrossOriginProtection の外）。ほかの画面への別サイトの POST は断る。
func TestSAMLACSCrossSite(t *testing.T) {
	l := newSAMLEnv(t, feature.SAML)
	r := httptest.NewRequest("POST", "/login/email", strings.NewReader("x=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site post to another page: %d", w.Code)
	}
	resp, relay := l.samlACS(t, "PHg+PC94Pg==", "abc")
	if resp != "PHg+PC94Pg==" || relay != "abc" {
		t.Fatalf("acs values: %q %q", resp, relay)
	}
	// GET は受けない。
	if w := l.do(t, l.a.PublicHandler(), "GET", "/login/saml/acs", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("acs get: %d", w.Code)
	}
}
