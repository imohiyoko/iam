package app

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// SAML 2.0 の IdP（フィーチャー saml_idp、ADR 0115）を HTTP で確かめる。

func newSAMLIdPEnv(t *testing.T, on bool) *loginEnv {
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
			names = append(names, feature.SAMLIdP)
		}
		c.Features = &names
	}, feature.Registered())
}

const (
	samlSP    = "https://app.example.com/saml/metadata"
	samlACS   = "https://app.example.com/saml/acs"
	samlSPSLO = "https://app.example.com/saml/slo"
)

// samlTestSP はテスト用の SP の鍵と証明書。
var samlTestSP = func() struct {
	key  *rsa.PrivateKey
	cert []byte
} {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"}, NotBefore: now.Add(-24 * 365 * time.Hour),
		NotAfter: now.Add(24 * 365 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return struct {
		key  *rsa.PrivateKey
		cert []byte
	}{key, der}
}()

func (l *loginEnv) registerSAMLSP(t *testing.T, owner string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"entity_id": samlSP, "name": "App", "acs": []map[string]any{{"url": samlACS}},
		"slo":                  []map[string]any{{"url": samlSPSLO, "binding": samlidp.BindingRedirect}},
		"signing_certificates": []string{base64.StdEncoding.EncodeToString(samlTestSP.cert)},
		"attributes":           []map[string]any{{"source": "email", "name": "urn:oid:0.9.2342.19200300.100.1.3"}}}
	for k, v := range extra {
		body[k] = v
	}
	code, out := l.admin(t, "/v1/admin/saml/service-providers", owner, body)
	if code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
	return out
}

func samlAuthnRequest(id string, now time.Time, extra string) string {
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id +
		`" Version="2.0" IssueInstant="` + now.UTC().Format(time.RFC3339) + `" Destination="` + testIssuer + samlidp.SSOPath + `"` + extra +
		`><saml:Issuer>` + samlSP + `</saml:Issuer></samlp:AuthnRequest>`
}

// samlRedirect は HTTP-Redirect のクエリを作る（sign なら SP の鍵で RSA-SHA256 の署名）。
func samlRedirect(raw, relay string, sign bool) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(raw))
	_ = w.Close()
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if sign {
		q += "&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
		sum := sha256.Sum256([]byte(q))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, samlTestSP.key, crypto.SHA256, sum[:])
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return q
}

var (
	samlFormAction = regexp.MustCompile(`<form id="samlidp" method="post" action="([^"]*)">`)
)

func samlPosted(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	m := samlFormAction.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form: %s", body)
	}
	vals := url.Values{}
	for _, f := range formField.FindAllStringSubmatch(body, -1) {
		vals.Set(f[1], htmlUnescape(f[2]))
	}
	return htmlUnescape(m[1]), vals
}

// samlIdPCert はメタデータから IdP の証明書を読む。
func (l *loginEnv) samlIdPCert(t *testing.T) *x509.Certificate {
	t.Helper()
	w := l.oidcDo(t, "GET", samlidp.MetadataPath, nil, "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/samlmetadata+xml" {
		t.Fatalf("metadata: %d", w.Code)
	}
	md := etree.NewDocument()
	if err := md.ReadFromBytes(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if md.Root().SelectAttrValue("entityID", "") != testIssuer {
		t.Fatalf("metadata: %s", w.Body)
	}
	der, _ := base64.StdEncoding.DecodeString(md.FindElement("//KeyDescriptor//X509Certificate").Text())
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (l *loginEnv) samlVerify(t *testing.T, resp, requestID string) saml.Assertion {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(resp)
	a, err := saml.Verify(raw, saml.Expect{IdPEntityID: testIssuer, Certs: []*x509.Certificate{l.samlIdPCert(t)}, SPEntityID: samlSP, ACSURL: samlACS,
		RequestID: requestID, Now: l.a.deps.Clock.Now()})
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, raw)
	}
	return a
}

func samlStatus(t *testing.T, resp string) string {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(resp)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	sc := doc.FindElement("//Status/StatusCode/StatusCode")
	if sc == nil {
		return doc.FindElement("//Status/StatusCode").SelectAttrValue("Value", "")
	}
	return sc.SelectAttrValue("Value", "")
}

func TestSAMLIdPRedirectSSO(t *testing.T) {
	l := newSAMLIdPEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	sp := l.registerSAMLSP(t, owner, nil)
	if sp["name_id_format"] != samlidp.NameIDPersistent || sp["sign_assertion"] != true || sp["assertion_lifetime"] != float64(300) {
		t.Fatalf("defaults: %v", sp)
	}
	now := l.a.deps.Clock.Now()

	// ログインしていなければ、要求を預けてログイン画面へ。
	u := location(t, l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_r1", now, ""), "deep/link", false), nil, ""))
	back := u.Query().Get("return_to")
	if u.Path != "/login" || !strings.HasPrefix(back, samlidp.ResumePath+"?request=") || safeReturnTo(back) != back {
		t.Fatalf("login redirect: %s", u)
	}
	_, cookie := l.login(t, "alice@example.com")
	w := l.oidcDo(t, "GET", back, nil, cookie)
	if w.Code != 200 {
		t.Fatalf("resume: %d %s", w.Code, w.Body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action https://app.example.com;") {
		t.Fatalf("csp: %s", csp)
	}
	action, vals := samlPosted(t, w.Body.String())
	if action != samlACS || vals.Get("RelayState") != "deep/link" {
		t.Fatalf("form: %s %v", action, vals)
	}
	a := l.samlVerify(t, vals.Get("SAMLResponse"), "_r1")
	if a.NameID != l.userID(t, "alice@example.com") || a.Attributes["urn:oid:0.9.2342.19200300.100.1.3"][0] != "alice@example.com" {
		t.Fatalf("assertion: %+v", a)
	}
	if countType(l.auditTypes(t), "saml_idp.assertion_issued") != 1 {
		t.Fatal("no saml_idp.assertion_issued")
	}
	// 預けた要求は 1 回だけ。
	if w := l.oidcDo(t, "GET", back, nil, cookie); w.Code != 400 {
		t.Fatalf("resume twice: %d", w.Code)
	}
	// セッションがあればそのまま渡す。署名した要求も受ける。
	w = l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_r2", now, ""), "", true), nil, cookie)
	if _, vals := samlPosted(t, w.Body.String()); vals.Has("RelayState") {
		t.Fatalf("second: %v", vals)
	} else {
		l.samlVerify(t, vals.Get("SAMLResponse"), "_r2")
	}
	// 同じ要求の ID は 2 度受けない。
	if w := l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_r2", now, ""), "", true), nil, cookie); w.Code != 400 {
		t.Fatalf("replay: %d", w.Code)
	}
	// ForceAuthn は今のセッションでは足りない（ログイン画面へ）。
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(time.Second)
	now = l.a.deps.Clock.Now()
	u = location(t, l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_r3", now, ` ForceAuthn="true"`), "", false), nil, cookie))
	if u.Path != "/login" {
		t.Fatalf("force authn: %s", u)
	}
	// MFA を求められたら、パスワードだけのセッションは step-up へ。IsPassive なら NoAuthnContext を ACS へ返す。
	mfa := `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		samlidp.ACREFEDSMFA + `</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`
	req := strings.Replace(samlAuthnRequest("_r4", now, ` IsPassive="true"`), "</samlp:AuthnRequest>", mfa+"</samlp:AuthnRequest>", 1)
	w = l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(req, "", false), nil, cookie)
	if _, vals := samlPosted(t, w.Body.String()); samlStatus(t, vals.Get("SAMLResponse")) != samlidp.StatusNoAuthnContext {
		t.Fatalf("passive mfa: %s", w.Body)
	}
	// ログインしていない IsPassive は NoPassive。
	w = l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_r5", now, ` IsPassive="true"`), "", false), nil, "")
	if _, vals := samlPosted(t, w.Body.String()); samlStatus(t, vals.Get("SAMLResponse")) != samlidp.StatusNoPassive {
		t.Fatalf("passive: %s", w.Body)
	}
}

func TestSAMLIdPPostBindingAndRejections(t *testing.T) {
	l := newSAMLIdPEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerSAMLSP(t, owner, nil)
	_, cookie := l.login(t, "alice@example.com")
	now := l.a.deps.Clock.Now()
	// HTTP-POST の要求は Cookie が届かないので、預けて GET の続きへ 303 で回す。
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(samlAuthnRequest("_p1", now, "")))}, "RelayState": {"rs"}}
	w := l.oidcDo(t, "POST", samlidp.SSOPath, form, "", "Origin", "https://app.example.com", "Sec-Fetch-Site", "cross-site")
	if w.Code != 303 {
		t.Fatalf("post: %d %s", w.Code, w.Body)
	}
	next := w.Header().Get("Location")
	if !strings.HasPrefix(next, samlidp.ResumePath+"?request=") {
		t.Fatalf("post redirect: %s", next)
	}
	w = l.oidcDo(t, "GET", next, nil, cookie)
	if _, vals := samlPosted(t, w.Body.String()); vals.Get("RelayState") != "rs" {
		t.Fatalf("post resume: %s", w.Body)
	} else {
		l.samlVerify(t, vals.Get("SAMLResponse"), "_p1")
	}
	// 知らない SP・登録に無い ACS・壊れた署名は SP に戻さず 400。
	bad := []string{
		strings.Replace(samlAuthnRequest("_b1", now, ""), samlSP, "https://evil.example/sp", 1),
		samlAuthnRequest("_b2", now, ` AssertionConsumerServiceURL="https://evil.example/acs"`),
	}
	for i, raw := range bad {
		w := l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(raw, "", false), nil, cookie)
		if w.Code != 400 || strings.Contains(w.Body.String(), "<form") {
			t.Errorf("%d: %d %s", i, w.Code, w.Body)
		}
	}
	q := samlRedirect(samlAuthnRequest("_b3", now, ""), "a", true)
	if w := l.oidcDo(t, "GET", samlidp.SSOPath+"?"+strings.Replace(q, "RelayState=a", "RelayState=b", 1), nil, cookie); w.Code != 400 {
		t.Fatalf("bad signature: %d", w.Code)
	}
	if w := l.oidcDo(t, "GET", samlidp.SSOPath+"?SAMLRequest=%%", nil, cookie); w.Code != 400 {
		t.Fatalf("garbage: %d", w.Code)
	}
	// IdP-initiated は許していない SP には使えない。
	if w := l.oidcDo(t, "GET", samlidp.InitPath+"?sp="+url.QueryEscape(samlSP), nil, cookie); w.Code != 400 {
		t.Fatalf("idp-initiated: %d", w.Code)
	}
}

func TestSAMLIdPInitiated(t *testing.T) {
	l := newSAMLIdPEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerSAMLSP(t, owner, map[string]any{"allow_idp_initiated": true})
	_, cookie := l.login(t, "alice@example.com")
	w := l.oidcDo(t, "GET", samlidp.InitPath+"?"+url.Values{"sp": {samlSP}, "RelayState": {"/home"}}.Encode(), nil, cookie)
	action, vals := samlPosted(t, w.Body.String())
	raw, _ := base64.StdEncoding.DecodeString(vals.Get("SAMLResponse"))
	if action != samlACS || vals.Get("RelayState") != "/home" || strings.Contains(string(raw), "InResponseTo") {
		t.Fatalf("idp-initiated: %s %v %s", action, vals, raw)
	}
}

func samlLogoutRequest(id, nameID string, now time.Time) string {
	return `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id +
		`" Version="2.0" IssueInstant="` + now.UTC().Format(time.RFC3339) + `" Destination="` + testIssuer + samlidp.SLOPath + `"><saml:Issuer>` + samlSP +
		`</saml:Issuer><saml:NameID Format="` + samlidp.NameIDPersistent + `">` + nameID + `</saml:NameID></samlp:LogoutRequest>`
}

func TestSAMLIdPLogout(t *testing.T) {
	l := newSAMLIdPEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerSAMLSP(t, owner, nil)
	_, cookie := l.login(t, "alice@example.com")
	alice := l.userID(t, "alice@example.com")
	alive := func() bool {
		code, _ := l.meDo(t, "GET", cookie, "/v1/me/sessions", nil)
		return code == 200
	}
	now := l.a.deps.Clock.Now()
	// 署名の無い LogoutRequest、別の本人の LogoutRequest ではセッションを終えない。
	if w := l.oidcDo(t, "GET", samlidp.SLOPath+"?"+samlRedirect(samlLogoutRequest("_l1", alice, now), "", false), nil, cookie); w.Code != 400 || !alive() {
		t.Fatalf("unsigned: %d", w.Code)
	}
	u := location(t, l.oidcDo(t, "GET", samlidp.SLOPath+"?"+samlRedirect(samlLogoutRequest("_l2", "usr_other", now), "", true), nil, cookie))
	if u.Host != "app.example.com" || !alive() {
		t.Fatalf("other principal: %s alive=%v", u, alive())
	}
	m, err := samlidp.DecodeRedirect(u.RawQuery, "SAMLResponse")
	if err != nil || !strings.Contains(string(m.XML), samlidp.StatusUnknownPrincipal) {
		t.Fatalf("other principal response: %s %v", m.XML, err)
	}
	// 本人の LogoutRequest でセッションを終え、SP の SLO へ LogoutResponse（Success）を返す。
	u = location(t, l.oidcDo(t, "GET", samlidp.SLOPath+"?"+samlRedirect(samlLogoutRequest("_l3", alice, now), "rs", true), nil, cookie))
	if u.Scheme+"://"+u.Host+u.Path != samlSPSLO || u.Query().Get("RelayState") != "rs" || u.Query().Get("Signature") == "" {
		t.Fatalf("logout redirect: %s", u)
	}
	if m, err := samlidp.DecodeRedirect(u.RawQuery, "SAMLResponse"); err != nil || !strings.Contains(string(m.XML), samlidp.StatusSuccess) ||
		!strings.Contains(string(m.XML), `InResponseTo="_l3"`) {
		t.Fatalf("logout response: %v", err)
	}
	if alive() {
		t.Fatal("session alive after logout")
	}
	if countType(l.auditTypes(t), "saml_idp.logged_out") != 1 {
		t.Fatal("no saml_idp.logged_out")
	}
}

func TestSAMLIdPAdminAPI(t *testing.T) {
	l := newSAMLIdPEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	sp := l.registerSAMLSP(t, owner, nil)
	id := sp["id"].(string)
	if code, out := l.admin(t, "/v1/admin/saml/service-providers", owner, map[string]any{"entity_id": samlSP, "name": "x", "acs": []map[string]any{{"url": samlACS}}}); code != 409 || out["error"] != "entity_id_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	for _, body := range []map[string]any{
		{"entity_id": "urn:a", "name": "x", "acs": []map[string]any{{"url": "http://app.example.com/acs"}}},
		{"entity_id": "urn:a", "name": "x", "acs": []map[string]any{{"url": samlACS}}, "signing_certificates": []string{"bad!"}},
		{"entity_id": "urn:a", "name": "x", "acs": []map[string]any{{"url": samlACS}}, "sign_assertion": false},
		{"entity_id": "urn:a", "name": "x", "acs": []map[string]any{{"url": samlACS}}, "assertion_lifetime": 0},
	} {
		if code, out := l.admin(t, "/v1/admin/saml/service-providers", owner, body); code != 400 || out["error"] != "invalid_service_provider" {
			t.Errorf("%v: %d %v", body, code, out)
		}
	}
	code, out := l.adminDo(t, "PUT", owner, "/v1/admin/saml/service-providers/"+id, map[string]any{"entity_id": "urn:app2", "name": "App2",
		"acs": []map[string]any{{"url": samlACS}}, "sign_response": true, "sign_assertion": false})
	if code != 200 || out["entity_id"] != "urn:app2" || out["sign_assertion"] != false || len(out["slo"].([]any)) != 0 {
		t.Fatalf("update: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/saml/service-providers", nil); code != 200 || len(out["service_providers"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "POST", owner, "/v1/admin/saml/service-providers/"+id+":delete", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/saml/service-providers/"+id, nil); code != 404 {
		t.Fatalf("get deleted: %d", code)
	}
	types := l.auditTypes(t)
	for _, ty := range []string{"saml_idp.service_provider.created", "saml_idp.service_provider.updated", "saml_idp.service_provider.deleted"} {
		if countType(types, ty) != 1 {
			t.Errorf("audit %s missing", ty)
		}
	}
}

func TestSAMLIdPDisabled(t *testing.T) {
	l := newSAMLIdPEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, p := range []string{samlidp.MetadataPath, samlidp.SSOPath + "?SAMLRequest=x", samlidp.SLOPath, samlidp.InitPath + "?sp=x"} {
		if w := l.oidcDo(t, "GET", p, nil, ""); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/saml/service-providers", nil); code != 404 || out["error"] != "saml_idp_disabled" {
		t.Fatalf("admin: %d %v", code, out)
	}
}

// 本人が書ける属性は NameID の出どころにできない（本人が値を変えて SP の別の利用者になりすませる）。
// 登録の後で属性を本人が書けるように変えたら、その NameID の Assertion は出さない。
func TestSAMLIdPEditableNameIDSource(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.SAMLIdP, feature.CustomAttributes)
		c.Features = &names
	}, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, body := range []map[string]any{{"key": "nickname", "type": "string", "user_editable": true}, {"key": "employee_no", "type": "string", "in_token": true}} {
		if code, out := l.adminDo(t, "POST", owner, "/v1/admin/attributes", body); code != 201 {
			t.Fatalf("define %v: %d %v", body["key"], code, out)
		}
	}
	body := map[string]any{"entity_id": samlSP, "name": "App", "acs": []map[string]any{{"url": samlACS}}, "name_id_source": "attribute:nickname",
		"slo":                  []map[string]any{{"url": samlSPSLO, "binding": samlidp.BindingRedirect}},
		"signing_certificates": []string{base64.StdEncoding.EncodeToString(samlTestSP.cert)}}
	if code, out := l.admin(t, "/v1/admin/saml/service-providers", owner, body); code != 400 || out["error"] != "invalid_service_provider" {
		t.Fatalf("editable source: %d %v", code, out)
	}
	body["name_id_source"] = "attribute:employee_no"
	if code, out := l.admin(t, "/v1/admin/saml/service-providers", owner, body); code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	alice := l.userID(t, "alice@example.com")
	if code, out := l.adminDo(t, "PATCH", owner, "/v1/admin/users/"+alice+"/attributes", map[string]any{"attributes": map[string]any{"employee_no": "E-1"}}); code != 200 {
		t.Fatalf("set value: %d %v", code, out)
	}
	now := l.a.deps.Clock.Now()
	w := l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_e1", now, ""), "", false), nil, cookie)
	_, vals := samlPosted(t, w.Body.String())
	if l.samlVerify(t, vals.Get("SAMLResponse"), "_e1").NameID != "E-1" {
		t.Fatalf("attribute name id: %s", w.Body)
	}
	raw, _ := base64.StdEncoding.DecodeString(vals.Get("SAMLResponse"))
	idx := regexp.MustCompile(`SessionIndex="([^"]+)"`).FindStringSubmatch(string(raw))
	if idx == nil {
		t.Fatalf("no session index: %s", raw)
	}
	index := idx[1]
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/attributes/employee_no", map[string]any{"user_editable": true, "in_token": true}); code != 200 {
		t.Fatalf("make editable: %d %v", code, out)
	}
	w = l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_e2", now, ""), "", false), nil, cookie)
	if _, vals := samlPosted(t, w.Body.String()); samlStatus(t, vals.Get("SAMLResponse")) != samlidp.StatusInvalidNameID {
		t.Fatalf("editable after registration: %s", w.Body)
	}
	// 既に渡したセッションは、SessionIndex が合えばログアウトできる（NameID は照合に使わない）。
	alive := func() bool {
		code, _ := l.meDo(t, "GET", cookie, "/v1/me/sessions", nil)
		return code == 200
	}
	withIndex := func(id, nameID, index string) string {
		return strings.Replace(samlLogoutRequest(id, nameID, now), "</samlp:LogoutRequest>",
			`<samlp:SessionIndex>`+index+`</samlp:SessionIndex></samlp:LogoutRequest>`, 1)
	}
	u := location(t, l.oidcDo(t, "GET", samlidp.SLOPath+"?"+samlRedirect(withIndex("_e3", "E-1", "_other"), "", true), nil, cookie))
	if m, err := samlidp.DecodeRedirect(u.RawQuery, "SAMLResponse"); err != nil || !strings.Contains(string(m.XML), samlidp.StatusUnknownPrincipal) || !alive() {
		t.Fatalf("wrong session index: %v alive=%v", err, alive())
	}
	u = location(t, l.oidcDo(t, "GET", samlidp.SLOPath+"?"+samlRedirect(withIndex("_e4", "anything", index), "", true), nil, cookie))
	if m, err := samlidp.DecodeRedirect(u.RawQuery, "SAMLResponse"); err != nil || !strings.Contains(string(m.XML), samlidp.StatusSuccess) || alive() {
		t.Fatalf("logout by session index: %v alive=%v", err, alive())
	}
}
