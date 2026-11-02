package saml

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/saml/samltest"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	testACS = "https://iam.example/login/saml/acs"
	testSP  = "https://iam.example/login/saml/metadata/acme"
	testReq = "_req123"
)

var testNow = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

var testIdP = samltest.New("https://idp.example/entity", "https://idp.example/sso", testNow)

func goodResponse() samltest.Response {
	return samltest.Response{Destination: testACS, Recipient: testACS, InResponseTo: testReq, Audience: testSP,
		NameID: "u-1", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Attributes: map[string]string{"email": "sam@acme.example"}, Now: testNow}
}

func expect() Expect {
	return Expect{IdPEntityID: testIdP.EntityID, Certs: []*x509.Certificate{testIdP.Cert}, SPEntityID: testSP, ACSURL: testACS,
		RequestID: testReq, Now: testNow}
}

func TestVerifyAccepts(t *testing.T) {
	a, err := Verify(testIdP.Sign(goodResponse()), expect())
	if err != nil {
		t.Fatal(err)
	}
	if a.NameID != "u-1" || a.Attributes["email"][0] != "sam@acme.example" || a.ID == "" || !a.Expires.After(testNow) {
		t.Fatalf("assertion = %+v", a)
	}
	// 応答にも署名したもの。
	r := goodResponse()
	r.SignResponse = true
	if _, err := Verify(testIdP.Sign(r), expect()); err != nil {
		t.Fatalf("signed response: %v", err)
	}
	// 時刻のずれの範囲内。
	e := expect()
	e.Now = testNow.Add(5*time.Minute + MaxSkew - time.Second)
	if _, err := Verify(testIdP.Sign(goodResponse()), e); err != nil {
		t.Fatalf("within skew: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	other := samltest.New(testIdP.EntityID, testIdP.SSOURL, testNow)
	cases := map[string]struct {
		mod    func(*samltest.Response)
		expect func(*Expect)
		raw    func(*etree.Element)
	}{
		"unsigned assertion":           {mod: func(r *samltest.Response) { r.UnsignedAssertion = true }},
		"unsigned but response signed": {mod: func(r *samltest.Response) { r.UnsignedAssertion, r.SignResponse = true, true }},
		"another key":                  {mod: func(r *samltest.Response) { r.SignWith = other }},
		"sha1":                         {mod: func(r *samltest.Response) { r.SHA1 = true }},
		"wrong audience":               {mod: func(r *samltest.Response) { r.Audience = "https://other.example/sp" }},
		"wrong recipient":              {mod: func(r *samltest.Response) { r.Recipient = "https://evil.example/acs" }},
		"wrong destination":            {mod: func(r *samltest.Response) { r.Destination = "https://evil.example/acs" }},
		"wrong in response to":         {mod: func(r *samltest.Response) { r.InResponseTo = "_other" }},
		"unsolicited":                  {mod: func(r *samltest.Response) { r.OmitResponseInResponseTo = true }},
		"wrong issuer":                 {mod: func(r *samltest.Response) { r.Issuer = "https://evil.example/entity" }},
		"error status":                 {mod: func(r *samltest.Response) { r.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Requester" }},
		"transient":                    {mod: func(r *samltest.Response) { r.NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" }},
		"expired":                      {expect: func(e *Expect) { e.Now = testNow.Add(5*time.Minute + MaxSkew) }},
		"not yet valid":                {expect: func(e *Expect) { e.Now = testNow.Add(-time.Minute - MaxSkew - time.Second) }},
		"certificate expired":          {expect: func(e *Expect) { e.Now = testNow.Add(400 * 24 * time.Hour) }},
		"tampered nameid": {raw: func(resp *etree.Element) {
			resp.FindElement("./Assertion/Subject/NameID").SetText("admin")
		}},
		// XML Signature Wrapping：署名した Assertion を残したまま、別の Assertion を足す。
		"wrapped assertion": {raw: func(resp *etree.Element) {
			evil := resp.FindElement("./Assertion").Copy()
			evil.RemoveChild(evil.FindElement("./Signature"))
			evil.CreateAttr("ID", "_evil")
			evil.FindElement("./Subject/NameID").SetText("admin")
			resp.InsertChildAt(0, evil)
		}},
		"assertion in extensions": {raw: func(resp *etree.Element) {
			evil := resp.FindElement("./Assertion").Copy()
			evil.CreateAttr("ID", "_evil")
			ext := etree.NewElement("samlp:Extensions")
			ext.AddChild(evil)
			resp.InsertChildAt(1, ext)
		}},
		// 署名した Assertion を Advice の中に隠し、外側を書き換える。
		"assertion moved into advice": {raw: func(resp *etree.Element) {
			signed := resp.FindElement("./Assertion")
			outer := signed.Copy()
			outer.RemoveChild(outer.FindElement("./Signature"))
			outer.CreateAttr("ID", "_outer")
			outer.FindElement("./Subject/NameID").SetText("admin")
			adv := outer.CreateElement("saml:Advice")
			resp.RemoveChild(signed)
			adv.AddChild(signed)
			resp.AddChild(outer)
		}},
		"duplicate id": {raw: func(resp *etree.Element) {
			a := resp.FindElement("./Assertion")
			resp.FindElement("./Status").CreateAttr("ID", a.SelectAttrValue("ID", ""))
		}},
		"encrypted assertion": {raw: func(resp *etree.Element) {
			resp.CreateElement("saml:EncryptedAssertion")
		}},
		"reference to whole document": {raw: func(resp *etree.Element) {
			resp.FindElement("./Assertion/Signature/SignedInfo/Reference").CreateAttr("URI", "")
		}},
		"two signatures": {raw: func(resp *etree.Element) {
			a := resp.FindElement("./Assertion")
			a.FindElement("./Subject").AddChild(a.FindElement("./Signature").Copy())
		}},
		"missing subject confirmation": {raw: func(resp *etree.Element) {
			s := resp.FindElement("./Assertion/Subject")
			s.RemoveChild(s.FindElement("./SubjectConfirmation"))
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := goodResponse()
			if c.mod != nil {
				c.mod(&r)
			}
			e := expect()
			if c.expect != nil {
				c.expect(&e)
			}
			el := testIdP.Element(r)
			if c.raw != nil {
				c.raw(el)
			}
			a, err := Verify(samltest.Bytes(el), e)
			t.Log(err)
			if err == nil {
				t.Fatalf("accepted: %+v", a)
			}
		})
	}
}

// コメントを挟んで NameID の読み方を変える攻撃（署名はコメントを除いた全体にかかる）。コメントのある文書は受けない。
func TestVerifyRejectsComments(t *testing.T) {
	raw := testIdP.Sign(goodResponse())
	evil := bytes.Replace(raw, []byte(">u-1<"), []byte(">u-<!---->1<"), 1)
	if bytes.Equal(raw, evil) {
		t.Fatal("NameID not found")
	}
	if _, err := Verify(evil, expect()); err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatalf("comment: %v", err)
	}
	for _, s := range []string{`<!DOCTYPE x [<!ENTITY e "x">]>`, `<?pi x?>`} {
		doc := bytes.Replace(raw, []byte("<samlp:Response"), []byte(s+"<samlp:Response"), 1)
		if _, err := Verify(doc, expect()); err == nil {
			t.Fatalf("%s accepted", s)
		}
	}
}

func TestVerifyLimits(t *testing.T) {
	if _, err := Verify(bytes.Repeat([]byte("a"), maxResponseBytes+1), expect()); err == nil {
		t.Fatal("large accepted")
	}
	deep := strings.Repeat("<a>", maxDepth+1) + strings.Repeat("</a>", maxDepth+1)
	if _, err := Verify([]byte(deep), expect()); err == nil || !strings.Contains(err.Error(), "deep") {
		t.Fatalf("deep: %v", err)
	}
}

func TestFederatedEmail(t *testing.T) {
	realm := Config{}
	a := Assertion{NameID: "u-1", Attributes: map[string][]string{"mail": {"Sam@acme.example"}}}
	if f := federated(realm, connOf(""), a); f.Email != "Sam@acme.example" || f.EmailVerified {
		t.Fatalf("realm without trust: %+v", f)
	}
	if f := federated(Config{TrustEmail: true}, connOf(""), a); !f.EmailVerified {
		t.Fatalf("trusted realm: %+v", f)
	}
	if f := federated(Config{}, connOf("org"), a); !f.EmailVerified || f.Subject != "u-1" {
		t.Fatalf("org: %+v", f)
	}
	// 設定した属性だけを見る。
	if f := federated(Config{EmailAttribute: "upn"}, connOf("org"), a); f.Email != "" || f.EmailVerified {
		t.Fatalf("configured attribute: %+v", f)
	}
	// 値が複数ある属性は使わない。
	multi := Assertion{NameID: "u-1", Attributes: map[string][]string{"email": {"a@x", "b@x"}}}
	if f := federated(Config{}, connOf("org"), multi); f.Email != "" {
		t.Fatalf("multi: %+v", f)
	}
	// 大文字と小文字だけが違う同じ名前の属性が複数あれば使わない。
	dup := Assertion{NameID: "u-1", Attributes: map[string][]string{"email": {"a@x"}, "Email": {"b@x"}}}
	if f := federated(Config{}, connOf("org"), dup); f.Email != "" {
		t.Fatalf("duplicate names: %+v", f)
	}
	// emailAddress 形式の NameID。
	byName := Assertion{NameID: "sam@acme.example", NameIDFormat: nameIDEmail}
	if f := federated(Config{}, connOf("org"), byName); f.Email != "sam@acme.example" {
		t.Fatalf("name id: %+v", f)
	}
}

func connOf(owner string) port.Connection {
	return port.Connection{ID: "con_1", Type: Type, OwnerOrgID: owner}
}
