package samlidp_test

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- テストで rsa-oaep-mgf1p を復号する
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

func TestValidate(t *testing.T) {
	now := testkit.T0
	in, err := samlidp.Validate(validInput(), now)
	if err != nil {
		t.Fatal(err)
	}
	c := in.Config
	if c.NameIDFormat != samlidp.NameIDPersistent || c.NameIDSource != samlidp.SourceUserID || c.AssertionLifetime != samlidp.DefaultAssertionLifetime ||
		c.ACS[0].Binding != samlidp.BindingPOST || c.Attributes[0].NameFormat != samlidp.AttrNameFormatURI {
		t.Fatalf("defaults = %+v", c)
	}
	email := validInput()
	email.Config.NameIDFormat = samlidp.NameIDEmail
	if in, err := samlidp.Validate(email, now); err != nil || in.Config.NameIDSource != samlidp.SourceEmail {
		t.Fatalf("email default source = %+v, %v", in.Config, err)
	}
	transient := validInput()
	transient.Config.NameIDFormat, transient.Config.NameIDSource = samlidp.NameIDTransient, "user_id"
	if in, err := samlidp.Validate(transient, now); err != nil || in.Config.NameIDSource != "" {
		t.Fatalf("transient = %+v, %v", in.Config, err)
	}
	expired := newTestSP(now.Add(-2 * 365 * 24 * time.Hour))
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecCert := selfSigned(t, ecKey, &ecKey.PublicKey, now)
	smallKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallCert := selfSigned(t, smallKey, &smallKey.PublicKey, now)
	bad := map[string]func(*samlidp.Input){
		"no entity id":         func(i *samlidp.Input) { i.EntityID = "" },
		"relative entity id":   func(i *samlidp.Input) { i.EntityID = "sp" },
		"entity id with space": func(i *samlidp.Input) { i.EntityID = "urn:a b" },
		"no name":              func(i *samlidp.Input) { i.Name = "" },
		"no acs":               func(i *samlidp.Input) { i.Config.ACS = nil },
		"http acs":             func(i *samlidp.Input) { i.Config.ACS = []samlidp.Endpoint{{URL: "http://sp.example.com/acs"}} },
		"fragment acs":         func(i *samlidp.Input) { i.Config.ACS = []samlidp.Endpoint{{URL: "https://sp.example.com/acs#"}} },
		"userinfo acs":         func(i *samlidp.Input) { i.Config.ACS = []samlidp.Endpoint{{URL: "https://u@sp.example.com/acs"}} },
		"artifact acs":         func(i *samlidp.Input) { i.Config.ACS[0].Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" },
		"redirect acs":         func(i *samlidp.Input) { i.Config.ACS[0].Binding = samlidp.BindingRedirect },
		"duplicate acs index":  func(i *samlidp.Input) { i.Config.ACS[1].Index = 0 },
		"duplicate acs url":    func(i *samlidp.Input) { i.Config.ACS[1].URL = spACS },
		"two default acs":      func(i *samlidp.Input) { i.Config.ACS[0].Default = true },
		"negative acs index":   func(i *samlidp.Input) { i.Config.ACS[0].Index = -1 },
		"slo without binding":  func(i *samlidp.Input) { i.Config.SLO[0].Binding = "" },
		"slo without certs":    func(i *samlidp.Input) { i.Config.SigningCerts = nil },
		"bad signing cert":     func(i *samlidp.Input) { i.Config.SigningCerts = [][]byte{{1, 2, 3}} },
		"expired signing cert": func(i *samlidp.Input) { i.Config.SigningCerts = [][]byte{expired.Cert} },
		"small rsa":            func(i *samlidp.Input) { i.Config.SigningCerts = [][]byte{smallCert} },
		"ec encryption cert":   func(i *samlidp.Input) { i.Config.EncryptionCert = ecCert },
		"require signed no key": func(i *samlidp.Input) {
			i.Config.SLO, i.Config.SigningCerts, i.Config.RequireSignedRequests = nil, nil, true
		},
		"name id format":   func(i *samlidp.Input) { i.Config.NameIDFormat = "urn:x" },
		"name id from amr": func(i *samlidp.Input) { i.Config.NameIDSource = "amr" },
		"email with user id": func(i *samlidp.Input) {
			i.Config.NameIDFormat, i.Config.NameIDSource = samlidp.NameIDEmail, "user_id"
		},
		"unknown source":        func(i *samlidp.Input) { i.Config.Attributes[0].Source = "password" },
		"bad attribute key":     func(i *samlidp.Input) { i.Config.Attributes[0].Source = "attribute:Bad" },
		"relative uri name":     func(i *samlidp.Input) { i.Config.Attributes[0].Name = "uid" },
		"name format":           func(i *samlidp.Input) { i.Config.Attributes[0].NameFormat = "urn:x" },
		"duplicate attribute":   func(i *samlidp.Input) { i.Config.Attributes[1].Name = i.Config.Attributes[0].Name },
		"no signature":          func(i *samlidp.Input) { i.Config.SignAssertion = false },
		"short lifetime":        func(i *samlidp.Input) { i.Config.AssertionLifetime = 30 },
		"long lifetime":         func(i *samlidp.Input) { i.Config.AssertionLifetime = 3601 },
		"negative lifetime":     func(i *samlidp.Input) { i.Config.AssertionLifetime = -1 },
		"too many signing cert": func(i *samlidp.Input) { i.Config.SigningCerts = [][]byte{sp1.Cert, sp1.Cert, sp1.Cert, sp1.Cert} },
	}
	for name, mut := range bad {
		in := validInput()
		mut(&in)
		if _, err := samlidp.Validate(in, now); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	ok := validInput()
	ok.Config.SigningCerts = [][]byte{ecCert}
	ok.Config.EncryptionCert = sp2.Cert
	if _, err := samlidp.Validate(ok, now); err != nil {
		t.Fatalf("ecdsa signing cert: %v", err)
	}
}

func selfSigned(t *testing.T, key crypto.Signer, pub any, now time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "x"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseCertificate(t *testing.T) {
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sp1.Cert}))
	for _, s := range []string{p, base64.StdEncoding.EncodeToString(sp1.Cert), "  " + base64.StdEncoding.EncodeToString(sp1.Cert)[:40] + "\n" + base64.StdEncoding.EncodeToString(sp1.Cert)[40:]} {
		der, err := samlidp.ParseCertificate(s)
		if err != nil || string(der) != string(sp1.Cert) {
			t.Fatalf("parse %q: %v", s[:20], err)
		}
	}
	for _, s := range []string{"", "!!", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})), p + p} {
		if _, err := samlidp.ParseCertificate(s); !errors.Is(err, errs.Invalid) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestServiceProviderLifecycle(t *testing.T) {
	s, k := newService(t)
	sp := create(t, s, k, validInput())
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if _, err := s.Create(ctx, tx, k.RealmID, validInput(), audit.Actor{}, ""); !errors.Is(err, samlidp.ErrEntityIDExists) {
			t.Fatalf("duplicate = %v", err)
		}
		up := validInput()
		up.EntityID = "urn:sp2"
		var err error
		sp, err = s.Update(ctx, tx, sp, up, audit.Actor{Type: "operator", ID: "op"}, "req")
		if err != nil || sp.EntityID != "urn:sp2" {
			t.Fatalf("update = %+v, %v", sp, err)
		}
		return s.Delete(ctx, tx, sp, audit.Actor{Type: "operator", ID: "op"}, "req")
	})
	if got := auditTypes(t, k); strings.Join(got, ",") != "saml_idp.service_provider.created,saml_idp.service_provider.updated,saml_idp.service_provider.deleted" {
		t.Fatalf("audit = %v", got)
	}
}

func auditEvents(t *testing.T, k *testkit.Kit) []audit.Event {
	t.Helper()
	var out []audit.Event
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().ListByRealm(ctx, k.RealmID, 0, 100)
		for _, r := range rs {
			e, err := audit.Unmarshal(r.Payload)
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return err
	})
	return out
}

func auditTypes(t *testing.T, k *testkit.Kit) []string {
	var out []string
	for _, e := range auditEvents(t, k) {
		out = append(out, e.Type)
	}
	return out
}

func TestParseAuthnRequest(t *testing.T) {
	s, k := newService(t)
	sp := create(t, s, k, validInput())
	ctx := context.Background()
	now := k.Clock.Now()
	parse := func(m samlidp.Message) (samlidp.AuthnRequest, error) {
		_, _, req, err := s.ParseAuthnRequest(ctx, k.RealmID, m)
		return req, err
	}

	// 署名の無い HTTP-Redirect。ACS を指さなければ既定のもの。
	r := goodReq(now)
	req, err := parse(redirectMessage(t, redirectQuery(t, r.xml(), "state", nil, "")))
	if err != nil || req.ID != "_req1" || req.ACS != spACS2 || req.Status != nil {
		t.Fatalf("unsigned redirect = %+v, %v", req, err)
	}
	// 同じ ID は 2 度受けない。
	if _, err := parse(redirectMessage(t, redirectQuery(t, r.xml(), "", nil, ""))); !errors.Is(err, samlidp.ErrReplayed) {
		t.Fatalf("replay = %v", err)
	}
	// URL・番号で ACS を指す。
	r.ID, r.ACSURL, r.ProtocolBinding = "_req2", spACS, samlidp.BindingPOST
	if req, err := parse(postMessage(t, r.xml(), "")); err != nil || req.ACS != spACS {
		t.Fatalf("acs url = %+v, %v", req, err)
	}
	r = goodReq(now)
	r.ID, r.ACSIndex = "_req3", "3"
	if req, err := parse(postMessage(t, r.xml(), "")); err != nil || req.ACS != spACS2 {
		t.Fatalf("acs index = %+v, %v", req, err)
	}
	// ForceAuthn・IsPassive・NameIDPolicy・RequestedAuthnContext。
	r = goodReq(now)
	r.ID, r.ForceAuthn, r.IsPassive, r.NameIDFormat = "_req4", true, true, samlidp.NameIDPersistent
	r.ClassRefs, r.Comparison = []string{samlidp.ACREFEDSMFA, "urn:x"}, "minimum"
	if req, err := parse(postMessage(t, r.xml(), "")); err != nil || !req.ForceAuthn || !req.IsPassive || req.NameIDFormat != samlidp.NameIDPersistent ||
		!slices.Equal(req.ClassRefs, []string{samlidp.ACREFEDSMFA, "urn:x"}) || req.Status != nil {
		t.Fatalf("options = %+v, %v", req, err)
	}

	// SP に戻さない誤り（400）。
	n := 10
	reject := map[string]struct {
		mod  func(*authnReq)
		want error
	}{
		"unknown sp":        {func(r *authnReq) { r.Issuer = "https://evil.example/sp" }, samlidp.ErrUnknownSP},
		"no issuer":         {func(r *authnReq) { r.Issuer = "" }, samlidp.ErrUnknownSP},
		"unknown acs url":   {func(r *authnReq) { r.ACSURL = "https://evil.example/acs" }, samlidp.ErrUnknownACS},
		"acs url prefix":    {func(r *authnReq) { r.ACSURL = spACS + "/x" }, samlidp.ErrUnknownACS},
		"unknown acs index": {func(r *authnReq) { r.ACSIndex = "7" }, samlidp.ErrUnknownACS},
		"url and index":     {func(r *authnReq) { r.ACSURL, r.ACSIndex = spACS, "0" }, samlidp.ErrUnknownACS},
		"artifact binding":  {func(r *authnReq) { r.ProtocolBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" }, samlidp.ErrUnknownACS},
		"wrong destination": {func(r *authnReq) { r.Destination = "https://evil.example/sso" }, errs.Invalid},
		"old request":       {func(r *authnReq) { r.IssueInstant = now.Add(-14 * time.Minute) }, errs.Invalid},
		"future request":    {func(r *authnReq) { r.IssueInstant = now.Add(4 * time.Minute) }, errs.Invalid},
		"bad id":            {func(r *authnReq) { r.ID = "1abc" }, errs.Invalid},
		"comment":           {func(r *authnReq) { r.Extra = "<!-- x -->" }, errs.Invalid},
		"nested assertion": {func(r *authnReq) {
			r.Extra = `<samlp:Extensions><saml:Assertion ID="_a" Version="2.0"/></samlp:Extensions>`
		}, errs.Invalid},
	}
	for name, c := range reject {
		r := goodReq(now)
		n++
		r.ID = "_r" + string(rune('a'+n))
		c.mod(&r)
		if _, err := parse(postMessage(t, r.xml(), "")); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	doctype := `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "y">]>` + goodReq(now).xml()
	if _, err := parse(postMessage(t, doctype, "")); !errors.Is(err, errs.Invalid) {
		t.Fatalf("doctype = %v", err)
	}

	// SP と ACS を確かめた後の、応えられない要求は Status で返す。
	status := map[string]struct {
		mod  func(*authnReq)
		want string
	}{
		"name id format":    {func(r *authnReq) { r.NameIDFormat = samlidp.NameIDEmail }, samlidp.StatusInvalidNameID},
		"unknown class ref": {func(r *authnReq) { r.ClassRefs = []string{"urn:x"} }, samlidp.StatusNoAuthnContext},
		"better":            {func(r *authnReq) { r.ClassRefs, r.Comparison = []string{samlidp.ACREFEDSMFA}, "better" }, samlidp.StatusNoAuthnContext},
		"subject": {func(r *authnReq) {
			r.Extra = `<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>`
		}, samlidp.StatusRequestUnsupport},
	}
	for name, c := range status {
		r := goodReq(now)
		n++
		r.ID = "_s" + string(rune('a'+n))
		c.mod(&r)
		req, err := parse(postMessage(t, r.xml(), ""))
		if err != nil || req.Status == nil || req.Status.Sub != c.want {
			t.Errorf("%s: %+v, %v", name, req.Status, err)
		}
	}
	_ = sp
}

func TestAuthnRequestSignatures(t *testing.T) {
	s, k := newService(t)
	in := validInput()
	in.Config.RequireSignedRequests = true
	create(t, s, k, in)
	ctx := context.Background()
	now := k.Clock.Now()
	parse := func(m samlidp.Message) error {
		_, _, _, err := s.ParseAuthnRequest(ctx, k.RealmID, m)
		return err
	}
	id := 0
	next := func() authnReq {
		id++
		r := goodReq(now)
		r.ID = "_sig" + strings.Repeat("x", id)
		return r
	}

	// HTTP-Redirect の署名。
	if err := parse(redirectMessage(t, redirectQuery(t, next().xml(), "rs", &sp1, rsaSHA256))); err != nil {
		t.Fatalf("signed redirect: %v", err)
	}
	if err := parse(redirectMessage(t, redirectQuery(t, next().xml(), "rs", &sp2, rsaSHA256))); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("another key = %v", err)
	}
	if err := parse(redirectMessage(t, redirectQuery(t, next().xml(), "", nil, ""))); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("unsigned but required = %v", err)
	}
	// RelayState を書き換えると署名が合わない。
	q := redirectQuery(t, next().xml(), "rs", &sp1, rsaSHA256)
	if err := parse(redirectMessage(t, strings.Replace(q, "RelayState=rs", "RelayState=evil", 1))); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("tampered relay state = %v", err)
	}
	// SHA-1 は受けない。
	q = redirectQuery(t, next().xml(), "", &sp1, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
	if err := parse(redirectMessage(t, q)); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("sha1 = %v", err)
	}
	// 署名が無いのに SigAlg だけある、同じ引数が 2 回あるものは読まない。
	if _, err := samlidp.DecodeRedirect(redirectQuery(t, next().xml(), "", nil, "")+"&SigAlg=x", "SAMLRequest"); !errors.Is(err, errs.Invalid) {
		t.Fatalf("SigAlg without Signature = %v", err)
	}
	if _, err := samlidp.DecodeRedirect(q+"&RelayState=a&RelayState=b", "SAMLRequest"); !errors.Is(err, errs.Invalid) {
		t.Fatalf("duplicate parameter = %v", err)
	}

	// HTTP-POST の XML 署名。
	if err := parse(postMessage(t, signXML(t, next().xml(), sp1), "")); err != nil {
		t.Fatalf("signed post: %v", err)
	}
	if err := parse(postMessage(t, signXML(t, next().xml(), sp2), "")); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("post another key = %v", err)
	}
	// 署名した後で ACS を書き換えると通らない。
	r := next()
	signed := signXML(t, r.xml(), sp1)
	tampered := strings.Replace(signed, `ID="`+r.ID+`"`, `ID="`+r.ID+`" AssertionConsumerServiceURL="`+spACS+`"`, 1)
	if err := parse(postMessage(t, tampered, "")); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("tampered post = %v", err)
	}
	// HTTP-Redirect の XML に署名を入れたものは受けない（クエリで署名する）。
	if err := parse(redirectMessage(t, redirectQuery(t, signXML(t, next().xml(), sp1), "", nil, ""))); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("xml signature in redirect = %v", err)
	}
	// 署名した要求は Destination が要る。
	r = next()
	r.Destination = ""
	if err := parse(postMessage(t, signXML(t, r.xml(), sp1), "")); !errors.Is(err, errs.Invalid) {
		t.Fatalf("signed without destination = %v", err)
	}
}

// TestSignatureWrapping は XML Signature Wrapping（署名した要素を残したまま別の要素を読ませる）を拒むことを確かめる。
func TestSignatureWrapping(t *testing.T) {
	s, k := newService(t)
	in := validInput()
	in.Config.RequireSignedRequests = true
	in.Config.ACS = append(in.Config.ACS, samlidp.Endpoint{URL: "https://sp.example.com/other", Index: 9})
	create(t, s, k, in)
	ctx := context.Background()
	now := k.Clock.Now()
	parse := func(raw string) (samlidp.AuthnRequest, error) {
		_, _, req, err := s.ParseAuthnRequest(ctx, k.RealmID, postMessage(t, raw, ""))
		return req, err
	}
	orig := goodReq(now)
	orig.ID = "_orig"
	signed := signXML(t, orig.xml(), sp1)
	inner := strings.TrimPrefix(signed, `<?xml version="1.0" encoding="UTF-8"?>`)
	// 1. 署名した要求を Extensions に隠し、外側を書き換える（ID が同じ）。
	evil := goodReq(now)
	evil.ID, evil.ACSURL = "_orig", "https://sp.example.com/other"
	evil.Extra = `<samlp:Extensions>` + inner + `</samlp:Extensions>`
	if _, err := parse(evil.xml()); err == nil {
		t.Fatal("wrapped request (same ID) accepted")
	}
	// 2. 外側に署名を移し、Reference は中の要素を指す（ID が違う）。
	doc := etree.NewDocument()
	if err := doc.ReadFromString(signed); err != nil {
		t.Fatal(err)
	}
	sig := doc.Root().FindElement("./Signature").Copy()
	doc.Root().RemoveChild(doc.Root().FindElement("./Signature"))
	hidden, _ := doc.WriteToString()
	hidden = strings.TrimPrefix(hidden, `<?xml version="1.0" encoding="UTF-8"?>`)
	outer := etree.NewDocument()
	evil = goodReq(now)
	evil.ID, evil.ACSURL = "_evil", "https://sp.example.com/other"
	evil.Extra = `<samlp:Extensions>` + hidden + `</samlp:Extensions>`
	if err := outer.ReadFromString(evil.xml()); err != nil {
		t.Fatal(err)
	}
	outer.Root().InsertChildAt(outer.Root().ChildElements()[0].Index()+1, sig)
	raw, _ := outer.WriteToString()
	if _, err := parse(raw); err == nil {
		t.Fatal("wrapped request (reference to inner) accepted")
	}
	// 3. 署名を中の要求に残し、外側には署名が無い。
	evil = goodReq(now)
	evil.ID, evil.ACSURL = "_evil2", "https://sp.example.com/other"
	evil.Extra = `<samlp:Extensions>` + inner + `</samlp:Extensions>`
	if _, err := parse(evil.xml()); err == nil {
		t.Fatal("unsigned outer request with signed inner accepted")
	}
	// 4. 正しい要求は通り、値は署名した要素から読む。
	if req, err := parse(signed); err != nil || req.ACS != spACS2 {
		t.Fatalf("original = %+v, %v", req, err)
	}
}

func TestSelectClassRef(t *testing.T) {
	s, _ := newService(t)
	cases := []struct {
		refs, amr []string
		want      string
		ok        bool
	}{
		{nil, []string{"pwd"}, samlidp.ACPasswordProtectedTransport, true},
		{nil, []string{"hwk"}, samlidp.ACUnspecified, true},
		{[]string{samlidp.ACREFEDSMFA}, []string{"pwd"}, "", false},
		{[]string{samlidp.ACREFEDSMFA}, []string{"pwd", "otp"}, samlidp.ACREFEDSMFA, true},
		{[]string{samlidp.ACMicrosoftMFA, samlidp.ACPasswordProtectedTransport}, []string{"pwd"}, samlidp.ACPasswordProtectedTransport, true},
		{[]string{"urn:iam:aal2"}, []string{"pwd", "otp"}, "urn:iam:aal2", true},
		{[]string{"urn:iam:aal3"}, []string{"pwd", "otp"}, "", false},
		{[]string{"urn:x"}, []string{"pwd"}, "", false},
	}
	for _, c := range cases {
		got, ok := s.SelectClassRef(c.refs, c.amr)
		if got != c.want || ok != c.ok {
			t.Errorf("%v %v = %q %v", c.refs, c.amr, got, ok)
		}
	}
}

// idpCert はメタデータから IdP の署名の証明書を読む。
func idpCert(t *testing.T, s *samlidp.Service, k *testkit.Kit) *x509.Certificate {
	t.Helper()
	md, err := s.Metadata(context.Background(), k.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := samlxml.Parse(md, "test")
	if err != nil {
		t.Fatal(err)
	}
	c := root.FindElement(".//KeyDescriptor/KeyInfo/X509Data/X509Certificate")
	der, _ := base64.StdEncoding.DecodeString(c.Text())
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := samlxml.ValidateEnveloped(root, root.FindElement("./Signature"), []*x509.Certificate{cert}, k.Clock.Now()); err != nil {
		t.Fatalf("metadata signature: %v", err)
	}
	for _, want := range []string{issuer + samlidp.SSOPath, issuer + samlidp.SLOPath} {
		if !strings.Contains(string(md), `Location="`+want+`"`) {
			t.Fatalf("metadata lacks %s", want)
		}
	}
	return cert
}

func pending(k *testkit.Kit, sp port.SAMLServiceProvider) samlidp.Pending {
	return samlidp.Pending{RealmID: k.RealmID, SPID: sp.ID, EntityID: sp.EntityID, ACS: spACS, RequestID: "_req1", RelayState: "rs"}
}

func subject(k *testkit.Kit, u port.User) samlidp.Subject {
	return samlidp.Subject{UserID: u.ID, SID: "sid-1", AuthTime: k.Clock.Now().Add(-time.Minute), AMR: []string{"pwd", "otp"}}
}

// TestIssueVerifiedBySP は発行した Response を iam の SAML の SP の検証（ADR 0098）に通す。
func TestIssueVerifiedBySP(t *testing.T) {
	s, k := newService(t)
	sp := create(t, s, k, validInput())
	cfg, _ := samlidp.ConfigOf(sp)
	u := k.SeedUser(t)
	cert := idpCert(t, s, k)
	out, err := s.Issue(context.Background(), sp, cfg, pending(k, sp), subject(k, u), samlidp.ACREFEDSMFA, "req")
	if err != nil {
		t.Fatal(err)
	}
	if out.ACS != spACS || out.RelayState != "rs" || out.AssertionID == "" {
		t.Fatalf("issued = %+v", out)
	}
	raw, _ := base64.StdEncoding.DecodeString(out.SAMLResponse)
	a, err := saml.Verify(raw, saml.Expect{IdPEntityID: issuer, Certs: []*x509.Certificate{cert}, SPEntityID: spEntity, ACSURL: spACS,
		RequestID: "_req1", Now: k.Clock.Now()})
	if err != nil {
		t.Fatalf("sp verify: %v\n%s", err, raw)
	}
	if a.NameID != u.PublicID || a.NameIDFormat != samlidp.NameIDPersistent || a.ID != out.AssertionID {
		t.Fatalf("assertion = %+v", a)
	}
	if a.Attributes["urn:oid:0.9.2342.19200300.100.1.1"][0] != u.PublicID || !slices.Equal(a.Attributes["amr"], []string{"pwd", "otp"}) {
		t.Fatalf("attributes = %v", a.Attributes)
	}
	doc := etree.NewDocument()
	_ = doc.ReadFromBytes(raw)
	st := doc.FindElement("//AuthnStatement")
	if st.FindElement("./AuthnContext/AuthnContextClassRef").Text() != samlidp.ACREFEDSMFA || st.SelectAttrValue("SessionIndex", "") == "" {
		t.Fatal("authn statement")
	}
	// 期限を過ぎた Response は SP が受けない（Assertion の期間は 5 分）。
	if _, err := saml.Verify(raw, saml.Expect{IdPEntityID: issuer, Certs: []*x509.Certificate{cert}, SPEntityID: spEntity, ACSURL: spACS,
		RequestID: "_req1", Now: k.Clock.Now().Add(9 * time.Minute)}); err == nil {
		t.Fatal("expired response accepted")
	}
	evs := auditEvents(t, k)
	ev := evs[len(evs)-1]
	if ev.Type != "saml_idp.assertion_issued" || ev.Actor.ID != u.PublicID || ev.SessionID != "sid-1" || ev.Details["assertion_id"] != out.AssertionID ||
		ev.Details["authn_context"] != samlidp.ACREFEDSMFA {
		t.Fatalf("audit = %+v", ev)
	}
	// IdP-initiated（InResponseTo なし）は許した SP だけ。
	if _, _, err := s.NewIdPInitiated(context.Background(), k.RealmID, spEntity, ""); !errors.Is(err, samlidp.ErrIdPInitiatedNotAllowed) {
		t.Fatalf("idp-initiated = %v", err)
	}
}

func TestIssueSignedResponseAndEncryption(t *testing.T) {
	s, k := newService(t)
	in := validInput()
	in.Config.SignAssertion, in.Config.SignResponse, in.Config.EncryptionCert = false, true, sp2.Cert
	in.Config.AllowIdPInitiated = true
	sp := create(t, s, k, in)
	cfg, _ := samlidp.ConfigOf(sp)
	u := k.SeedUser(t)
	cert := idpCert(t, s, k)
	_, p, err := s.NewIdPInitiated(context.Background(), k.RealmID, spEntity, "deep")
	if err != nil || p.RequestID != "" || p.ACS != spACS2 {
		t.Fatalf("idp-initiated = %+v, %v", p, err)
	}
	out, err := s.Issue(context.Background(), sp, cfg, p, subject(k, u), samlidp.ACUnspecified, "req")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(out.SAMLResponse)
	root, err := samlxml.Parse(raw, "test")
	if err != nil {
		t.Fatal(err)
	}
	if root.SelectAttr("InResponseTo") != nil {
		t.Fatal("idp-initiated response has InResponseTo")
	}
	verified, err := samlxml.ValidateEnveloped(root, root.FindElement("./Signature"), []*x509.Certificate{cert}, k.Clock.Now())
	if err != nil {
		t.Fatalf("response signature: %v", err)
	}
	if verified.FindElement("./Assertion") != nil {
		t.Fatal("plaintext assertion next to the encrypted one")
	}
	ea := verified.FindElement("./EncryptedAssertion/EncryptedData")
	if ea == nil || ea.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", "") != "http://www.w3.org/2009/xmlenc11#aes128-gcm" {
		t.Fatal("encryption method")
	}
	ekv, _ := base64.StdEncoding.DecodeString(ea.FindElement("./KeyInfo/EncryptedKey/CipherData/CipherValue").Text())
	key, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, sp2.Key, ekv, nil) // #nosec G401 -- テスト
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(ea.FindElement("./CipherData/CipherValue").Text())
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, ct[:12], ct[12:], nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := samlxml.Parse(plain, "test")
	if err != nil || a.Tag != "Assertion" || a.FindElement("./Signature") != nil || a.FindElement("./Subject/NameID").Text() != u.PublicID {
		t.Fatalf("decrypted = %s, %v", plain, err)
	}
	if a.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData").SelectAttrValue("Recipient", "") != spACS2 {
		t.Fatal("recipient")
	}
}

func TestIssueNameID(t *testing.T) {
	s, k := newService(t)
	in := validInput()
	in.Config.NameIDFormat = samlidp.NameIDEmail
	sp := create(t, s, k, in)
	cfg, _ := samlidp.ConfigOf(sp)
	u := k.SeedUser(t)
	// 確認済みのメールが無ければ InvalidNameIDPolicy。
	_, err := s.Issue(context.Background(), sp, cfg, pending(k, sp), subject(k, u), samlidp.ACUnspecified, "req")
	if st, ok := samlidp.ErrorFor(err); !ok || st.Sub != samlidp.StatusInvalidNameID {
		t.Fatalf("no email = %v", err)
	}
	// transient は毎回変わる。
	in.EntityID, in.Config.NameIDFormat = "urn:t", samlidp.NameIDTransient
	sp = create(t, s, k, in)
	cfg, _ = samlidp.ConfigOf(sp)
	var ids []string
	for range 2 {
		out, err := s.Issue(context.Background(), sp, cfg, pending(k, sp), subject(k, u), samlidp.ACUnspecified, "req")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(out.SAMLResponse)
		doc := etree.NewDocument()
		_ = doc.ReadFromBytes(raw)
		n := doc.FindElement("//Subject/NameID")
		if n.SelectAttrValue("Format", "") != samlidp.NameIDTransient {
			t.Fatal("format")
		}
		ids = append(ids, n.Text())
	}
	if ids[0] == ids[1] || ids[0] == u.PublicID {
		t.Fatalf("transient ids = %v", ids)
	}
}

func TestIssueError(t *testing.T) {
	s, k := newService(t)
	sp := create(t, s, k, validInput())
	cert := idpCert(t, s, k)
	out, err := s.IssueError(context.Background(), pending(k, sp), &samlidp.StatusError{Code: samlidp.StatusResponder, Sub: samlidp.StatusNoPassive, Msg: "m"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(out.SAMLResponse)
	root, _ := samlxml.Parse(raw, "test")
	v, err := samlxml.ValidateEnveloped(root, root.FindElement("./Signature"), []*x509.Certificate{cert}, k.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	sc := v.FindElement("./Status/StatusCode")
	if sc.SelectAttrValue("Value", "") != samlidp.StatusResponder || sc.FindElement("./StatusCode").SelectAttrValue("Value", "") != samlidp.StatusNoPassive ||
		v.FindElement("./Assertion") != nil || v.SelectAttrValue("InResponseTo", "") != "_req1" {
		t.Fatalf("error response = %s", raw)
	}
	// SP の検証は失敗の状態を受けない。
	if _, err := saml.Verify(raw, saml.Expect{IdPEntityID: issuer, Certs: []*x509.Certificate{cert}, SPEntityID: spEntity, ACSURL: spACS,
		RequestID: "_req1", Now: k.Clock.Now()}); err == nil {
		t.Fatal("error response verified as success")
	}
}

func TestPending(t *testing.T) {
	s, k := newService(t)
	ctx := context.Background()
	sp := create(t, s, k, validInput())
	now := k.Clock.Now()
	p := samlidp.NewPending(k.RealmID, sp, samlidp.AuthnRequest{ID: "_r", ACS: spACS, ForceAuthn: true}, "rs", now)
	if p.Fresh(now.Add(-time.Second)) || !p.Fresh(now) {
		t.Fatal("ForceAuthn")
	}
	rid, err := s.Hold(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Resume(ctx, k.RealmID, rid)
	if err != nil || got.SPID != sp.ID || got.RelayState != "rs" || got.LoginAfter == nil {
		t.Fatalf("resume = %+v, %v", got, err)
	}
	if _, _, err := s.Recheck(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resume(ctx, "other", rid); !errors.Is(err, samlidp.ErrRequestExpired) {
		t.Fatalf("other realm = %v", err)
	}
	// 待つ間に ACS の登録から外れたら返さない。
	up := validInput()
	up.Config.ACS = []samlidp.Endpoint{{URL: spACS2}}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := s.Update(ctx, tx, sp, up, audit.Actor{}, "")
		return err
	})
	if _, _, err := s.Recheck(ctx, got); !errors.Is(err, samlidp.ErrUnknownACS) {
		t.Fatalf("recheck = %v", err)
	}
	k.Clock.Advance(11 * time.Minute)
	if _, err := s.Resume(ctx, k.RealmID, rid); !errors.Is(err, samlidp.ErrRequestExpired) {
		t.Fatalf("expired = %v", err)
	}
}

// logoutReq は LogoutRequest の XML。
func logoutReq(id, nameID string, now time.Time, indexes ...string) string {
	x := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id +
		`" Version="2.0" IssueInstant="` + now.UTC().Format(time.RFC3339) + `" Destination="` + issuer + samlidp.SLOPath + `"><saml:Issuer>` + spEntity +
		`</saml:Issuer><saml:NameID Format="` + samlidp.NameIDPersistent + `">` + nameID + `</saml:NameID>`
	for _, i := range indexes {
		x += `<samlp:SessionIndex>` + i + `</samlp:SessionIndex>`
	}
	return x + `</samlp:LogoutRequest>`
}

func TestLogout(t *testing.T) {
	s, k := newService(t)
	ctx := context.Background()
	sp := create(t, s, k, validInput())
	cfg, _ := samlidp.ConfigOf(sp)
	u := k.SeedUser(t)
	cert := idpCert(t, s, k)
	now := k.Clock.Now()
	// SSO で渡した SessionIndex を読む。
	out, err := s.Issue(ctx, sp, cfg, pending(k, sp), subject(k, u), samlidp.ACUnspecified, "req")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(out.SAMLResponse)
	doc := etree.NewDocument()
	_ = doc.ReadFromBytes(raw)
	idx := doc.FindElement("//AuthnStatement").SelectAttrValue("SessionIndex", "")

	parse := func(q string) (samlidp.LogoutPending, error) {
		return s.ParseLogoutRequest(ctx, k.RealmID, redirectMessage(t, q))
	}
	// 署名の無い LogoutRequest は受けない。
	if _, err := parse(redirectQuery(t, logoutReq("_l0", u.PublicID, now), "", nil, "")); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("unsigned = %v", err)
	}
	if _, err := parse(redirectQuery(t, logoutReq("_l1", u.PublicID, now), "", &sp2, rsaSHA256)); !errors.Is(err, samlidp.ErrBadSignature) {
		t.Fatalf("another key = %v", err)
	}
	lp, err := parse(redirectQuery(t, logoutReq("_l2", u.PublicID, now, idx), "rs", &sp1, rsaSHA256))
	if err != nil || lp.NameID != u.PublicID || lp.Reply.URL != spSLO || lp.RelayState != "rs" {
		t.Fatalf("parse = %+v, %v", lp, err)
	}
	if _, err := parse(redirectQuery(t, logoutReq("_l2", u.PublicID, now, idx), "rs", &sp1, rsaSHA256)); !errors.Is(err, samlidp.ErrReplayed) {
		t.Fatalf("replay = %v", err)
	}
	if ok, err := s.Matches(ctx, lp, u.ID, "", "sid-1"); err != nil || !ok {
		t.Fatalf("match = %v %v", ok, err)
	}
	if ok, _ := s.Matches(ctx, lp, u.ID, "", "sid-2"); ok {
		t.Fatal("matched another session index")
	}
	other := k.SeedUser(t)
	if ok, _ := s.Matches(ctx, lp, other.ID, "", "sid-1"); ok {
		t.Fatal("matched another user")
	}
	// SessionIndex が無ければ NameID で決める。
	lp2, err := parse(redirectQuery(t, logoutReq("_l3", u.PublicID, now), "", &sp1, rsaSHA256))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Matches(ctx, lp2, u.ID, "", "any"); !ok {
		t.Fatal("name id match")
	}
	// LogoutResponse（HTTP-Redirect。IdP の鍵でクエリに署名する）。
	reply, err := s.LogoutResponse(ctx, lp, nil)
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := url.Parse(reply.URL)
	if reply.Binding != samlidp.BindingRedirect || u2.Host != "sp.example.com" || u2.Query().Get("RelayState") != "rs" ||
		u2.Query().Get("SigAlg") != samlxml.AlgECDSA256 {
		t.Fatalf("reply = %+v", reply)
	}
	signedPart := u2.RawQuery[:strings.Index(u2.RawQuery, "&Signature=")]
	sig, _ := base64.StdEncoding.DecodeString(u2.Query().Get("Signature"))
	sum := sha256.Sum256([]byte(signedPart))
	pub := cert.PublicKey.(*ecdsa.PublicKey)
	if len(sig) != 64 || !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("logout response signature")
	}
	m, err := samlidp.DecodeRedirect(u2.RawQuery, "SAMLResponse")
	if err != nil || !strings.Contains(string(m.XML), `InResponseTo="_l2"`) || !strings.Contains(string(m.XML), samlidp.StatusSuccess) {
		t.Fatalf("logout response = %s, %v", m.XML, err)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return nil })
	if err := s.LoggedOut(ctx, lp, u.PublicID, "sid-1", "req"); err != nil {
		t.Fatal(err)
	}
	if got := auditTypes(t, k); got[len(got)-1] != "saml_idp.logged_out" {
		t.Fatalf("audit = %v", got)
	}
	// SLO の登録が無い SP の LogoutRequest は受けない（返す先が無い）。
	in := validInput()
	in.EntityID, in.Config.SLO = "urn:noslo", nil
	create(t, s, k, in)
	x := strings.Replace(logoutReq("_l4", u.PublicID, now), spEntity, "urn:noslo", 1)
	if _, err := parse(redirectQuery(t, x, "", &sp1, rsaSHA256)); !errors.Is(err, samlidp.ErrNoSLO) {
		t.Fatalf("no slo = %v", err)
	}
}

func TestMetadataStableCertificate(t *testing.T) {
	s, k := newService(t)
	c1 := idpCert(t, s, k)
	c2 := idpCert(t, s, k)
	if !c1.Equal(c2) {
		t.Fatal("certificate changed for the same key")
	}
	if _, ok := c1.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatal("not ES256")
	}
}
