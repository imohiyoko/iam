package wsfed_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/wsfed"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

const issuer = "https://id.example.com"

func newService(t *testing.T) (*wsfed.Service, *testkit.Kit) {
	t.Helper()
	k := testkit.New(t)
	keys := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour}
	return &wsfed.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Keys: keys, Tokens: &provider.Tokens{},
		Issuer: issuer}, k
}

func validInput() wsfed.Input {
	return wsfed.Input{Realm: "urn:sharepoint:portal", Name: "Portal", ReplyURLs: []string{"https://portal.example.com/_trust/", "https://portal.example.com/b"}}
}

func TestValidate(t *testing.T) {
	in, err := wsfed.Validate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	if in.TokenType != wsfed.TokenSAML11 || in.TokenLifetime != wsfed.DefaultTokenLifetime || len(in.Claims) != 1 || in.Claims[0].Source != wsfed.SourceEmail {
		t.Fatalf("defaults = %+v", in)
	}
	empty := validInput()
	empty.Claims = []wsfed.Claim{}
	if in, err := wsfed.Validate(empty); err != nil || len(in.Claims) != 0 {
		t.Fatalf("explicit empty claims = %+v, %v", in, err)
	}
	bad := map[string]func(*wsfed.Input){
		"no realm":         func(i *wsfed.Input) { i.Realm = "" },
		"relative realm":   func(i *wsfed.Input) { i.Realm = "portal" },
		"realm with space": func(i *wsfed.Input) { i.Realm = "urn:a b" },
		"long realm":       func(i *wsfed.Input) { i.Realm = "urn:" + strings.Repeat("a", 1024) },
		"no name":          func(i *wsfed.Input) { i.Name = "" },
		"control in name":  func(i *wsfed.Input) { i.Name = "a\nb" },
		"no reply":         func(i *wsfed.Input) { i.ReplyURLs = nil },
		"http reply":       func(i *wsfed.Input) { i.ReplyURLs = []string{"http://portal.example.com/"} },
		"fragment reply":   func(i *wsfed.Input) { i.ReplyURLs = []string{"https://portal.example.com/#x"} },
		"empty fragment":   func(i *wsfed.Input) { i.ReplyURLs = []string{"https://portal.example.com/#"} },
		"userinfo reply":   func(i *wsfed.Input) { i.ReplyURLs = []string{"https://u@portal.example.com/"} },
		"relative reply":   func(i *wsfed.Input) { i.ReplyURLs = []string{"/trust"} },
		"duplicate reply":  func(i *wsfed.Input) { i.ReplyURLs = []string{"https://a.example/", "https://a.example/"} },
		"too many replies": func(i *wsfed.Input) {
			i.ReplyURLs = strings.Split(strings.Repeat("https://a.example/x,", 11), ",")[:11]
		},
		"token type":          func(i *wsfed.Input) { i.TokenType = "jwt" },
		"short lifetime":      func(i *wsfed.Input) { i.TokenLifetime = 60 },
		"long lifetime":       func(i *wsfed.Input) { i.TokenLifetime = 86401 },
		"negative lifetime":   func(i *wsfed.Input) { i.TokenLifetime = -1 },
		"unknown source":      func(i *wsfed.Input) { i.Claims = []wsfed.Claim{{Source: "password", Type: "urn:x/y"}} },
		"bad attribute key":   func(i *wsfed.Input) { i.Claims = []wsfed.Claim{{Source: "attribute:Bad", Type: "urn:x/y"}} },
		"relative claim type": func(i *wsfed.Input) { i.Claims = []wsfed.Claim{{Source: "email", Type: "email"}} },
		"saml11 no name":      func(i *wsfed.Input) { i.Claims = []wsfed.Claim{{Source: "email", Type: "urn:oid:0.9.2342"}} },
		"saml11 slash end": func(i *wsfed.Input) {
			i.Claims = []wsfed.Claim{{Source: "email", Type: "http://schemas.example.com/claims/"}}
		},
		"duplicate claim type": func(i *wsfed.Input) {
			i.Claims = []wsfed.Claim{{Source: "email", Type: "urn:x/y"}, {Source: "user_id", Type: "urn:x/y"}}
		},
	}
	for name, mut := range bad {
		in := validInput()
		mut(&in)
		if _, err := wsfed.Validate(in); !errors.Is(err, errs.Invalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// SAML 2.0 は "/" の無いクレームの種類（urn:oid など）も使える。
	ok := validInput()
	ok.TokenType, ok.Claims = wsfed.TokenSAML20, []wsfed.Claim{{Source: "email", Type: "urn:oid:0.9.2342.19200300.100.1.3"}, {Source: "attribute:dept", Type: "urn:x/dept"}}
	if _, err := wsfed.Validate(ok); err != nil {
		t.Fatal(err)
	}
}

func TestParseRequest(t *testing.T) {
	r, err := wsfed.ParseRequest(url.Values{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wreply": {"https://a.example/"}, "wctx": {"rm=0&id=x"},
		"wct": {"2026-11-02T00:00:00Z"}, "whr": {"urn:x"}, "wfresh": {"0"}})
	if err != nil || r.Action != wsfed.ActionSignIn || r.Realm != "urn:a" || r.Reply != "https://a.example/" || r.Context != "rm=0&id=x" ||
		r.Fresh == nil || *r.Fresh != 0 {
		t.Fatalf("parse = %+v, %v", r, err)
	}
	if r, err := wsfed.ParseRequest(url.Values{"wa": {"wsignout1.0"}}); err != nil || r.Action != wsfed.ActionSignOut {
		t.Fatalf("signout = %+v, %v", r, err)
	}
	big := url.Values{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wfresh": {"9999999999"}}
	if r, err := wsfed.ParseRequest(big); err != nil || *r.Fresh != 100*365*24*60 {
		t.Fatalf("large wfresh = %+v, %v", r, err)
	}
	bad := []url.Values{
		{},
		{"wa": {"wsignin1.0"}},
		{"wa": {"wsignin2.0"}, "wtrealm": {"urn:a"}},
		{"wa": {"wsignoutcleanup1.0"}},
		{"wa": {"wsignin1.0", "wsignin1.0"}, "wtrealm": {"urn:a"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a", "urn:b"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wreply": {"https://a/", "https://b/"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wreq": {"<x/>"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wreqptr": {"https://x/"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wauth": {"urn:oasis:names:tc:SAML:1.0:am:password"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wauth": {""}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wfresh": {""}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wfresh": {"-1"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wfresh": {"1.5"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wctx": {strings.Repeat("x", 2049)}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:a"}, "wctx": {"\xff"}},
		{"wa": {"wsignin1.0"}, "wtrealm": {"urn:" + strings.Repeat("a", 1100)}},
	}
	for i, q := range bad {
		if _, err := wsfed.ParseRequest(q); !errors.Is(err, errs.Invalid) {
			t.Errorf("%d %v: err = %v", i, q, err)
		}
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add("wa=wsignin1.0&wtrealm=urn%3Aa&wreply=https%3A%2F%2Fa.example%2F&wctx=x&wfresh=5")
	f.Add("wa=wsignout1.0&wreply=https%3A%2F%2Fa%2F")
	f.Add("wa=wsignin1.0&wtrealm=a&wtrealm=b")
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		r, err := wsfed.ParseRequest(q)
		if err != nil {
			return
		}
		if r.Action != wsfed.ActionSignIn && r.Action != wsfed.ActionSignOut {
			t.Fatalf("action %q accepted", r.Action)
		}
		if r.Action == wsfed.ActionSignIn && r.Realm == "" {
			t.Fatal("signin without wtrealm accepted")
		}
		if len(r.Context) > 2048 || (r.Fresh != nil && *r.Fresh < 0) {
			t.Fatalf("out of range: %+v", r)
		}
		for _, k := range []string{"wreq", "wreqptr", "wauth"} {
			if q.Has(k) {
				t.Fatalf("%s accepted", k)
			}
		}
	})
}

func FuzzValidateInput(f *testing.F) {
	f.Add("urn:a", "App", "https://a.example/", "saml11", "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", 0)
	f.Add("https://a.example/", "x", "https://a.example/#", "saml20", "attribute:dept", "urn:oid:1.2", 300)
	f.Fuzz(func(t *testing.T, realm, name, reply, tokenType, source, claimType string, lifetime int) {
		in, err := wsfed.Validate(wsfed.Input{Realm: realm, Name: name, ReplyURLs: []string{reply}, TokenType: tokenType,
			Claims: []wsfed.Claim{{Source: source, Type: claimType}}, TokenLifetime: lifetime})
		if err != nil {
			return
		}
		u, err := url.Parse(in.ReplyURLs[0])
		if err != nil || u.Scheme != "https" || u.Host == "" || strings.Contains(in.ReplyURLs[0], "#") {
			t.Fatalf("reply %q accepted", in.ReplyURLs[0])
		}
		if in.TokenLifetime < wsfed.MinTokenLifetime || in.TokenLifetime > wsfed.MaxTokenLifetime {
			t.Fatalf("lifetime %d accepted", in.TokenLifetime)
		}
		if in.TokenType != wsfed.TokenSAML11 && in.TokenType != wsfed.TokenSAML20 {
			t.Fatalf("token type %q accepted", in.TokenType)
		}
	})
}

func create(t *testing.T, s *wsfed.Service, k *testkit.Kit, in wsfed.Input) port.WSFedRelyingParty {
	t.Helper()
	var rp port.WSFedRelyingParty
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		rp, err = s.Create(ctx, tx, k.RealmID, in, audit.Actor{Type: "operator", ID: "op"}, "req")
		return err
	})
	return rp
}

func TestRelyingPartyLifecycle(t *testing.T) {
	s, k := newService(t)
	ctx := context.Background()
	rp := create(t, s, k, validInput())
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if _, err := s.Create(ctx, tx, k.RealmID, validInput(), audit.Actor{}, ""); !errors.Is(err, wsfed.ErrRealmExists) {
			t.Fatalf("duplicate = %v", err)
		}
		return nil
	})
	// wtrealm と wreply は完全一致だけ。
	got, reply, err := s.Lookup(ctx, k.RealmID, "urn:sharepoint:portal", "")
	if err != nil || got.ID != rp.ID || reply != "https://portal.example.com/_trust/" {
		t.Fatalf("lookup = %+v %q %v", got, reply, err)
	}
	if _, reply, err := s.Lookup(ctx, k.RealmID, "urn:sharepoint:portal", "https://portal.example.com/b"); err != nil || reply != "https://portal.example.com/b" {
		t.Fatalf("lookup reply = %q %v", reply, err)
	}
	for _, c := range []struct{ realm, reply string }{
		{"urn:sharepoint:portal", "https://portal.example.com/_trust"},
		{"urn:sharepoint:portal", "https://portal.example.com/_trust/?x=1"},
		{"urn:sharepoint:portal", "https://evil.example/"},
		{"urn:sharepoint:Portal", ""},
		{"urn:sharepoint:portal/", ""},
		{"", ""},
	} {
		_, _, err := s.Lookup(ctx, k.RealmID, c.realm, c.reply)
		if !errors.Is(err, wsfed.ErrUnknownRealm) && !errors.Is(err, wsfed.ErrUnknownReply) {
			t.Errorf("%+v: err = %v", c, err)
		}
	}
	// 別の realm からは見えない。
	if _, _, err := s.Lookup(ctx, "other", "urn:sharepoint:portal", ""); !errors.Is(err, wsfed.ErrUnknownRealm) {
		t.Fatalf("other realm = %v", err)
	}
	up := validInput()
	up.Realm, up.TokenType = "urn:sharepoint:portal2", wsfed.TokenSAML20
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		rp, err = s.Update(ctx, tx, rp, up, audit.Actor{Type: "operator", ID: "op"}, "req")
		return err
	})
	if _, _, err := s.Lookup(ctx, k.RealmID, "urn:sharepoint:portal", ""); !errors.Is(err, wsfed.ErrUnknownRealm) {
		t.Fatalf("old realm still resolves: %v", err)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		return s.Delete(ctx, tx, rp, audit.Actor{Type: "operator", ID: "op"}, "req")
	})
	if _, _, err := s.Lookup(ctx, k.RealmID, "urn:sharepoint:portal2", ""); !errors.Is(err, wsfed.ErrUnknownRealm) {
		t.Fatalf("deleted realm resolves: %v", err)
	}
	var types []string
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().ListByRealm(ctx, k.RealmID, 0, 100)
		for _, r := range rs {
			e, err := audit.Unmarshal(r.Payload)
			if err != nil {
				return err
			}
			types = append(types, e.Type)
		}
		return err
	})
	if strings.Join(types, ",") != "wsfed.relying_party.created,wsfed.relying_party.updated,wsfed.relying_party.deleted" {
		t.Fatalf("audit = %v", types)
	}
}

func TestPendingFreshness(t *testing.T) {
	s, k := newService(t)
	ctx := context.Background()
	rp := create(t, s, k, validInput())
	now := k.Clock.Now()
	zero, five := 0, 5
	p := wsfed.NewPending(k.RealmID, rp, rp.ReplyURLs[0], wsfed.Request{Context: "c", Fresh: &zero}, now)
	if p.Fresh(now.Add(-time.Second), now) || !p.Fresh(now, now) {
		t.Fatal("wfresh=0")
	}
	p5 := wsfed.NewPending(k.RealmID, rp, rp.ReplyURLs[0], wsfed.Request{Fresh: &five}, now)
	if !p5.Fresh(now.Add(-5*time.Minute), now) || p5.Fresh(now.Add(-5*time.Minute-time.Second), now) {
		t.Fatal("wfresh=5")
	}
	rid, err := s.Hold(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Resume(ctx, k.RealmID, rid)
	if err != nil || got.RPID != rp.ID || got.Context != "c" || got.LoginAfter == nil {
		t.Fatalf("resume = %+v, %v", got, err)
	}
	if _, err := s.Resume(ctx, "other", rid); !errors.Is(err, wsfed.ErrRequestExpired) {
		t.Fatalf("other realm = %v", err)
	}
	if _, err := s.Resume(ctx, k.RealmID, rid+"x"); !errors.Is(err, wsfed.ErrRequestExpired) {
		t.Fatalf("wrong id = %v", err)
	}
	k.Clock.Advance(11 * time.Minute)
	if _, err := s.Resume(ctx, k.RealmID, rid); !errors.Is(err, wsfed.ErrRequestExpired) {
		t.Fatalf("expired = %v", err)
	}
}

// verify は XML 署名を goxmldsig で確かめる。署名の値は r||s（XML 署名の ECDSA）であることを確かめ、goxmldsig が読む DER に
// 直してから検証する。返すのは署名を確かめた要素。
func verify(t *testing.T, el *etree.Element, idAttr string, now time.Time) (*etree.Element, *x509.Certificate) {
	t.Helper()
	el = el.Copy()
	sv := el.FindElement(".//SignatureValue")
	certEl := el.FindElement(".//X509Certificate")
	if sv == nil || certEl == nil {
		t.Fatal("no signature")
	}
	raw, err := base64.StdEncoding.DecodeString(sv.Text())
	if err != nil || len(raw) != 64 {
		t.Fatalf("signature value is not r||s: %d bytes, %v", len(raw), err)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	if err != nil {
		t.Fatal(err)
	}
	sv.SetText(base64.StdEncoding.EncodeToString(der))
	cb, err := base64.StdEncoding.DecodeString(certEl.Text())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(cb)
	if err != nil {
		t.Fatal(err)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	vc.IdAttribute = idAttr
	vc.Clock = dsig.NewFakeClockAt(now)
	out, err := vc.Validate(el)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	if m := el.FindElement(".//SignatureMethod"); m.SelectAttrValue("Algorithm", "") != dsig.ECDSASHA256SignatureMethod {
		t.Fatalf("signature method = %s", m.SelectAttrValue("Algorithm", ""))
	}
	return out, cert
}

func issue(t *testing.T, s *wsfed.Service, k *testkit.Kit, rp port.WSFedRelyingParty, u port.User) (wsfed.Issued, *etree.Element) {
	t.Helper()
	out, err := s.Issue(context.Background(), k.RealmID, rp, rp.ReplyURLs[1], "ctx", wsfed.Subject{UserID: u.ID, SID: "sid",
		AuthTime: k.Clock.Now().Add(-time.Minute), AMR: []string{"pwd", "otp"}}, "req")
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(out.Result); err != nil {
		t.Fatal(err)
	}
	if doc.Root().Tag != "RequestSecurityTokenResponse" || doc.Root().NamespaceURI() != "http://schemas.xmlsoap.org/ws/2005/02/trust" {
		t.Fatalf("root = %s", doc.Root().Tag)
	}
	if a := doc.FindElement("//AppliesTo/EndpointReference/Address"); a == nil || a.Text() != rp.Realm {
		t.Fatal("AppliesTo")
	}
	tok := doc.FindElement("//RequestedSecurityToken/Assertion")
	if tok == nil {
		t.Fatal("no assertion")
	}
	return out, tok
}

func TestIssueSAML11(t *testing.T) {
	s, k := newService(t)
	in := validInput()
	in.Claims = []wsfed.Claim{{Source: "user_id", Type: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"},
		{Source: "email", Type: wsfed.ClaimEmailAddress}, {Source: "amr", Type: "http://schemas.microsoft.com/claims/authnmethodsreferences"}}
	rp := create(t, s, k, in)
	u := k.SeedUser(t)
	out, tok := issue(t, s, k, rp, u)
	if out.Reply != "https://portal.example.com/b" || out.Context != "ctx" {
		t.Fatalf("issued = %+v", out)
	}
	a, _ := verify(t, tok, "AssertionID", k.Clock.Now())
	if a.SelectAttrValue("Issuer", "") != issuer || a.SelectAttrValue("MajorVersion", "") != "1" || a.SelectAttrValue("AssertionID", "") != out.AssertionID {
		t.Fatal("assertion attributes")
	}
	if a.FindElement("./Conditions/AudienceRestrictionCondition/Audience").Text() != rp.Realm {
		t.Fatal("audience")
	}
	if c := a.FindElement("./Conditions"); c.SelectAttrValue("NotOnOrAfter", "") != k.Clock.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z") {
		t.Fatalf("NotOnOrAfter = %s", c.SelectAttrValue("NotOnOrAfter", ""))
	}
	if n := a.FindElement("./AuthenticationStatement/Subject/NameIdentifier"); n == nil || n.Text() != u.PublicID {
		t.Fatal("subject")
	}
	if a.FindElement("./AuthenticationStatement").SelectAttrValue("AuthenticationMethod", "") != "urn:oasis:names:tc:SAML:1.0:am:password" {
		t.Fatal("authentication method")
	}
	// メールが無いユーザーには emailaddress を出さない。amr は複数の値。
	var names []string
	for _, at := range a.FindElements("./AttributeStatement/Attribute") {
		names = append(names, at.SelectAttrValue("AttributeName", ""))
		if at.SelectAttrValue("AttributeName", "") == "authnmethodsreferences" && len(at.ChildElements()) != 2 {
			t.Fatal("amr values")
		}
		if at.SelectAttrValue("AttributeName", "") == "nameidentifier" &&
			(at.SelectAttrValue("AttributeNamespace", "") != "http://schemas.xmlsoap.org/ws/2005/05/identity/claims" || at.ChildElements()[0].Text() != u.PublicID) {
			t.Fatal("nameidentifier")
		}
	}
	if strings.Join(names, ",") != "nameidentifier,authnmethodsreferences" {
		t.Fatalf("attributes = %v", names)
	}
	// 署名は最後の子。
	if ch := tok.ChildElements(); ch[len(ch)-1].Tag != "Signature" {
		t.Fatal("signature position")
	}
	// 書き換えた Assertion は検証に通らない。
	bad := tok.Copy()
	bad.FindElement("./Conditions/AudienceRestrictionCondition/Audience").SetText("urn:evil")
	if err := verifyErr(bad, "AssertionID", k.Clock.Now()); err == nil {
		t.Fatal("tampered assertion verified")
	}
	var ev audit.Event
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Audit().ListByRealm(ctx, k.RealmID, 0, 100)
		if err != nil {
			return err
		}
		ev, err = audit.Unmarshal(rs[len(rs)-1].Payload)
		return err
	})
	if ev.Type != "wsfed.token_issued" || ev.Actor.ID != u.PublicID || ev.SessionID != "sid" || ev.Details["assertion_id"] != out.AssertionID {
		t.Fatalf("audit = %+v", ev)
	}
}

func verifyErr(el *etree.Element, idAttr string, now time.Time) error {
	el = el.Copy()
	sv := el.FindElement(".//SignatureValue")
	raw, _ := base64.StdEncoding.DecodeString(sv.Text())
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
	sv.SetText(base64.StdEncoding.EncodeToString(der))
	cb, _ := base64.StdEncoding.DecodeString(el.FindElement(".//X509Certificate").Text())
	cert, err := x509.ParseCertificate(cb)
	if err != nil {
		return err
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	vc.IdAttribute, vc.Clock = idAttr, dsig.NewFakeClockAt(now)
	_, err = vc.Validate(el)
	return err
}

func TestIssueSAML20AndStableCertificate(t *testing.T) {
	s, k := newService(t)
	in := validInput()
	in.TokenType = wsfed.TokenSAML20
	in.Claims = []wsfed.Claim{{Source: "user_id", Type: "urn:oid:0.9.2342.19200300.100.1.1"}}
	rp := create(t, s, k, in)
	u := k.SeedUser(t)
	_, tok := issue(t, s, k, rp, u)
	a, cert1 := verify(t, tok, "ID", k.Clock.Now())
	if a.SelectAttrValue("Version", "") != "2.0" || a.FindElement("./Issuer").Text() != issuer {
		t.Fatal("assertion")
	}
	if ch := tok.ChildElements(); ch[0].Tag != "Issuer" || ch[1].Tag != "Signature" {
		t.Fatal("signature must follow Issuer")
	}
	scd := a.FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData")
	if scd.SelectAttrValue("Recipient", "") != "https://portal.example.com/b" || a.FindElement("./Subject/NameID").Text() != u.PublicID {
		t.Fatal("subject confirmation")
	}
	if a.FindElement("./Conditions/AudienceRestriction/Audience").Text() != rp.Realm {
		t.Fatal("audience")
	}
	if at := a.FindElement("./AttributeStatement/Attribute"); at.SelectAttrValue("Name", "") != "urn:oid:0.9.2342.19200300.100.1.1" {
		t.Fatal("attribute name")
	}
	// 同じ鍵なら同じ証明書（RP が指紋で登録できる）。メタデータにも同じ証明書が載る。
	_, tok2 := issue(t, s, k, rp, u)
	_, cert2 := verify(t, tok2, "ID", k.Clock.Now())
	if !cert1.Equal(cert2) {
		t.Fatal("certificate changed between tokens")
	}
	if p, ok := cert1.PublicKey.(*ecdsa.PublicKey); !ok || p.Curve.Params().Name != "P-256" {
		t.Fatal("certificate key")
	}
	md, err := s.Metadata(context.Background(), k.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(md); err != nil {
		t.Fatal(err)
	}
	ed, mcert := verify(t, doc.Root(), "ID", k.Clock.Now())
	if !mcert.Equal(cert1) || ed.SelectAttrValue("entityID", "") != issuer {
		t.Fatal("metadata certificate or entityID")
	}
	if e := ed.FindElement("./RoleDescriptor/PassiveRequestorEndpoint/EndpointReference/Address"); e == nil || e.Text() != issuer+"/wsfed" {
		t.Fatal("passive endpoint")
	}
	if n := len(ed.FindElements("./RoleDescriptor/KeyDescriptor")); n != 1 {
		t.Fatalf("key descriptors = %d", n)
	}
}

func TestKeyRotationKeepsRetiredCertificateInMetadata(t *testing.T) {
	s, k := newService(t)
	rp := create(t, s, k, validInput())
	u := k.SeedUser(t)
	_, tok := issue(t, s, k, rp, u)
	_, old := verify(t, tok, "AssertionID", k.Clock.Now())
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := s.Keys.Rotate(ctx, tx, k.RealmID, port.AlgES256)
		return err
	})
	_, tok = issue(t, s, k, rp, u)
	_, cur := verify(t, tok, "AssertionID", k.Clock.Now())
	if cur.Equal(old) {
		t.Fatal("certificate did not change with the key")
	}
	count := func() int {
		md, err := s.Metadata(context.Background(), k.RealmID)
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(md); err != nil {
			t.Fatal(err)
		}
		return len(doc.FindElements("//KeyDescriptor"))
	}
	if n := count(); n != 2 {
		t.Fatalf("key descriptors after rotation = %d", n)
	}
	// 退役した鍵が JWKS から消えたら、その証明書も消える。
	k.Clock.Advance(25 * time.Hour)
	if n := count(); n != 1 {
		t.Fatalf("key descriptors after retirement = %d", n)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.WSFed().ListCertificates(ctx, k.RealmID)
		if err == nil && len(cs) != 1 {
			t.Fatalf("certificates = %d", len(cs))
		}
		return err
	})
}
