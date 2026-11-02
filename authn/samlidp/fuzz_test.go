package samlidp_test

import (
	"context"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/internal/testkit"
)

// FuzzParseAuthnRequest は AuthnRequest の解析（HTTP-POST）に任意の XML を与え、panic せず、受けたなら ACS が登録したものの
// どれかで、ID があることを確かめる（design.md 13 章。ADR 0115）。
func FuzzParseAuthnRequest(f *testing.F) {
	now := testkit.T0
	f.Add([]byte(goodReq(now).xml()))
	r := goodReq(now)
	r.ACSURL, r.ClassRefs, r.NameIDFormat = spACS, []string{samlidp.ACREFEDSMFA}, samlidp.NameIDPersistent
	f.Add([]byte(r.xml()))
	f.Add([]byte(signXML(f, goodReq(now).xml(), sp1)))
	f.Add([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE a [<!ENTITY b "c">]><a>&b;</a>`))
	s, k := newService(f)
	sp := create(f, s, k, validInput())
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := samlidp.DecodePOST(base64.StdEncoding.EncodeToString(raw), "")
		if err != nil {
			return
		}
		got, cfg, req, err := s.ParseAuthnRequest(context.Background(), k.RealmID, m)
		if err != nil {
			return
		}
		if got.ID != sp.ID || req.ID == "" || !slices.ContainsFunc(cfg.ACS, func(e samlidp.Endpoint) bool { return e.URL == req.ACS }) {
			t.Fatalf("accepted %+v for %+v", req, got)
		}
	})
}

// FuzzDecodeRedirect は HTTP-Redirect のクエリの読み取りに任意の入力を与え、panic せず、上限を守ることを確かめる。
func FuzzDecodeRedirect(f *testing.F) {
	f.Add(redirectQuery(f, goodReq(testkit.T0).xml(), "rs", nil, ""))
	f.Add(redirectQuery(f, goodReq(testkit.T0).xml(), "", &sp1, rsaSHA256))
	f.Add("SAMLRequest=%%&RelayState=a&RelayState=b")
	f.Fuzz(func(t *testing.T, q string) {
		m, err := samlidp.DecodeRedirect(q, "SAMLRequest")
		if err != nil {
			return
		}
		if len(m.XML) == 0 || len(m.XML) > 64<<10 || len(m.RelayState) > samlidp.MaxRelayStateLen {
			t.Fatalf("out of range: %d %d", len(m.XML), len(m.RelayState))
		}
	})
}

// FuzzParseLogoutRequest は LogoutRequest の解析に任意の XML を与え、panic せず、署名の無いものを受けないことを確かめる。
func FuzzParseLogoutRequest(f *testing.F) {
	f.Add([]byte(logoutReq("_l", "u", testkit.T0)))
	f.Add([]byte(signXML(f, logoutReq("_l", "u", testkit.T0), sp1)))
	s, k := newService(f)
	create(f, s, k, validInput())
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := samlidp.DecodePOST(base64.StdEncoding.EncodeToString(raw), "")
		if err != nil {
			return
		}
		lp, err := s.ParseLogoutRequest(context.Background(), k.RealmID, m)
		if err == nil && (lp.NameID == "" || lp.Reply.URL == "") {
			t.Fatalf("accepted %+v", lp)
		}
	})
}
