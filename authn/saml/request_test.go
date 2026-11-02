package saml

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

func TestRedirectURLSigned(t *testing.T) {
	key, certDER, err := newSPKey(testSP, testNow)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{SSOURL: "https://idp.example/sso?tenant=a", ACSURL: testACS, SPEntityID: testSP, NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}
	req, err := authnRequest(cfg, "_abc", testNow)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := redirectURL(cfg.SSOURL, req, "relay-1", key)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("tenant") != "a" || q.Get("RelayState") != "relay-1" || q.Get("SigAlg") != algECDSASHA256 {
		t.Fatalf("query = %v", q)
	}
	// AuthnRequest を取り出す。
	deflated, _ := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	xmlb, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlb); err != nil {
		t.Fatal(err)
	}
	r := doc.Root()
	if r.SelectAttrValue("ID", "") != "_abc" || r.SelectAttrValue("AssertionConsumerServiceURL", "") != testACS ||
		r.SelectAttrValue("Destination", "") != cfg.SSOURL || r.FindElement("./Issuer").Text() != testSP ||
		r.FindElement("./NameIDPolicy").SelectAttrValue("Format", "") != cfg.NameIDFormat {
		t.Fatalf("request = %s", xmlb)
	}
	// 署名は、並べたパラメータそのもの（RawQuery の該当部分）にかかる。
	signed := u.RawQuery[strings.Index(u.RawQuery, "SAMLRequest="):strings.Index(u.RawQuery, "&Signature=")]
	sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
	cert, _ := x509.ParseCertificate(certDER)
	sum := sha256.Sum256([]byte(signed))
	rr, ss := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if len(sig) != 64 || !ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), sum[:], rr, ss) {
		t.Fatal("signature does not verify")
	}
	// 署名しないとき。
	raw, _ = redirectURL(cfg.SSOURL, req, "relay-1", nil)
	if u, _ := url.Parse(raw); u.Query().Get("Signature") != "" || u.Query().Get("SigAlg") != "" {
		t.Fatalf("unsigned: %s", raw)
	}
}

func TestMetadata(t *testing.T) {
	md, err := ParseIdPMetadata(testIdP.Metadata(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if md.EntityID != testIdP.EntityID || md.SSOURL != testIdP.SSOURL || len(md.Certs) != 1 || !md.Certs[0].Equal(testIdP.Cert) {
		t.Fatalf("metadata = %+v", md)
	}
	// 集約（EntitiesDescriptor）からは entity_id で選ぶ。
	other := samltestMetadata("https://other.example/entity")
	agg := []byte(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` +
		strings.TrimPrefix(string(testIdP.Metadata()), `<?xml version="1.0"?>`) + other + `</md:EntitiesDescriptor>`)
	if _, err := ParseIdPMetadata(agg, "", false); err == nil {
		t.Fatal("ambiguous metadata accepted")
	}
	if md, err := ParseIdPMetadata(agg, testIdP.EntityID, false); err != nil || md.EntityID != testIdP.EntityID {
		t.Fatalf("select: %v %+v", err, md)
	}
	for name, raw := range map[string]string{
		"doctype":   `<!DOCTYPE md [<!ENTITY x "y">]>` + strings.TrimPrefix(string(testIdP.Metadata()), `<?xml version="1.0"?>`),
		"http sso":  strings.Replace(string(testIdP.Metadata()), "https://idp.example/sso", "http://idp.example/sso", 1),
		"no cert":   strings.Replace(string(testIdP.Metadata()), `use="signing"`, `use="encryption"`, 1),
		"not saml":  `<a/>`,
		"truncated": string(testIdP.Metadata())[:100],
	} {
		if _, err := ParseIdPMetadata([]byte(raw), "", false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// SP のメタデータ。
	_, cert, _ := newSPKey(testSP, testNow)
	b, err := SPMetadata(Config{SPEntityID: testSP, ACSURL: testACS, SPCert: cert, SignRequests: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`entityID="` + testSP + `"`, `Location="` + testACS + `"`, `AuthnRequestsSigned="true"`, `WantAssertionsSigned="true"`,
		base64.StdEncoding.EncodeToString(cert)[:40]} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("sp metadata lacks %s:\n%s", want, b)
		}
	}
}

func samltestMetadata(entityID string) string {
	return strings.Replace(strings.TrimPrefix(string(testIdP.Metadata()), `<?xml version="1.0"?>`), testIdP.EntityID, entityID, 1)
}
