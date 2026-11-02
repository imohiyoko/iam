// Package samltest はテスト用の SAML の IdP（署名した応答を作る）。本番のコードからは使わない。
package samltest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// IdP はテスト用の IdP。
type IdP struct {
	EntityID string
	SSOURL   string
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
}

// New は鍵と自己署名の証明書（now から 1 年）を持つ IdP を作る。
func New(entityID, ssoURL string, now time.Time) *IdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &IdP{EntityID: entityID, SSOURL: ssoURL, Key: key, Cert: cert}
}

// Metadata は IdP のメタデータ（EntityDescriptor）を返す。
func (p *IdP) Metadata() []byte {
	return fmt.Appendf(nil, `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, p.EntityID, base64.StdEncoding.EncodeToString(p.Cert.Raw), p.SSOURL)
}

// Response は作る応答の中身。空の項目は正しい既定値にしない（テストで明示する）。
type Response struct {
	ID, AssertionID          string
	Destination, Recipient   string
	InResponseTo             string // Response と SubjectConfirmationData の両方
	Audience                 string
	NameID, NameIDFormat     string
	Issuer                   string // 空なら IdP の EntityID
	Attributes               map[string]string
	Now                      time.Time
	NotOnOrAfter             time.Time // 空なら Now + 5 分
	StatusCode               string    // 空なら Success
	SHA1                     bool      // SHA-1 で署名する
	SignResponse             bool      // 応答にも署名する
	UnsignedAssertion        bool
	SignWith                 *IdP // 空なら p
	OmitResponseInResponseTo bool
}

// Element は署名した Assertion を含む Response の要素を返す（テストで書き換えてから Bytes にする）。
func (p *IdP) Element(r Response) *etree.Element {
	if r.ID == "" {
		r.ID = "_resp" + rnd()
	}
	if r.AssertionID == "" {
		r.AssertionID = "_assert" + rnd()
	}
	if r.Issuer == "" {
		r.Issuer = p.EntityID
	}
	if r.NotOnOrAfter.IsZero() {
		r.NotOnOrAfter = r.Now.Add(5 * time.Minute)
	}
	if r.StatusCode == "" {
		r.StatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}
	signer := p
	if r.SignWith != nil {
		signer = r.SignWith
	}
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", r.AssertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(r.Now))
	a.CreateElement("saml:Issuer").SetText(r.Issuer)
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	if r.NameIDFormat != "" {
		nid.CreateAttr("Format", r.NameIDFormat)
	}
	nid.SetText(r.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("InResponseTo", r.InResponseTo)
	scd.CreateAttr("NotOnOrAfter", ts(r.NotOnOrAfter))
	scd.CreateAttr("Recipient", r.Recipient)
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", ts(r.Now.Add(-time.Minute)))
	cond.CreateAttr("NotOnOrAfter", ts(r.NotOnOrAfter))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(r.Audience)
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", ts(r.Now))
	as.CreateAttr("SessionIndex", "_s1")
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	if len(r.Attributes) > 0 {
		st := a.CreateElement("saml:AttributeStatement")
		names := make([]string, 0, len(r.Attributes))
		for k := range r.Attributes {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			at := st.CreateElement("saml:Attribute")
			at.CreateAttr("Name", k)
			at.CreateElement("saml:AttributeValue").SetText(r.Attributes[k])
		}
	}
	if !r.UnsignedAssertion {
		a = signer.sign(a, r.SHA1)
	}

	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", r.ID)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", ts(r.Now))
	resp.CreateAttr("Destination", r.Destination)
	if !r.OmitResponseInResponseTo {
		resp.CreateAttr("InResponseTo", r.InResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(r.Issuer)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", r.StatusCode)
	resp.AddChild(a)
	if r.SignResponse {
		resp = signer.sign(resp, r.SHA1)
	}
	return resp
}

// Bytes は要素を XML にする。
func Bytes(el *etree.Element) []byte {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return b
}

// Sign は応答の要素を作り、XML にする。
func (p *IdP) Sign(r Response) []byte { return Bytes(p.Element(r)) }

// Encoded は HTTP-POST の SAMLResponse（base64）を返す。
func (p *IdP) Encoded(r Response) string { return base64.StdEncoding.EncodeToString(p.Sign(r)) }

func (p *IdP) sign(el *etree.Element, sha1 bool) *etree.Element {
	ctx, err := dsig.NewSigningContext(p.Key, [][]byte{p.Cert.Raw})
	if err != nil {
		panic(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if sha1 {
		ctx.Hash = crypto.SHA1
		if err := ctx.SetSignatureMethod(dsig.RSASHA1SignatureMethod); err != nil {
			panic(err)
		}
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		panic(err)
	}
	return signed
}

func rnd() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
