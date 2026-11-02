package samlidp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	issuer   = "https://id.example.com"
	spEntity = "https://sp.example.com/metadata"
	spACS    = "https://sp.example.com/acs"
	spACS2   = "https://sp.example.com/acs2"
	spSLO    = "https://sp.example.com/slo"
)

// testSP はテスト用の SP（RSA の鍵と自己署名の証明書）。
type testSP struct {
	Key  *rsa.PrivateKey
	Cert []byte
}

func newTestSP(now time.Time) testSP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test sp"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return testSP{Key: key, Cert: der}
}

var (
	sp1 = newTestSP(testkit.T0)
	sp2 = newTestSP(testkit.T0)
)

func newService(t testing.TB) (*samlidp.Service, *testkit.Kit) {
	t.Helper()
	k := testkit.New(t)
	keys := &provider.Keys{Crypter: k.Crypter, Clock: k.Clock, RetiredKeyTTL: 24 * time.Hour}
	return &samlidp.Service{Storage: k.Storage, Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock, Keys: keys, Tokens: &provider.Tokens{},
		Issuer: issuer}, k
}

func validInput() samlidp.Input {
	return samlidp.Input{EntityID: spEntity, Name: "SP", Config: samlidp.Config{
		ACS:          []samlidp.Endpoint{{URL: spACS, Index: 0}, {URL: spACS2, Index: 3, Default: true}},
		SLO:          []samlidp.Endpoint{{URL: spSLO, Binding: samlidp.BindingRedirect}},
		SigningCerts: [][]byte{sp1.Cert}, SignAssertion: true,
		Attributes: []samlidp.Attribute{{Source: "user_id", Name: "urn:oid:0.9.2342.19200300.100.1.1", FriendlyName: "uid"},
			{Source: "amr", Name: "amr", NameFormat: samlidp.AttrNameFormatBasic}},
	}}
}

func create(t testing.TB, s *samlidp.Service, k *testkit.Kit, in samlidp.Input) port.SAMLServiceProvider {
	t.Helper()
	var sp port.SAMLServiceProvider
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		sp, err = s.Create(ctx, tx, k.RealmID, in, audit.Actor{Type: "operator", ID: "op"}, "req")
		return err
	})
	return sp
}

// authnReq は AuthnRequest の中身。
type authnReq struct {
	ID, Issuer, Destination string
	IssueInstant            time.Time
	ACSURL                  string
	ACSIndex                string
	ProtocolBinding         string
	ForceAuthn, IsPassive   bool
	NameIDFormat            string
	ClassRefs               []string
	Comparison              string
	Extra                   string // 根の最後に足す XML
}

func goodReq(now time.Time) authnReq {
	return authnReq{ID: "_req1", Issuer: spEntity, Destination: issuer + samlidp.SSOPath, IssueInstant: now}
}

func (r authnReq) xml() string {
	attrs := fmt.Sprintf(` ID="%s" Version="2.0" IssueInstant="%s"`, r.ID, r.IssueInstant.UTC().Format(time.RFC3339))
	if r.Destination != "" {
		attrs += fmt.Sprintf(` Destination="%s"`, r.Destination)
	}
	if r.ACSURL != "" {
		attrs += fmt.Sprintf(` AssertionConsumerServiceURL="%s"`, r.ACSURL)
	}
	if r.ACSIndex != "" {
		attrs += fmt.Sprintf(` AssertionConsumerServiceIndex="%s"`, r.ACSIndex)
	}
	if r.ProtocolBinding != "" {
		attrs += fmt.Sprintf(` ProtocolBinding="%s"`, r.ProtocolBinding)
	}
	if r.ForceAuthn {
		attrs += ` ForceAuthn="true"`
	}
	if r.IsPassive {
		attrs += ` IsPassive="1"`
	}
	body := fmt.Sprintf(`<saml:Issuer>%s</saml:Issuer>`, r.Issuer)
	if r.NameIDFormat != "" {
		body += fmt.Sprintf(`<samlp:NameIDPolicy Format="%s" AllowCreate="true"/>`, r.NameIDFormat)
	}
	if len(r.ClassRefs) > 0 {
		cmp := ""
		if r.Comparison != "" {
			cmp = fmt.Sprintf(` Comparison="%s"`, r.Comparison)
		}
		body += `<samlp:RequestedAuthnContext` + cmp + `>`
		for _, c := range r.ClassRefs {
			body += `<saml:AuthnContextClassRef>` + c + `</saml:AuthnContextClassRef>`
		}
		body += `</samlp:RequestedAuthnContext>`
	}
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		attrs + `>` + body + r.Extra + `</samlp:AuthnRequest>`
}

// signXML は根の要素に enveloped の署名（RSA-SHA256）を Issuer の後に入れる。
func signXML(t testing.TB, raw string, sp testSP) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatal(err)
	}
	ctx, err := dsig.NewSigningContext(sp.Key, [][]byte{sp.Cert})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	sig, err := ctx.ConstructSignature(root, true)
	if err != nil {
		t.Fatal(err)
	}
	root.InsertChildAt(root.ChildElements()[0].Index()+1, sig)
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// redirectQuery は HTTP-Redirect のクエリを作る。sp があれば署名する（sigAlg は RSA の識別子）。
func redirectQuery(t testing.TB, raw, relay string, sp *testSP, sigAlg string) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(raw))
	_ = w.Close()
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	if sp != nil {
		q += "&SigAlg=" + url.QueryEscape(sigAlg)
		h := crypto.SHA256
		sum := sha256.Sum256([]byte(q))
		sig, err := rsa.SignPKCS1v15(rand.Reader, sp.Key, h, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	return q
}

func postMessage(t testing.TB, raw, relay string) samlidp.Message {
	t.Helper()
	m, err := samlidp.DecodePOST(base64.StdEncoding.EncodeToString([]byte(raw)), relay)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func redirectMessage(t testing.TB, q string) samlidp.Message {
	t.Helper()
	m, err := samlidp.DecodeRedirect(q, "SAMLRequest")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
