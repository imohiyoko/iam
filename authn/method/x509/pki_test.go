package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ocsp"
)

// テスト用の PKI：ルート → 中間 → 本人。OCSP のレスポンダーと CRL の配布点を httptest で持つ。

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var serial int64 = 100

func nextSerial() *big.Int { serial++; return big.NewInt(serial) }

func create(t *testing.T, tmpl *x509.Certificate, parent *ca, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	p, signer := tmpl, key
	if parent != nil {
		p, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCA(t *testing.T, name string, parent *ca, crl ...string) *ca {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name}, NotBefore: t0.Add(-24 * time.Hour),
		NotAfter: t0.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: crl}
	return &ca{cert: create(t, tmpl, parent, k.Public(), k), key: k}
}

type leafOpts struct {
	cn       string
	eku      []x509.ExtKeyUsage
	ekuOIDs  []asn1.ObjectIdentifier
	emails   []string
	upns     []string
	notAfter time.Time
	ocsp     []string
	crl      []string
	isCA     bool
	ku       x509.KeyUsage
}

func newLeaf(t *testing.T, issuer *ca, o leafOpts) *x509.Certificate {
	t.Helper()
	k := newKey(t)
	if o.notAfter.IsZero() {
		o.notAfter = t0.Add(30 * 24 * time.Hour)
	}
	if o.eku == nil && o.ekuOIDs == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if o.ku == 0 {
		o.ku = x509.KeyUsageDigitalSignature
	}
	tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: o.cn, Organization: []string{"Example"}},
		NotBefore: t0.Add(-time.Hour), NotAfter: o.notAfter, KeyUsage: o.ku, ExtKeyUsage: o.eku, UnknownExtKeyUsage: o.ekuOIDs,
		EmailAddresses: o.emails, OCSPServer: o.ocsp, CRLDistributionPoints: o.crl, IsCA: o.isCA, BasicConstraintsValid: o.isCA}
	if len(o.upns) > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Value: sanWithUPNs(t, o.upns, o.emails)}}
		tmpl.EmailAddresses = nil
	}
	return create(t, tmpl, issuer, k.Public(), nil)
}

// sanWithUPNs は UPN の otherName（とメール）を持つ SAN を作る（Go の x509 は otherName を作れない）。
func sanWithUPNs(t *testing.T, upns, emails []string) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, u := range upns {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidUPN)
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(u)) })
				})
			})
		}
		for _, e := range emails {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes([]byte(e)) })
		}
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// newOCSPSigner は issuer が OCSP の署名を委ねる証明書を作る（eku が空なら委ねていない証明書）。応答の producedAt は
// x/crypto/ocsp が実の時刻で入れるので、有効期間は広く取る。
func newOCSPSigner(t *testing.T, issuer *ca, eku ...x509.ExtKeyUsage) *ca {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "OCSP"}, NotBefore: time.Unix(0, 0),
		NotAfter: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku}
	return &ca{cert: create(t, tmpl, issuer, k.Public(), nil), key: k}
}

// responder は OCSP のレスポンダーと CRL の配布点。
type responder struct {
	mu       sync.Mutex
	issuer   *ca
	signer   *ca // nil なら発行者が署名する。そうでなければ委ねた署名者（証明書を応答に埋め込む）
	revoked  map[string]bool
	unknown  bool
	down     bool
	requests int
	crlNext  time.Time
}

func newResponder(t *testing.T, issuer *ca) (*responder, *httptest.Server) {
	r := &responder{issuer: issuer, revoked: map[string]bool{}, crlNext: t0.Add(24 * time.Hour)}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return r, srv
}

func (r *responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests++
	if r.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if req.URL.Path == "/crl" {
		var entries []x509.RevocationListEntry
		for s := range r.revoked {
			n, _ := new(big.Int).SetString(s, 10)
			entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: t0.Add(-time.Hour)})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: t0.Add(-time.Hour),
			NextUpdate: r.crlNext, RevokedCertificateEntries: entries}, r.issuer.cert, r.issuer.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(der)
		return
	}
	body, _ := io.ReadAll(req.Body)
	oreq, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, "bad", 400)
		return
	}
	tmpl := ocsp.Response{SerialNumber: oreq.SerialNumber, Status: ocsp.Good, ThisUpdate: t0.Add(-time.Minute), NextUpdate: t0.Add(time.Hour)}
	if r.revoked[oreq.SerialNumber.String()] {
		tmpl.Status, tmpl.RevokedAt = ocsp.Revoked, t0.Add(-time.Hour)
	}
	if r.unknown {
		tmpl.Status = ocsp.Unknown
	}
	signer := r.issuer
	if r.signer != nil {
		signer, tmpl.Certificate = r.signer, r.signer.cert
	}
	der, err := ocsp.CreateResponse(r.issuer.cert, signer.cert, tmpl, signer.key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_, _ = w.Write(der)
}
