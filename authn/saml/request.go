package saml

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/beevik/etree"
)

// AuthnRequest（HTTP-Redirect バインディング）と SP の鍵。

// newRequestID は AuthnRequest の ID（xs:ID なので英字か "_" で始める）。
func newRequestID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}

// authnRequest は AuthnRequest の XML を組み立てる。
func authnRequest(cfg Config, requestID string, now time.Time) ([]byte, error) {
	doc := etree.NewDocument()
	r := doc.CreateElement("samlp:AuthnRequest")
	r.CreateAttr("xmlns:samlp", nsProtocol)
	r.CreateAttr("xmlns:saml", nsAssertion)
	r.CreateAttr("ID", requestID)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", now.UTC().Format("2006-01-02T15:04:05Z"))
	r.CreateAttr("Destination", cfg.SSOURL)
	r.CreateAttr("AssertionConsumerServiceURL", cfg.ACSURL)
	r.CreateAttr("ProtocolBinding", bindingPOST)
	r.CreateElement("saml:Issuer").SetText(cfg.SPEntityID)
	p := r.CreateElement("samlp:NameIDPolicy")
	if cfg.NameIDFormat != "" {
		p.CreateAttr("Format", cfg.NameIDFormat)
	}
	p.CreateAttr("AllowCreate", "true")
	return doc.WriteToBytes()
}

// redirectURL は HTTP-Redirect バインディングの URL を作る（SAML Bindings 3.4）。key があれば署名する
// （SigAlg は ECDSA-SHA256。署名の値は XML 署名と同じく r||s）。
func redirectURL(ssoURL string, req []byte, relayState string, key *ecdsa.PrivateKey) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(req); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	// 署名する文字列は、この順に並べたパラメータそのもの（Bindings 3.4.4.1）。
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if key != nil {
		q += "&SigAlg=" + url.QueryEscape(algECDSASHA256)
		sum := sha256.Sum256([]byte(q))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			return "", err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	u, err := url.Parse(ssoURL)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += q
	return u.String(), nil
}

// spCertLifetime は SP の自己署名の証明書の有効期間（IdP に登録する鍵。証明書の期限で検証する IdP がある）。
const spCertLifetime = 10 * 365 * 24 * time.Hour

// newSPKey は SP の署名鍵（ECDSA P-256。ADR 0005）と自己署名の証明書（DER）を作る。
func newSPKey(entityID string, now time.Time) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	cn := entityID
	if len(cn) > 64 {
		cn = cn[:64]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(spCertLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// errNoKey は署名する設定なのに鍵が無いこと。
var errNoKey = errors.New("saml: the connection has no signing key")
