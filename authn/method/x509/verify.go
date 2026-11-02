package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// verified は確かめた証明書の要約（Preflight の結果。コアが Complete・EnrollComplete に渡す）。
type verified struct {
	Fingerprint string    `json:"fingerprint"`
	Lookup      string    `json:"lookup"`
	Identifier  string    `json:"identifier"`
	Hardware    bool      `json:"hardware"`
	PIN         bool      `json:"pin"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotAfter    time.Time `json:"not_after"`
}

// Fingerprint は証明書（DER）の SHA-256 を小文字の16進で返す。
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// parseChain は受け取った連鎖を読む。先頭が本人の証明書。数と大きさを限る。
func parseChain(chain [][]byte) ([]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, rejected("no client certificate")
	}
	if len(chain) > maxChainLength {
		return nil, rejected("certificate chain too long")
	}
	out := make([]*x509.Certificate, 0, len(chain))
	for _, der := range chain {
		if len(der) == 0 || len(der) > maxCertBytes {
			return nil, rejected("certificate too large")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, rejected("unparsable certificate")
		}
		out = append(out, c)
	}
	return out, nil
}

// checkKey は本人の証明書の鍵の種類と大きさを確かめる。
func checkKey(c *x509.Certificate) error {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return nil
		}
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
	case ed25519.PublicKey:
		return nil
	}
	return rejected("unsupported or weak key")
}

// checkUsage は本人の証明書の鍵用途（digitalSignature）と拡張鍵用途を確かめる。拡張鍵用途は明示を求める（無い・any は拒む）。
func (p *policy) checkUsage(c *x509.Certificate) (clientAuth bool, err error) {
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false, rejected("key usage lacks digitalSignature")
	}
	if c.IsCA {
		return false, rejected("CA certificate presented as client certificate")
	}
	if p.clientAuth && slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return true, nil
	}
	for _, want := range p.ekuOIDs {
		for _, got := range c.UnknownExtKeyUsage {
			if got.Equal(want) {
				return false, nil
			}
		}
	}
	return false, rejected("extended key usage not accepted")
}

// verify は連鎖・期限・用途を確かめ（失効は別）、確かめた連鎖を返す。
func (p *policy) verify(certs []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	leaf := certs[0]
	if err := checkKey(leaf); err != nil {
		return nil, err
	}
	clientAuth, err := p.checkUsage(leaf)
	if err != nil {
		return nil, err
	}
	inter := p.intermediates.Clone()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	// client_auth だけを受けるなら、連鎖の拡張鍵用途の入れ子も Go に確かめさせる。独自の OID は Go が知らないので、本人の証明書だけ確かめる。
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	if clientAuth && p.clientAuthOnly {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: inter, CurrentTime: now, KeyUsages: usages})
	if err != nil || len(chains) == 0 {
		return nil, rejected(fmt.Sprintf("chain verification failed: %v", err))
	}
	return chains[0], nil
}

// hardwareOf は、本人の証明書を直接発行した CA がハードウェアの鍵だけに発行する CA かを返す（主体と公開鍵で比べる。相互認証の
// 別の証明書でも同じ CA とみなす）。
func (p *policy) hardwareOf(chain []*x509.Certificate) (hw, pin bool) {
	if len(chain) < 2 {
		return false, false
	}
	issuer := chain[1]
	spki := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	for _, h := range p.hardware {
		if bytes.Equal(h.subject, issuer.RawSubject) && h.spki == spki {
			return true, h.pin
		}
	}
	return false, false
}

// identifier はマッピングの規則で、証明書を利用者に結び付ける値（検索キーの元）を返す。
func (p *policy) identifier(leaf *x509.Certificate) (string, error) {
	switch p.mapping {
	case MappingFingerprint:
		return Fingerprint(leaf.Raw), nil
	case MappingEmail:
		if len(leaf.EmailAddresses) != 1 {
			return "", rejected("certificate must carry exactly one email SAN")
		}
		return strings.ToLower(leaf.EmailAddresses[0]), nil
	case MappingUPN:
		upns, err := UPNs(leaf)
		if err != nil {
			return "", rejected("unparsable subject alternative name")
		}
		if len(upns) != 1 {
			return "", rejected("certificate must carry exactly one UPN SAN")
		}
		return strings.ToLower(upns[0]), nil
	case MappingSubjectDN:
		dn := leaf.Subject.String()
		if dn == "" {
			return "", rejected("certificate has an empty subject")
		}
		return dn, nil
	}
	return "", errors.New("x509: unknown mapping")
}

// lookupOf は規則と値から検索キーを作る（規則を変えたら前の登録とは一致しない）。
func lookupOf(rule, identifier string) string { return rule + ":" + identifier }

var (
	oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// UPNs は SAN の otherName のうち Microsoft の UPN（1.3.6.1.4.1.311.20.2.3、UTF8String）を返す。SAN の形が誤っていればエラー。
func UPNs(c *x509.Certificate) ([]string, error) {
	var out []string
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		v, err := parseSANUPNs(ext.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, v...)
	}
	return out, nil
}

// parseSANUPNs は SubjectAltName（GeneralNames）の DER から UPN を読む。otherName は
// [0] IMPLICIT SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }。
func parseSANUPNs(der []byte) ([]string, error) {
	in := cryptobyte.String(der)
	var names cryptobyte.String
	if !in.ReadASN1(&names, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errors.New("x509: malformed SAN")
	}
	var out []string
	for !names.Empty() {
		var name cryptobyte.String
		var tag cbasn1.Tag
		if !names.ReadAnyASN1(&name, &tag) {
			return nil, errors.New("x509: malformed general name")
		}
		if tag != cbasn1.Tag(0).ContextSpecific().Constructed() {
			continue
		}
		var oid asn1.ObjectIdentifier
		if !name.ReadASN1ObjectIdentifier(&oid) {
			return nil, errors.New("x509: malformed otherName")
		}
		var explicit cryptobyte.String
		if !name.ReadASN1(&explicit, cbasn1.Tag(0).ContextSpecific().Constructed()) || !name.Empty() {
			return nil, errors.New("x509: malformed otherName value")
		}
		if !oid.Equal(oidUPN) {
			continue
		}
		var s cryptobyte.String
		if !explicit.ReadASN1(&s, cbasn1.UTF8String) || !explicit.Empty() {
			return nil, errors.New("x509: UPN is not a UTF8String")
		}
		v := string(s)
		if v == "" || !utf8Valid(v) {
			return nil, errors.New("x509: invalid UPN")
		}
		out = append(out, v)
	}
	return out, nil
}

func utf8Valid(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
