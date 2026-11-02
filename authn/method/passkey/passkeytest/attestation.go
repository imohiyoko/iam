package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

// CA はテスト用の認証局（attestation の信頼の起点と、MDS の BLOB の署名のルート）。
type CA struct {
	Cert *x509.Certificate
	DER  []byte
	key  *ecdsa.PrivateKey
}

// 証明書の有効期間。ライブラリは実際の時刻で確かめるので、テストの時計に関わらず広く取る。
var (
	notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
)

func mustKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}
	return n
}

// NewCA は自己署名のルートを作る。
func NewCA(cn string) *CA {
	key := mustKey()
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn, Organization: []string{"Test"}, Country: []string{"JP"}},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &CA{Cert: cert, DER: der, key: key}
}

func (ca *CA) issue(tmpl *x509.Certificate) ([]byte, *ecdsa.PrivateKey) {
	key := mustKey()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		panic(err)
	}
	return der, key
}

// idFidoGenCeAAGUID は attestation の証明書に AAGUID を載せる拡張（WebAuthn §8.2.1）。
var idFidoGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// Packed は packed 形式の basic attestation（x5c 付き）。
type Packed struct {
	key   *ecdsa.PrivateKey
	chain [][]byte
}

// PackedAttestation は ca が発行した attestation の証明書で、aaguid の認証器の packed attestation を作る。
func (ca *CA) PackedAttestation(aaguid []byte) *Packed {
	ext, err := asn1.Marshal(aaguid)
	if err != nil {
		panic(err)
	}
	der, key := ca.issue(&x509.Certificate{SerialNumber: serial(),
		Subject:   pkix.Name{CommonName: "Test Authenticator", Organization: []string{"Test Vendor"}, OrganizationalUnit: []string{"Authenticator Attestation"}, Country: []string{"JP"}},
		NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true, IsCA: false,
		ExtraExtensions: []pkix.Extension{{Id: idFidoGenCeAAGUID, Value: ext}}})
	return &Packed{key: key, chain: [][]byte{der}}
}

func (p *Packed) statement(authData, clientDataHash []byte) map[string]any {
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		panic(err)
	}
	x5c := make([]any, 0, len(p.chain))
	for _, c := range p.chain {
		x5c = append(x5c, c)
	}
	return map[string]any{"alg": -7, "sig": sig, "x5c": x5c}
}

// MDSEntry は MDS3 の BLOB の項目（AAGUID の認証器。roots は attestation のルート、statuses は status report の状態）。
func MDSEntry(aaguid, description string, roots [][]byte, statuses ...string) map[string]any {
	var rs []string
	for _, r := range roots {
		rs = append(rs, base64.StdEncoding.EncodeToString(r))
	}
	var reports []map[string]any
	for _, s := range statuses {
		reports = append(reports, map[string]any{"status": s, "effectiveDate": "2020-01-01"})
	}
	return map[string]any{
		"aaguid": aaguid, "timeOfLastStatusChange": "2020-01-01", "statusReports": reports,
		"metadataStatement": map[string]any{
			"aaguid": aaguid, "description": description, "authenticatorVersion": 1, "protocolFamily": "fido2", "schema": 3,
			"upv": []map[string]any{{"major": 1, "minor": 0}}, "authenticationAlgorithms": []string{"secp256r1_ecdsa_sha256_raw"},
			"publicKeyAlgAndEncodings": []string{"cose"}, "attestationTypes": []string{"basic_full"},
			"userVerificationDetails": [][]map[string]any{{{"userVerificationMethod": "passcode_internal"}}},
			"keyProtection":           []string{"hardware"}, "matcherProtection": []string{"on_chip"}, "attachmentHint": []string{"external"},
			"tcDisplay": []string{}, "attestationRootCertificates": rs,
		},
	}
}

// MDSBlob は ca が発行した署名用の証明書で、MDS3 の BLOB（JWT。x5c は署名用の証明書と ca）を作る。
func (ca *CA) MDSBlob(number int, nextUpdate string, entries ...map[string]any) []byte {
	der, key := ca.issue(&x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Test MDS Signer"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature})
	if entries == nil {
		entries = []map[string]any{}
	}
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT",
		"x5c": []string{base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(ca.DER)}})
	p, _ := json.Marshal(map[string]any{"legalHeader": "test", "no": number, "nextUpdate": nextUpdate, "entries": entries})
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return []byte(signing + "." + enc.EncodeToString(sig))
}
