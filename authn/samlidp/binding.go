package samlidp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"math/big"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/samlxml"
)

// バインディング（SAML Bindings 3.4 の HTTP-Redirect と 3.5 の HTTP-POST）での受け渡し。ADR 0115。

const (
	// maxMessageBytes は SAML のメッセージ（展開した XML）の上限。
	maxMessageBytes = 64 << 10
	// maxEncodedBytes は base64 のメッセージの上限（HTTP-POST。展開前）。
	maxEncodedBytes = 128 << 10
	// MaxRelayStateLen は RelayState の上限（Bindings 3.4.3 は 80 バイトとするが、実装の多くが越えるので広めにとる）。
	MaxRelayStateLen = 1024
)

// 受け付ける HTTP-Redirect の SigAlg（SHA-1 は受けない）。
var redirectSigAlgs = map[string]crypto.Hash{
	samlxml.AlgRSASHA256: crypto.SHA256, samlxml.AlgRSASHA384: crypto.SHA384, samlxml.AlgRSASHA512: crypto.SHA512,
	samlxml.AlgECDSA256: crypto.SHA256, samlxml.AlgECDSA384: crypto.SHA384, samlxml.AlgECDSA512: crypto.SHA512,
}

// Message は受け取った SAML のメッセージ（AuthnRequest か LogoutRequest）。
type Message struct {
	// XML は展開した XML。
	XML []byte
	// RelayState はそのまま返す値。
	RelayState string
	// Binding は受け取ったバインディング。
	Binding string
	// redirectSig は HTTP-Redirect の署名（無ければ空）。signed は署名した文字列（Bindings 3.4.4.1）。
	sigAlg, redirectSig string
	signed              []byte
}

// SignedByQuery は HTTP-Redirect の署名（クエリの Signature）があるか。
func (m Message) SignedByQuery() bool { return m.redirectSig != "" }

// ErrBadMessage はメッセージを読めないこと（SP に戻さずに 400 にする）。
var ErrBadMessage = errBad("malformed saml message")

// DecodeRedirect は HTTP-Redirect の GET のクエリ（生のまま）からメッセージを読む。param は SAMLRequest か SAMLResponse。
// 署名した文字列は、受け取ったとおりの URL エンコードの値から作る（Bindings 3.4.4.1）。同じ引数が 2 回あるものは受けない。
func DecodeRedirect(rawQuery, param string) (Message, error) {
	if len(rawQuery) > maxEncodedBytes {
		return Message{}, ErrBadMessage
	}
	raw := map[string]string{}
	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			return Message{}, ErrBadMessage
		}
		switch key {
		case param, "RelayState", "SigAlg", "Signature":
			if _, dup := raw[key]; dup {
				return Message{}, ErrBadMessage
			}
			raw[key] = v
		}
	}
	m := Message{Binding: BindingRedirect}
	val := func(k string) (string, error) {
		v, err := url.QueryUnescape(raw[k])
		if err != nil {
			return "", ErrBadMessage
		}
		return v, nil
	}
	enc, err := val(param)
	if err != nil || enc == "" {
		return Message{}, ErrBadMessage
	}
	if m.RelayState, err = val("RelayState"); err != nil {
		return Message{}, err
	}
	if m.sigAlg, err = val("SigAlg"); err != nil {
		return Message{}, err
	}
	if m.redirectSig, err = val("Signature"); err != nil {
		return Message{}, err
	}
	if (m.sigAlg == "") != (m.redirectSig == "") {
		return Message{}, ErrBadMessage
	}
	if err := checkRelayState(m.RelayState); err != nil {
		return Message{}, err
	}
	if m.redirectSig != "" {
		s := param + "=" + raw[param]
		if _, ok := raw["RelayState"]; ok {
			s += "&RelayState=" + raw["RelayState"]
		}
		s += "&SigAlg=" + raw["SigAlg"]
		m.signed = []byte(s)
	}
	compressed, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return Message{}, ErrBadMessage
	}
	// DEFLATE を展開する（上限を越えるものは受けない。展開の爆弾を防ぐ）。
	r := flate.NewReader(bytes.NewReader(compressed))
	defer func() { _ = r.Close() }()
	xmlb, err := io.ReadAll(io.LimitReader(r, maxMessageBytes+1))
	if err != nil || len(xmlb) == 0 || len(xmlb) > maxMessageBytes {
		return Message{}, ErrBadMessage
	}
	m.XML = xmlb
	return m, nil
}

// DecodePOST は HTTP-POST のフォームの値からメッセージを読む（base64。DEFLATE しない）。
func DecodePOST(encoded, relayState string) (Message, error) {
	if encoded == "" || len(encoded) > maxEncodedBytes {
		return Message{}, ErrBadMessage
	}
	if err := checkRelayState(relayState); err != nil {
		return Message{}, err
	}
	xmlb, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil || len(xmlb) == 0 || len(xmlb) > maxMessageBytes {
		return Message{}, ErrBadMessage
	}
	return Message{XML: xmlb, RelayState: relayState, Binding: BindingPOST}, nil
}

func checkRelayState(s string) error {
	if len(s) > MaxRelayStateLen || !utf8.ValidString(s) || strings.ContainsFunc(s, isControl) {
		return ErrBadMessage
	}
	return nil
}

// verifyQuery は HTTP-Redirect の署名を SP の証明書のどれかで確かめる。ECDSA の値は XML 署名と同じ r||s を受け、DER も受ける。
func (m Message) verifyQuery(certs [][]byte) error {
	h, ok := redirectSigAlgs[m.sigAlg]
	if !ok {
		return errors.New("saml: SigAlg is not allowed")
	}
	sig, err := base64.StdEncoding.DecodeString(m.redirectSig)
	if err != nil || len(sig) == 0 {
		return errors.New("saml: invalid Signature")
	}
	digest := hashOf(h, m.signed)
	for _, der := range certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		switch k := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if strings.Contains(m.sigAlg, "rsa-") && rsa.VerifyPKCS1v15(k, h, digest, sig) == nil {
				return nil
			}
		case *ecdsa.PublicKey:
			if strings.Contains(m.sigAlg, "ecdsa-") && verifyECDSA(k, digest, sig) {
				return nil
			}
		}
	}
	return errors.New("saml: the query signature does not verify")
}

func hashOf(h crypto.Hash, b []byte) []byte {
	var f hash.Hash
	switch h {
	case crypto.SHA384:
		f = sha512.New384()
	case crypto.SHA512:
		f = sha512.New()
	default:
		f = sha256.New()
	}
	f.Write(b)
	return f.Sum(nil)
}

func verifyECDSA(k *ecdsa.PublicKey, digest, sig []byte) bool {
	n := (k.Curve.Params().BitSize + 7) / 8
	if len(sig) == 2*n {
		r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		return ecdsa.Verify(k, digest, r, s)
	}
	return ecdsa.VerifyASN1(k, digest, sig)
}

// EncodeRedirect は HTTP-Redirect の URL を作り、IdP の鍵で署名する（SigAlg は ECDSA-SHA256、値は r||s）。param は SAMLResponse など。
func EncodeRedirect(location, param string, xmlb []byte, relayState string, key *ecdsa.PrivateKey) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(xmlb); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(samlxml.AlgECDSA256)
	sum := sha256.Sum256([]byte(q))
	sig, err := samlxml.RawECDSA{Key: key}.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += q
	return u.String(), nil
}
