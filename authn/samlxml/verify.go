// Package samlxml は SAML 2.0 と WS-Federation が共通に使う XML の扱い（ADR 0098、0110、0115）。
//
//   - 受け取った XML の字句の確認（コメント・処理命令・DOCTYPE を拒み、深さと要素の数を限る）
//   - 要素を辿る小さな関数（名前空間で比べる。文字列は子の要素・コメントを含まない要素からだけ読む）
//   - enveloped の XML 署名の検証（goxmldsig。署名を確かめたバイト列から作り直した要素を返す。XML Signature Wrapping を防ぐ）
//   - realm の ES256 の鍵での XML 署名（署名の値は r||s）と、その自己署名の証明書
//
// SAML の SP（authn/saml）、SAML の IdP（authn/samlidp）、WS-Federation の IdP（authn/wsfed）が使う。
package samlxml

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// 名前空間とアルゴリズムの識別子。
const (
	NSDSig        = "http://www.w3.org/2000/09/xmldsig#"
	AlgExcC14N    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgEnveloped  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	AlgECDSA256   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgRSASHA256  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgRSASHA384  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgRSASHA512  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgECDSA384   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	AlgECDSA512   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	maxDepth      = 32
	maxElements   = 4096
	maxTextLength = 64 << 10
)

// SignatureMethods は受け付ける署名のアルゴリズム（SHA-1 は受けない）。
var SignatureMethods = map[string]bool{
	AlgRSASHA256: true, AlgRSASHA384: true, AlgRSASHA512: true,
	AlgECDSA256: true, AlgECDSA384: true, AlgECDSA512: true,
}

// DigestMethods は受け付けるダイジェストのアルゴリズム（SHA-1 は受けない）。
var DigestMethods = map[string]bool{
	"http://www.w3.org/2001/04/xmlenc#sha256":       true,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
	"http://www.w3.org/2001/04/xmlenc#sha512":       true,
}

// Scan は文書の字句を確かめる：コメント・処理命令（XML 宣言を除く）・DOCTYPE を拒み、深さと要素の数を限る。
// encoding/xml の往復で意味が変わる入力（名前空間の扱いの不具合）も拒む。エラーの文には prefix を付ける。
func Scan(raw []byte, prefix string) error {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("%s: xml round trip: %w", prefix, err)
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	depth, elements := 0, 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			if depth != 0 || elements == 0 {
				return fmt.Errorf("%s: truncated document", prefix)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: xml: %w", prefix, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			elements++
			if depth > maxDepth || elements > maxElements {
				return fmt.Errorf("%s: document too deep or too large", prefix)
			}
		case xml.EndElement:
			depth--
		case xml.Comment:
			return fmt.Errorf("%s: comments are not allowed", prefix)
		case xml.Directive:
			return fmt.Errorf("%s: directives are not allowed", prefix)
		case xml.ProcInst:
			if t.Target != "xml" || elements > 0 {
				return fmt.Errorf("%s: processing instructions are not allowed", prefix)
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return fmt.Errorf("%s: text outside the root element", prefix)
			}
		}
	}
}

// Parse は Scan で確かめた文書を読み、根の要素を返す。
func Parse(raw []byte, prefix string) (*etree.Element, error) {
	if err := Scan(raw, prefix); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", prefix, err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("%s: no root element", prefix)
	}
	return doc.Root(), nil
}

// CheckAlgorithm は XML 署名の要素のアルゴリズムを許したものに限る。SignedInfo は Reference がちょうど 1 つであること。
func CheckAlgorithm(el *etree.Element, prefix string) error {
	alg := el.SelectAttrValue("Algorithm", "")
	switch el.Tag {
	case "SignatureMethod":
		if !SignatureMethods[alg] {
			return fmt.Errorf("%s: signature method %q is not allowed", prefix, alg)
		}
	case "DigestMethod":
		if !DigestMethods[alg] {
			return fmt.Errorf("%s: digest method %q is not allowed", prefix, alg)
		}
	case "CanonicalizationMethod":
		if alg != AlgExcC14N {
			return fmt.Errorf("%s: canonicalization %q is not allowed", prefix, alg)
		}
	case "Transform":
		if alg != AlgExcC14N && alg != AlgEnveloped {
			return fmt.Errorf("%s: transform %q is not allowed", prefix, alg)
		}
	case "SignedInfo":
		if len(Children(el, NSDSig, "Reference")) != 1 {
			return fmt.Errorf("%s: a signature must have exactly one reference", prefix)
		}
	}
	return nil
}

// ValidateEnveloped は el に包まれた署名 sig（el の直下）を確かめ、署名を確かめたバイト列から作り直した要素を返す。
// Reference は el の ID を指すこと（空の URI で文書全体を指すものは受けない）。証明書は 1 つずつ試す
// （KeyInfo に証明書があれば、それが渡した証明書と一致すること。無ければ渡した証明書で確かめる）。証明書の期限は now で確かめる。
// アルゴリズムの制限（CheckAlgorithm）は呼ぶ側が文書全体に対して先に確かめる。
func ValidateEnveloped(el, sig *etree.Element, certs []*x509.Certificate, now time.Time) (*etree.Element, error) {
	elID := el.SelectAttrValue("ID", "")
	if elID == "" {
		return nil, errors.New("missing ID")
	}
	si, err := OneChild(sig, NSDSig, "SignedInfo")
	if err != nil {
		return nil, err
	}
	refs := Children(si, NSDSig, "Reference")
	if len(refs) != 1 || refs[0].SelectAttrValue("URI", "") != "#"+elID {
		return nil, errors.New("the reference does not point to the signed element")
	}
	nsctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	if nsctx, err = nsctx.SubContext(el); err != nil {
		return nil, err
	}
	detached, err := etreeutils.NSDetatch(nsctx, el)
	if err != nil {
		return nil, err
	}
	// 証明書の無い KeyInfo（KeyName・KeyValue だけのもの）は使わない。KeyInfo は SignedInfo の外にあり、外しても署名の範囲は変わらない。
	for _, s := range detached.ChildElements() {
		if !Is(s, NSDSig, "Signature") {
			continue
		}
		for _, ki := range Children(s, NSDSig, "KeyInfo") {
			if len(Descendants(ki, NSDSig, "X509Certificate")) == 0 {
				s.RemoveChild(ki)
			}
		}
	}
	var last error
	for _, cert := range certs {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		ctx.IdAttribute = "ID"
		ctx.Clock = dsig.NewFakeClockAt(now)
		verified, err := ctx.Validate(rawECDSAToDER(detached, cert))
		if err != nil {
			last = err
			continue
		}
		if verified == nil || verified.Tag != el.Tag || verified.NamespaceURI() != el.NamespaceURI() || verified.SelectAttrValue("ID", "") != elID {
			return nil, errors.New("the verified element differs from the signed one")
		}
		return verified, nil
	}
	if last == nil {
		last = errors.New("no certificate")
	}
	return nil, last
}

// rawECDSAToDER は、cert が ECDSA で、el の直下の署名の SignatureValue が XML 署名の形（r||s の固定長。RFC 4050、
// XML Signature 1.1 の 6.4.3）なら、goxmldsig が読む DER に直した写しを返す（それ以外は el のまま）。SignatureValue は
// SignedInfo の外にあり、書き換えても署名の範囲は変わらない。
func rawECDSAToDER(el *etree.Element, cert *x509.Certificate) *etree.Element {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return el
	}
	n := (pub.Curve.Params().BitSize + 7) / 8
	out := el.Copy()
	for _, s := range Children(out, NSDSig, "Signature") {
		for _, sv := range Children(s, NSDSig, "SignatureValue") {
			raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sv.Text()), ""))
			if err != nil || len(raw) != 2*n {
				continue
			}
			der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:n]), new(big.Int).SetBytes(raw[n:])})
			if err != nil {
				continue
			}
			sv.SetText(base64.StdEncoding.EncodeToString(der))
		}
	}
	return out
}

// Is は el が名前空間 ns の tag かを返す。
func Is(el *etree.Element, ns, tag string) bool {
	return el != nil && el.Tag == tag && el.NamespaceURI() == ns
}

// Children は el の直下の、名前空間 ns の tag の要素を返す。
func Children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if Is(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

// Descendants は el の子孫（el を含まない）のうち、名前空間 ns の tag の要素を返す。
func Descendants(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if Is(c, ns, tag) {
			out = append(out, c)
		}
		out = append(out, Descendants(c, ns, tag)...)
	}
	return out
}

// OptionalChild は直下の要素を返す（無ければ nil、2 つ以上ならエラー）。
func OptionalChild(el *etree.Element, ns, tag string) (*etree.Element, error) {
	cs := Children(el, ns, tag)
	if len(cs) > 1 {
		return nil, fmt.Errorf("saml: more than one %s", tag)
	}
	if len(cs) == 0 {
		return nil, nil
	}
	return cs[0], nil
}

// OneChild は直下にちょうど 1 つある要素を返す。
func OneChild(el *etree.Element, ns, tag string) (*etree.Element, error) {
	c, err := OptionalChild(el, ns, tag)
	if err == nil && c == nil {
		err = fmt.Errorf("saml: missing %s", tag)
	}
	return c, err
}

// TextOf は要素の文字列を返す（前後の空白を除く）。子の要素・コメントなどを含むものは受けない（一部の文字列だけを読むことの無いように）。
func TextOf(el *etree.Element) (string, error) {
	var b strings.Builder
	for _, t := range el.Child {
		cd, ok := t.(*etree.CharData)
		if !ok {
			return "", fmt.Errorf("saml: %s must contain only text", el.Tag)
		}
		b.WriteString(cd.Data)
		if b.Len() > maxTextLength {
			return "", fmt.Errorf("saml: %s is too long", el.Tag)
		}
	}
	return strings.TrimSpace(b.String()), nil
}

// TimeAttr は xs:dateTime の属性を読む。required で無ければ空を許す。
func TimeAttr(el *etree.Element, name string, required bool) (time.Time, error) {
	v := el.SelectAttrValue(name, "")
	if v == "" {
		if required {
			return time.Time{}, fmt.Errorf("saml: missing %s", name)
		}
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("saml: invalid %s", name)
	}
	return t, nil
}

// Same は a と b が等しく、空でないかを返す。
func Same(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
