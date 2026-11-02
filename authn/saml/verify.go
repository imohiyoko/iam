package saml

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// SAML の応答（samlp:Response）の検証（ADR 0098）。セキュリティ上もっとも重要な部分で、不変条件は次のとおり。
//   - 署名を確かめた Assertion だけを使う。値は goxmldsig が返す「署名を確かめたバイト列から作り直した要素」からだけ読む
//     （XML Signature Wrapping で、署名した要素と読む要素をすり替えられないように）
//   - Assertion は文書全体でちょうど 1 つ（Advice・Extensions の中の Assertion も数える）。暗号化された Assertion は受けない
//   - 署名・ダイジェストは SHA-256 以上。正規化は Exclusive C14N（コメントを含まないもの）だけ。Reference は 1 つで Assertion の ID を指す
//   - コメント・処理命令・DOCTYPE を含む文書は受けない（コメントの挿入で NameID の読み方を変えられないように。XXE を防ぐ）
//   - Issuer・Audience・Recipient・Destination・InResponseTo・NotBefore / NotOnOrAfter（Clock）を確かめる

// 名前空間。
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
)

// 識別子。
const (
	statusSuccess    = "urn:oasis:names:tc:SAML:2.0:status:Success"
	cmBearer         = "urn:oasis:names:tc:SAML:2.0:cm:bearer" // #nosec G101 -- SAML の識別子で、秘密ではない
	nameIDTransient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	nameIDEmail      = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	nameIDEntity     = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	bindingRedirect  = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST      = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	algExcC14N       = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped     = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algECDSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	maxResponseBytes = 256 << 10
	maxDepth         = 32
	maxElements      = 4096
)

// MaxSkew は IdP との時刻のずれとして許す幅。
const MaxSkew = 3 * time.Minute

// 受け付ける署名とダイジェストのアルゴリズム（SHA-1 は受けない）。
var (
	allowedSignatureMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": true,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": true,
		algECDSASHA256: true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": true,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": true,
	}
	allowedDigestMethods = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256":       true,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512":       true,
	}
)

// Expect は応答に求める値。
type Expect struct {
	IdPEntityID string
	Certs       []*x509.Certificate
	SPEntityID  string
	ACSURL      string
	// RequestID は AuthnRequest の ID（InResponseTo と比べる）。IdP からの一方的な応答は受けない。
	RequestID string
	Now       time.Time
}

// Assertion は確かめた Assertion のうち使うもの。
type Assertion struct {
	ID           string
	NameID       string
	NameIDFormat string
	Attributes   map[string][]string
	// Expires は、これより後には同じ Assertion を受け付けない時刻（ID の再利用の拒否に使う）。
	Expires time.Time
}

// Verify は samlp:Response（XML）を確かめ、署名を確かめた Assertion を返す。理由は内部向け（外には返さない）。
func Verify(raw []byte, e Expect) (Assertion, error) {
	if e.IdPEntityID == "" || len(e.Certs) == 0 || e.SPEntityID == "" || e.ACSURL == "" || e.RequestID == "" {
		return Assertion{}, errors.New("saml: incomplete expectation")
	}
	if len(raw) > maxResponseBytes {
		return Assertion{}, errors.New("saml: response too large")
	}
	if err := scan(raw); err != nil {
		return Assertion{}, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return Assertion{}, fmt.Errorf("saml: parse: %w", err)
	}
	root := doc.Root()
	if !is(root, nsProtocol, "Response") {
		return Assertion{}, errors.New("saml: not a Response")
	}
	if err := checkDocument(root); err != nil {
		return Assertion{}, err
	}
	if root.SelectAttrValue("Version", "") != "2.0" {
		return Assertion{}, errors.New("saml: unsupported version")
	}
	if !same(root.SelectAttrValue("Destination", ""), e.ACSURL) {
		return Assertion{}, errors.New("saml: destination mismatch")
	}
	if !same(root.SelectAttrValue("InResponseTo", ""), e.RequestID) {
		return Assertion{}, errors.New("saml: response InResponseTo mismatch")
	}
	if iss, err := optionalChild(root, nsAssertion, "Issuer"); err != nil {
		return Assertion{}, err
	} else if iss != nil {
		if err := checkIssuer(iss, e.IdPEntityID); err != nil {
			return Assertion{}, err
		}
	}
	if err := checkStatus(root); err != nil {
		return Assertion{}, err
	}
	// 応答そのものの署名は任意。あれば確かめる（失敗なら受けない）。
	if sig, err := optionalChild(root, nsDSig, "Signature"); err != nil {
		return Assertion{}, err
	} else if sig != nil {
		if _, err := validate(e, root, sig); err != nil {
			return Assertion{}, fmt.Errorf("saml: response signature: %w", err)
		}
	}
	assertions := children(root, nsAssertion, "Assertion")
	if len(assertions) != 1 {
		return Assertion{}, errors.New("saml: the response must contain exactly one assertion")
	}
	sig, err := optionalChild(assertions[0], nsDSig, "Signature")
	if err != nil {
		return Assertion{}, err
	}
	if sig == nil {
		return Assertion{}, errors.New("saml: the assertion is not signed")
	}
	if n := len(descendants(assertions[0], nsDSig, "Signature")); n != 1 {
		return Assertion{}, errors.New("saml: the assertion must contain exactly one signature")
	}
	verified, err := validate(e, assertions[0], sig)
	if err != nil {
		return Assertion{}, fmt.Errorf("saml: assertion signature: %w", err)
	}
	return readAssertion(verified, e)
}

// scan は文書の字句を確かめる：コメント・処理命令（XML 宣言を除く）・DOCTYPE を拒み、深さと要素の数を限る。
// encoding/xml の往復で意味が変わる入力（名前空間の扱いの不具合）も拒む。
func scan(raw []byte) error {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("saml: xml round trip: %w", err)
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	depth, elements := 0, 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			if depth != 0 || elements == 0 {
				return errors.New("saml: truncated document")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("saml: xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			elements++
			if depth > maxDepth || elements > maxElements {
				return errors.New("saml: document too deep or too large")
			}
		case xml.EndElement:
			depth--
		case xml.Comment:
			return errors.New("saml: comments are not allowed")
		case xml.Directive:
			return errors.New("saml: directives are not allowed")
		case xml.ProcInst:
			if t.Target != "xml" || elements > 0 {
				return errors.New("saml: processing instructions are not allowed")
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return errors.New("saml: text outside the root element")
			}
		}
	}
}

// checkDocument は文書全体を見る：Assertion はちょうど 1 つ（入れ子も数える）、暗号化された要素は受けない、ID は重ならない、
// 署名のアルゴリズムは許したものだけ。
func checkDocument(root *etree.Element) error {
	ids := map[string]bool{}
	assertions := 0
	var walk func(el *etree.Element) error
	walk = func(el *etree.Element) error {
		ns := el.NamespaceURI()
		switch {
		case ns == nsAssertion && el.Tag == "Assertion":
			assertions++
		case ns == nsAssertion && (el.Tag == "EncryptedAssertion" || el.Tag == "EncryptedID" || el.Tag == "EncryptedAttribute"):
			return errors.New("saml: encrypted elements are not supported")
		case ns == nsDSig:
			if err := checkAlgorithm(el); err != nil {
				return err
			}
		}
		if v := el.SelectAttrValue("ID", ""); v != "" {
			if ids[v] {
				return errors.New("saml: duplicate ID")
			}
			ids[v] = true
		}
		for _, c := range el.ChildElements() {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return err
	}
	if assertions != 1 {
		return errors.New("saml: the document must contain exactly one assertion")
	}
	return nil
}

// checkAlgorithm は XML 署名の要素のアルゴリズムを許したものに限る。
func checkAlgorithm(el *etree.Element) error {
	alg := el.SelectAttrValue("Algorithm", "")
	switch el.Tag {
	case "SignatureMethod":
		if !allowedSignatureMethods[alg] {
			return fmt.Errorf("saml: signature method %q is not allowed", alg)
		}
	case "DigestMethod":
		if !allowedDigestMethods[alg] {
			return fmt.Errorf("saml: digest method %q is not allowed", alg)
		}
	case "CanonicalizationMethod":
		if alg != algExcC14N {
			return fmt.Errorf("saml: canonicalization %q is not allowed", alg)
		}
	case "Transform":
		if alg != algExcC14N && alg != algEnveloped {
			return fmt.Errorf("saml: transform %q is not allowed", alg)
		}
	case "SignedInfo":
		if len(children(el, nsDSig, "Reference")) != 1 {
			return errors.New("saml: a signature must have exactly one reference")
		}
	}
	return nil
}

// validate は el に包まれた署名 sig（el の直下）を確かめ、署名を確かめたバイト列から作り直した要素を返す。
// Reference は el の ID を指すこと（空の URI で文書全体を指すものは受けない）。証明書は 1 つずつ試す
// （KeyInfo に証明書があれば、それが登録した証明書と一致すること。無ければ登録した証明書で確かめる）。
func validate(e Expect, el, sig *etree.Element) (*etree.Element, error) {
	elID := el.SelectAttrValue("ID", "")
	if elID == "" {
		return nil, errors.New("missing ID")
	}
	si, err := oneChild(sig, nsDSig, "SignedInfo")
	if err != nil {
		return nil, err
	}
	refs := children(si, nsDSig, "Reference")
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
		if !is(s, nsDSig, "Signature") {
			continue
		}
		for _, ki := range children(s, nsDSig, "KeyInfo") {
			if len(descendants(ki, nsDSig, "X509Certificate")) == 0 {
				s.RemoveChild(ki)
			}
		}
	}
	var last error
	for _, cert := range e.Certs {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		ctx.IdAttribute = "ID"
		ctx.Clock = dsig.NewFakeClockAt(e.Now)
		verified, err := ctx.Validate(detached)
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

// readAssertion は署名を確かめた Assertion の中身を確かめて読む。
func readAssertion(a *etree.Element, e Expect) (Assertion, error) {
	out := Assertion{ID: a.SelectAttrValue("ID", ""), Attributes: map[string][]string{}}
	if a.SelectAttrValue("Version", "") != "2.0" || out.ID == "" {
		return Assertion{}, errors.New("saml: invalid assertion")
	}
	if len(descendants(a, nsAssertion, "Assertion")) > 0 {
		return Assertion{}, errors.New("saml: nested assertion")
	}
	if t, err := timeAttr(a, "IssueInstant", true); err != nil {
		return Assertion{}, err
	} else if t.After(e.Now.Add(MaxSkew)) {
		return Assertion{}, errors.New("saml: assertion issued in the future")
	}
	iss, err := oneChild(a, nsAssertion, "Issuer")
	if err != nil {
		return Assertion{}, err
	}
	if err := checkIssuer(iss, e.IdPEntityID); err != nil {
		return Assertion{}, err
	}
	subj, err := oneChild(a, nsAssertion, "Subject")
	if err != nil {
		return Assertion{}, err
	}
	if len(children(subj, nsAssertion, "BaseID"))+len(children(subj, nsAssertion, "EncryptedID")) > 0 {
		return Assertion{}, errors.New("saml: unsupported subject identifier")
	}
	nameID, err := oneChild(subj, nsAssertion, "NameID")
	if err != nil {
		return Assertion{}, err
	}
	if out.NameID, err = textOf(nameID); err != nil {
		return Assertion{}, err
	}
	out.NameIDFormat = nameID.SelectAttrValue("Format", "")
	switch {
	case out.NameID == "" || len(out.NameID) > 255:
		return Assertion{}, errors.New("saml: invalid NameID")
	case out.NameIDFormat == nameIDTransient:
		// 毎回変わる識別子では、同じ人を見分けられない。
		return Assertion{}, errors.New("saml: transient NameID cannot identify a user")
	case nameID.SelectAttrValue("SPNameQualifier", e.SPEntityID) != e.SPEntityID:
		return Assertion{}, errors.New("saml: NameID is for another SP")
	}
	confirmed, err := confirm(subj, e)
	if err != nil {
		return Assertion{}, err
	}
	out.Expires = confirmed
	cond, err := oneChild(a, nsAssertion, "Conditions")
	if err != nil {
		return Assertion{}, err
	}
	until, err := checkConditions(cond, e)
	if err != nil {
		return Assertion{}, err
	}
	if !until.IsZero() && until.Before(out.Expires) {
		out.Expires = until
	}
	authn := children(a, nsAssertion, "AuthnStatement")
	if len(authn) == 0 {
		return Assertion{}, errors.New("saml: no AuthnStatement")
	}
	for _, s := range authn {
		t, err := timeAttr(s, "SessionNotOnOrAfter", false)
		if err != nil {
			return Assertion{}, err
		}
		if !t.IsZero() && !e.Now.Before(t.Add(MaxSkew)) {
			return Assertion{}, errors.New("saml: IdP session expired")
		}
	}
	for _, st := range children(a, nsAssertion, "AttributeStatement") {
		for _, attr := range children(st, nsAssertion, "Attribute") {
			name := attr.SelectAttrValue("Name", "")
			if name == "" {
				continue
			}
			for _, v := range children(attr, nsAssertion, "AttributeValue") {
				// 値が要素を含むもの（複合の値）は使わない。
				if s, err := textOf(v); err == nil {
					out.Attributes[name] = append(out.Attributes[name], s)
				}
			}
		}
	}
	return out, nil
}

// confirm は bearer の SubjectConfirmation のうち、条件をすべて満たすものがあるかを確かめ、その期限を返す。
func confirm(subj *etree.Element, e Expect) (time.Time, error) {
	for _, sc := range children(subj, nsAssertion, "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != cmBearer {
			continue
		}
		data, err := oneChild(sc, nsAssertion, "SubjectConfirmationData")
		if err != nil {
			continue
		}
		until, err := timeAttr(data, "NotOnOrAfter", true)
		if err != nil {
			continue
		}
		// bearer の確認には NotBefore を付けない（SAML Profiles 4.1.4.2）。
		if data.SelectAttr("NotBefore") != nil {
			continue
		}
		if !same(data.SelectAttrValue("Recipient", ""), e.ACSURL) || !same(data.SelectAttrValue("InResponseTo", ""), e.RequestID) {
			continue
		}
		if !e.Now.Before(until.Add(MaxSkew)) {
			continue
		}
		return until.Add(MaxSkew), nil
	}
	return time.Time{}, errors.New("saml: no valid bearer subject confirmation")
}

// checkConditions は Conditions を確かめ、NotOnOrAfter（あれば。ずれの幅を足したもの）を返す。
func checkConditions(c *etree.Element, e Expect) (time.Time, error) {
	nb, err := timeAttr(c, "NotBefore", false)
	if err != nil {
		return time.Time{}, err
	}
	na, err := timeAttr(c, "NotOnOrAfter", false)
	if err != nil {
		return time.Time{}, err
	}
	if !nb.IsZero() && e.Now.Before(nb.Add(-MaxSkew)) {
		return time.Time{}, errors.New("saml: assertion not yet valid")
	}
	if !na.IsZero() && !e.Now.Before(na.Add(MaxSkew)) {
		return time.Time{}, errors.New("saml: assertion expired")
	}
	restrictions := 0
	for _, el := range c.ChildElements() {
		if el.NamespaceURI() != nsAssertion {
			return time.Time{}, errors.New("saml: unknown condition")
		}
		switch el.Tag {
		case "AudienceRestriction":
			restrictions++
			ok := false
			for _, aud := range children(el, nsAssertion, "Audience") {
				if s, err := textOf(aud); err == nil && same(s, e.SPEntityID) {
					ok = true
				}
			}
			if !ok {
				return time.Time{}, errors.New("saml: audience mismatch")
			}
		case "OneTimeUse", "ProxyRestriction":
			// OneTimeUse は ID の再利用の拒否で満たす。ProxyRestriction は再発行しないので関係しない。
		default:
			return time.Time{}, errors.New("saml: unknown condition")
		}
	}
	if restrictions == 0 {
		return time.Time{}, errors.New("saml: no audience restriction")
	}
	if na.IsZero() {
		return time.Time{}, nil
	}
	return na.Add(MaxSkew), nil
}

func checkIssuer(iss *etree.Element, want string) error {
	s, err := textOf(iss)
	if err != nil {
		return err
	}
	if f := iss.SelectAttrValue("Format", nameIDEntity); f != nameIDEntity || !same(s, want) {
		return errors.New("saml: issuer mismatch")
	}
	return nil
}

func checkStatus(root *etree.Element) error {
	st, err := oneChild(root, nsProtocol, "Status")
	if err != nil {
		return err
	}
	code, err := oneChild(st, nsProtocol, "StatusCode")
	if err != nil {
		return err
	}
	if code.SelectAttrValue("Value", "") != statusSuccess {
		return errors.New("saml: the IdP returned an error status")
	}
	return nil
}

// is は el が名前空間 ns の tag かを返す。
func is(el *etree.Element, ns, tag string) bool {
	return el != nil && el.Tag == tag && el.NamespaceURI() == ns
}

// children は el の直下の、名前空間 ns の tag の要素を返す。
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

// descendants は el の子孫（el を含まない）のうち、名前空間 ns の tag の要素を返す。
func descendants(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
		out = append(out, descendants(c, ns, tag)...)
	}
	return out
}

// optionalChild は直下の要素を返す（無ければ nil、2 つ以上ならエラー）。
func optionalChild(el *etree.Element, ns, tag string) (*etree.Element, error) {
	cs := children(el, ns, tag)
	if len(cs) > 1 {
		return nil, fmt.Errorf("saml: more than one %s", tag)
	}
	if len(cs) == 0 {
		return nil, nil
	}
	return cs[0], nil
}

// oneChild は直下にちょうど 1 つある要素を返す。
func oneChild(el *etree.Element, ns, tag string) (*etree.Element, error) {
	c, err := optionalChild(el, ns, tag)
	if err == nil && c == nil {
		err = fmt.Errorf("saml: missing %s", tag)
	}
	return c, err
}

// textOf は要素の文字列を返す。子の要素・コメントなどを含むものは受けない（一部の文字列だけを読むことの無いように）。
func textOf(el *etree.Element) (string, error) {
	var b strings.Builder
	for _, t := range el.Child {
		cd, ok := t.(*etree.CharData)
		if !ok {
			return "", fmt.Errorf("saml: %s must contain only text", el.Tag)
		}
		b.WriteString(cd.Data)
	}
	return strings.TrimSpace(b.String()), nil
}

// timeAttr は xs:dateTime の属性を読む。required で無ければ空を許す。
func timeAttr(el *etree.Element, name string, required bool) (time.Time, error) {
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

// same は a と b が等しく、空でないかを返す。
func same(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
