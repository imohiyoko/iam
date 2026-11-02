package samlidp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- RSA-OAEP（rsa-oaep-mgf1p）の既定のハッシュ。OAEP の安全性は衝突への強さに依らない（ADR 0115）
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// Response（SAML Core 3.3.3）と Assertion の組み立て、署名と暗号化（ADR 0115）。

const (
	cmBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer" // #nosec G101 -- SAML の識別子

	nsXEnc         = "http://www.w3.org/2001/04/xmlenc#"
	xencElement    = "http://www.w3.org/2001/04/xmlenc#Element"
	xencAES128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	xencRSAOAEP    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	dsigSHA1Digest = "http://www.w3.org/2000/09/xmldsig#sha1"
)

func xmlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// newID は Response・Assertion などの ID（xs:ID なので "_" で始める。160 bit の乱数）。
func newID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}

// sessionIndex は SP ごとの SessionIndex（ログインの系列 sid と SP から作る。SP をまたいで同じ値にしない）。
func sessionIndex(spID, sid string) string {
	h := sha256.Sum256([]byte("iam-saml-idp-session-index\x00" + spID + "\x00" + sid))
	return "_" + hex.EncodeToString(h[:20])
}

// attribute は SP に出す属性。
type attribute struct {
	Attribute
	Values []string
}

// assertion は Assertion の中身。
type assertion struct {
	ID, Issuer, Audience, Recipient, InResponseTo string
	NameID, NameIDFormat                          string
	SessionIndex, ClassRef                        string
	IssuedAt, Expires, AuthTime                   time.Time
	Attrs                                         []attribute
}

// element は Assertion を組み立てる（署名は Issuer の後に入れる）。
func (a assertion) element() *etree.Element {
	el := etree.NewElement("saml:Assertion")
	el.CreateAttr("xmlns:saml", nsAssertion)
	el.CreateAttr("ID", a.ID)
	el.CreateAttr("IssueInstant", xmlTime(a.IssuedAt))
	el.CreateAttr("Version", "2.0")
	el.CreateElement("saml:Issuer").SetText(a.Issuer)
	s := el.CreateElement("saml:Subject")
	n := s.CreateElement("saml:NameID")
	n.CreateAttr("Format", a.NameIDFormat)
	n.SetText(a.NameID)
	sc := s.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", cmBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	if a.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", a.InResponseTo)
	}
	scd.CreateAttr("NotOnOrAfter", xmlTime(a.Expires))
	scd.CreateAttr("Recipient", a.Recipient)
	cond := el.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", xmlTime(a.IssuedAt))
	cond.CreateAttr("NotOnOrAfter", xmlTime(a.Expires))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(a.Audience)
	au := el.CreateElement("saml:AuthnStatement")
	au.CreateAttr("AuthnInstant", xmlTime(a.AuthTime))
	au.CreateAttr("SessionIndex", a.SessionIndex)
	au.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(a.ClassRef)
	if len(a.Attrs) > 0 {
		st := el.CreateElement("saml:AttributeStatement")
		for _, at := range a.Attrs {
			x := st.CreateElement("saml:Attribute")
			x.CreateAttr("Name", at.Name)
			x.CreateAttr("NameFormat", at.NameFormat)
			if at.FriendlyName != "" {
				x.CreateAttr("FriendlyName", at.FriendlyName)
			}
			for _, v := range at.Values {
				x.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	return el
}

// response は samlp:Response を組み立てる。body は Assertion か EncryptedAssertion（失敗なら nil）。
func response(id, issuer, dest, inResponseTo string, now time.Time, st *StatusError, body *etree.Element) *etree.Element {
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", nsProtocol)
	r.CreateAttr("xmlns:saml", nsAssertion)
	r.CreateAttr("ID", id)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", xmlTime(now))
	r.CreateAttr("Destination", dest)
	if inResponseTo != "" {
		r.CreateAttr("InResponseTo", inResponseTo)
	}
	r.CreateElement("saml:Issuer").SetText(issuer)
	status(r, st)
	if body != nil {
		r.AddChild(body)
	}
	return r
}

// status は samlp:Status を足す（st が nil なら Success）。
func status(parent *etree.Element, st *StatusError) {
	stEl := parent.CreateElement("samlp:Status")
	sc := stEl.CreateElement("samlp:StatusCode")
	if st == nil {
		sc.CreateAttr("Value", StatusSuccess)
		return
	}
	sc.CreateAttr("Value", st.Code)
	if st.Sub != "" {
		sc.CreateElement("samlp:StatusCode").CreateAttr("Value", st.Sub)
	}
	if st.Msg != "" {
		stEl.CreateElement("samlp:StatusMessage").SetText(st.Msg)
	}
}

// encrypt は Assertion を SP の証明書（RSA）へ暗号化した EncryptedAssertion を作る。内容の暗号は AES-128-GCM、
// 鍵の運搬は RSA-OAEP（rsa-oaep-mgf1p、SHA-1）。CBC は使わない（パディングオラクル）。
func encrypt(a *etree.Element, certDER []byte) (*etree.Element, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("samlidp: the encryption certificate is not RSA")
	}
	doc := etree.NewDocument()
	doc.SetRoot(a.Copy())
	plain, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// XML Encryption 1.1 の AES-GCM：CipherValue は IV || 暗号文 || タグ。
	ct := gcm.Seal(nonce, nonce, plain, nil)
	ek, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil) // #nosec G401 -- rsa-oaep-mgf1p の既定（上の説明）
	if err != nil {
		return nil, err
	}
	ea := etree.NewElement("saml:EncryptedAssertion")
	ea.CreateAttr("xmlns:saml", nsAssertion)
	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", nsXEnc)
	ed.CreateAttr("Type", xencElement)
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", xencAES128GCM)
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", samlxml.NSDSig)
	k := ki.CreateElement("xenc:EncryptedKey")
	em := k.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", xencRSAOAEP)
	em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", dsigSHA1Digest)
	k.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(certDER))
	k.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ek))
	ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(ct))
	return ea, nil
}

// Subject は Assertion に載せる本人（ブラウザのセッションから）。
type Subject struct {
	// UserID と OrgID は内部 ID（OrgID は空なら Org なし）。SID はログインの系列。
	UserID, OrgID, SID string
	AuthTime           time.Time
	AMR                []string
}

// Issued は SP の ACS に POST する値。
type Issued struct {
	ACS, SAMLResponse, RelayState string
	ResponseID, AssertionID       string
}

// errNoNameID は NameID の値が無い（確認済みのメールが無いなど）こと。
var errNoNameID = statusErr(StatusResponder, StatusInvalidNameID, "the user has no value for the configured NameID")

// Issue は SP に Assertion を入れた Response を発行する（監査ログ saml_idp.assertion_issued）。sp・cfg は Recheck で確かめたもの、
// classRef は SelectClassRef で選んだもの。NameID の値が無ければ *StatusError を返す（呼ぶ側が IssueError で返す）。
func (s *Service) Issue(ctx context.Context, sp port.SAMLServiceProvider, cfg Config, p Pending, sub Subject, classRef, requestID string) (Issued, error) {
	format := p.NameIDFormat
	if format == "" {
		format = cfg.NameIDFormat
	}
	needEmail := cfg.NameIDSource == SourceEmail || slices.ContainsFunc(cfg.Attributes, func(a Attribute) bool { return a.Source == SourceEmail })
	needAttrs := s.Attributes && (strings.HasPrefix(cfg.NameIDSource, SourceAttributePrefix) ||
		slices.ContainsFunc(cfg.Attributes, func(a Attribute) bool { return strings.HasPrefix(a.Source, SourceAttributePrefix) }))
	rid, err := newID()
	if err != nil {
		return Issued{}, err
	}
	aid, err := newID()
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		vals, err := s.Tokens.SubjectClaims(ctx, tx, p.RealmID, sub.UserID, sub.OrgID, needEmail, needAttrs)
		if err != nil {
			return err
		}
		subject, _ := vals["sub"].(string)
		if subject == "" {
			return errors.New("samlidp: no subject for user")
		}
		nameID, err := s.nameID(format, cfg.NameIDSource, vals)
		if err != nil {
			return err
		}
		key, cert, err := s.signer(ctx, tx, p.RealmID)
		if err != nil {
			return err
		}
		now := s.Clock.Now()
		a := assertion{ID: aid, Issuer: s.Issuer, Audience: sp.EntityID, Recipient: p.ACS, InResponseTo: p.RequestID, NameID: nameID, NameIDFormat: format,
			SessionIndex: sessionIndex(sp.ID, sub.SID), ClassRef: classRef, IssuedAt: now, Expires: now.Add(time.Duration(cfg.AssertionLifetime) * time.Second),
			AuthTime: sub.AuthTime, Attrs: attributes(cfg.Attributes, vals, sub.AMR, s.Attributes)}
		body := a.element()
		if cfg.SignAssertion {
			if err := samlxml.SignAt(body, key, cert, "ID", 1); err != nil {
				return err
			}
		}
		if len(cfg.EncryptionCert) > 0 {
			if body, err = encrypt(body, cfg.EncryptionCert); err != nil {
				return err
			}
		}
		raw, err := s.finish(response(rid, s.Issuer, p.ACS, p.RequestID, now, nil, body), cfg.SignResponse, key, cert)
		if err != nil {
			return err
		}
		out = Issued{ACS: p.ACS, SAMLResponse: base64.StdEncoding.EncodeToString(raw), RelayState: p.RelayState, ResponseID: rid, AssertionID: aid}
		orgID, _ := vals["org_id"].(string)
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "saml_idp.assertion_issued", Result: audit.ResultSuccess, RealmID: p.RealmID, OrgID: orgID,
			Actor: audit.Actor{Type: "user", ID: subject}, SessionID: sub.SID, RequestID: requestID,
			Details: map[string]any{"service_provider_id": sp.ID, "entity_id": sp.EntityID, "assertion_id": aid, "response_id": rid,
				"in_response_to": p.RequestID, "idp_initiated": p.RequestID == "", "name_id_format": format, "authn_context": classRef,
				"encrypted": len(cfg.EncryptionCert) > 0},
		})
		return err
	})
	return out, err
}

// IssueError は失敗の Response（Assertion なし。いつも署名する）を作る。SP と ACS を確かめた後の誤りにだけ使う。
func (s *Service) IssueError(ctx context.Context, p Pending, st *StatusError) (Issued, error) {
	rid, err := newID()
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		key, cert, err := s.signer(ctx, tx, p.RealmID)
		if err != nil {
			return err
		}
		raw, err := s.finish(response(rid, s.Issuer, p.ACS, p.RequestID, s.Clock.Now(), st, nil), true, key, cert)
		if err != nil {
			return err
		}
		out = Issued{ACS: p.ACS, SAMLResponse: base64.StdEncoding.EncodeToString(raw), RelayState: p.RelayState, ResponseID: rid}
		return nil
	})
	return out, err
}

// finish は Response に署名し（sign のとき。Issuer の後に入れる）、XML にする。
func (s *Service) finish(r *etree.Element, sign bool, key *ecdsa.PrivateKey, cert []byte) ([]byte, error) {
	if sign {
		if err := samlxml.SignAt(r, key, cert, "ID", 1); err != nil {
			return nil, err
		}
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(r)
	return doc.WriteToBytes()
}

// nameID は NameID の値を決める。transient は毎回の乱数。値が無ければ errNoNameID。
func (s *Service) nameID(format, source string, vals map[string]any) (string, error) {
	if format == NameIDTransient {
		return newID()
	}
	var vs []string
	switch {
	case source == SourceUserID:
		vs = scalar(vals["sub"])
	case source == SourceEmail:
		// SAML には email_verified が無い。確認済みのものだけを出す（ADR 0115。0110 と同じ）。
		if v, _ := vals["email_verified"].(bool); v {
			vs = scalar(vals["email"])
		}
	case s.Attributes && strings.HasPrefix(source, SourceAttributePrefix):
		m, _ := vals["attributes"].(map[string]any)
		vs = scalar(m[strings.TrimPrefix(source, SourceAttributePrefix)])
	}
	if len(vs) != 1 || vs[0] == "" || len(vs[0]) > 256 {
		return "", errNoNameID
	}
	return vs[0], nil
}

// attributes は属性の対応から属性を作る。値の無いもの（未確認のメール、Org なし、属性が無いなど）は出さない。
func attributes(as []Attribute, vals map[string]any, amr []string, withAttributes bool) []attribute {
	var out []attribute
	for _, a := range as {
		var vs []string
		switch {
		case a.Source == SourceUserID:
			vs = scalar(vals["sub"])
		case a.Source == SourceEmail:
			if v, _ := vals["email_verified"].(bool); v {
				vs = scalar(vals["email"])
			}
		case a.Source == SourceOrgID:
			vs = scalar(vals["org_id"])
		case a.Source == SourceAMR:
			vs = slices.Clone(amr)
		case withAttributes && strings.HasPrefix(a.Source, SourceAttributePrefix):
			m, _ := vals["attributes"].(map[string]any)
			vs = values(m[strings.TrimPrefix(a.Source, SourceAttributePrefix)])
		}
		if len(vs) > 0 {
			out = append(out, attribute{Attribute: a, Values: vs})
		}
	}
	return out
}

// scalar は文字列・真偽値・数の値を文字列にする（それ以外と空の文字列は無し）。
func scalar(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case bool:
		return []string{strconv.FormatBool(x)}
	case float64:
		return []string{strconv.FormatFloat(x, 'f', -1, 64)}
	case int:
		return []string{strconv.Itoa(x)}
	case int64:
		return []string{strconv.FormatInt(x, 10)}
	case json.Number:
		return []string{x.String()}
	}
	return nil
}

// values はカスタム属性の値（スカラーか、スカラーの配列）を属性の値にする。オブジェクトは出さない。
func values(v any) []string {
	if xs, ok := v.([]any); ok {
		var out []string
		for _, x := range xs {
			out = append(out, scalar(x)...)
		}
		return out
	}
	return scalar(v)
}
