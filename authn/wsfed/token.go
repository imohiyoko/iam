package wsfed

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// トークン（RequestSecurityTokenResponse に入れた SAML の Assertion）の組み立て（ADR 0110）。

// 名前空間と識別子。
const (
	nsSAML11    = "urn:oasis:names:tc:SAML:1.0:assertion"
	nsSAML20    = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsTrust     = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	nsPolicy    = "http://schemas.xmlsoap.org/ws/2004/09/policy"
	nsAddress   = "http://www.w3.org/2005/08/addressing"
	nsUtility   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	nameIDUnspc = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	// TokenTypeSAML11 と TokenTypeSAML20 は RSTR の TokenType（メタデータの TokenTypesOffered にも載せる）。
	TokenTypeSAML11 = "urn:oasis:names:tc:SAML:1.0:assertion" // #nosec G101 -- SAML の識別子
	TokenTypeSAML20 = "urn:oasis:names:tc:SAML:2.0:assertion" // #nosec G101 -- SAML の識別子

	cmBearer11    = "urn:oasis:names:tc:SAML:1.0:cm:bearer"   // #nosec G101 -- SAML の識別子
	cmBearer20    = "urn:oasis:names:tc:SAML:2.0:cm:bearer"   // #nosec G101 -- SAML の識別子
	amPassword11  = "urn:oasis:names:tc:SAML:1.0:am:password" // #nosec G101 -- SAML の識別子
	amUnspc11     = "urn:oasis:names:tc:SAML:1.0:am:unspecified"
	acPassword20  = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" // #nosec G101 -- SAML の識別子
	acUnspc20     = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	requestIssue  = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"
	keyNoProofKey = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey"
)

func xmlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// newAssertionID は Assertion の ID（xs:ID なので "_" で始める。160 bit の乱数）。
func newAssertionID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}

// attribute は RP に出す属性（クレームの種類と値）。
type attribute struct {
	Type   string
	Values []string
}

// assertion は Assertion の中身。
type assertion struct {
	ID       string
	Issuer   string
	Audience string
	// Recipient は SAML 2.0 の SubjectConfirmationData の Recipient（wreply）。
	Recipient string
	Subject   string
	IssuedAt  time.Time
	Expires   time.Time
	AuthTime  time.Time
	Password  bool
	Attrs     []attribute
}

// saml11 は SAML 1.1 の Assertion を組み立てる（署名は最後の子に入れる）。
func (a assertion) saml11() *etree.Element {
	el := etree.NewElement("saml:Assertion")
	el.CreateAttr("xmlns:saml", nsSAML11)
	el.CreateAttr("MajorVersion", "1")
	el.CreateAttr("MinorVersion", "1")
	el.CreateAttr("AssertionID", a.ID)
	el.CreateAttr("Issuer", a.Issuer)
	el.CreateAttr("IssueInstant", xmlTime(a.IssuedAt))
	cond := el.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", xmlTime(a.IssuedAt))
	cond.CreateAttr("NotOnOrAfter", xmlTime(a.Expires))
	cond.CreateElement("saml:AudienceRestrictionCondition").CreateElement("saml:Audience").SetText(a.Audience)
	subject := func(parent *etree.Element) {
		s := parent.CreateElement("saml:Subject")
		n := s.CreateElement("saml:NameIdentifier")
		n.CreateAttr("Format", nameIDUnspc)
		n.SetText(a.Subject)
		s.CreateElement("saml:SubjectConfirmation").CreateElement("saml:ConfirmationMethod").SetText(cmBearer11)
	}
	if len(a.Attrs) > 0 {
		st := el.CreateElement("saml:AttributeStatement")
		subject(st)
		for _, at := range a.Attrs {
			ns, name, _ := splitClaimType(at.Type)
			x := st.CreateElement("saml:Attribute")
			x.CreateAttr("AttributeName", name)
			x.CreateAttr("AttributeNamespace", ns)
			for _, v := range at.Values {
				x.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	au := el.CreateElement("saml:AuthenticationStatement")
	au.CreateAttr("AuthenticationMethod", map[bool]string{true: amPassword11, false: amUnspc11}[a.Password])
	au.CreateAttr("AuthenticationInstant", xmlTime(a.AuthTime))
	subject(au)
	return el
}

// saml20 は SAML 2.0 の Assertion を組み立てる（署名は Issuer の後に入れる）。
func (a assertion) saml20() *etree.Element {
	el := etree.NewElement("saml:Assertion")
	el.CreateAttr("xmlns:saml", nsSAML20)
	el.CreateAttr("ID", a.ID)
	el.CreateAttr("IssueInstant", xmlTime(a.IssuedAt))
	el.CreateAttr("Version", "2.0")
	el.CreateElement("saml:Issuer").SetText(a.Issuer)
	s := el.CreateElement("saml:Subject")
	n := s.CreateElement("saml:NameID")
	n.CreateAttr("Format", nameIDUnspc)
	n.SetText(a.Subject)
	sc := s.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", cmBearer20)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", xmlTime(a.Expires))
	scd.CreateAttr("Recipient", a.Recipient)
	cond := el.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", xmlTime(a.IssuedAt))
	cond.CreateAttr("NotOnOrAfter", xmlTime(a.Expires))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(a.Audience)
	if len(a.Attrs) > 0 {
		st := el.CreateElement("saml:AttributeStatement")
		for _, at := range a.Attrs {
			x := st.CreateElement("saml:Attribute")
			x.CreateAttr("Name", at.Type)
			for _, v := range at.Values {
				x.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	au := el.CreateElement("saml:AuthnStatement")
	au.CreateAttr("AuthnInstant", xmlTime(a.AuthTime))
	au.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(
		map[bool]string{true: acPassword20, false: acUnspc20}[a.Password])
	return el
}

// signed は tokenType の Assertion を組み立てて署名する。
func (a assertion) signed(tokenType string, key crypto.Signer, cert []byte) (*etree.Element, error) {
	if tokenType == TokenSAML20 {
		el := a.saml20()
		return el, signAt(el, key, cert, "ID", 1)
	}
	el := a.saml11()
	return el, signAt(el, key, cert, "AssertionID", -1)
}

// rstr は Assertion を入れた RequestSecurityTokenResponse（WS-Trust 2005/02。パッシブ要求者の wresult）を組み立てる。
func rstr(tok *etree.Element, tokenType, audience string, created, expires time.Time) ([]byte, error) {
	doc := etree.NewDocument()
	r := doc.CreateElement("t:RequestSecurityTokenResponse")
	r.CreateAttr("xmlns:t", nsTrust)
	lt := r.CreateElement("t:Lifetime")
	c := lt.CreateElement("wsu:Created")
	c.CreateAttr("xmlns:wsu", nsUtility)
	c.SetText(xmlTime(created))
	e := lt.CreateElement("wsu:Expires")
	e.CreateAttr("xmlns:wsu", nsUtility)
	e.SetText(xmlTime(expires))
	at := r.CreateElement("wsp:AppliesTo")
	at.CreateAttr("xmlns:wsp", nsPolicy)
	epr := at.CreateElement("wsa:EndpointReference")
	epr.CreateAttr("xmlns:wsa", nsAddress)
	epr.CreateElement("wsa:Address").SetText(audience)
	r.CreateElement("t:RequestedSecurityToken").AddChild(tok)
	tt := TokenTypeSAML11
	if tokenType == TokenSAML20 {
		tt = TokenTypeSAML20
	}
	r.CreateElement("t:TokenType").SetText(tt)
	r.CreateElement("t:RequestType").SetText(requestIssue)
	r.CreateElement("t:KeyType").SetText(keyNoProofKey)
	return doc.WriteToBytes()
}

// Subject はトークンに載せる本人（ブラウザのセッションから）。
type Subject struct {
	// UserID と OrgID は内部 ID（OrgID は空なら Org なし）。SID はログインの系列。
	UserID, OrgID, SID string
	AuthTime           time.Time
	AMR                []string
}

// Issued は RP に POST する値。
type Issued struct {
	// Reply は POST する先（wreply）、Result は wresult（RSTR の XML）、Context は wctx。
	Reply, Result, Context string
	AssertionID            string
}

// Issue は RP にトークンを発行する（監査ログ wsfed.token_issued）。rp と reply は Lookup・ReplyFor で確かめたもの。
func (s *Service) Issue(ctx context.Context, realmID string, rp port.WSFedRelyingParty, reply, wctx string, sub Subject, requestID string) (Issued, error) {
	claims, err := Claims(rp)
	if err != nil {
		return Issued{}, err
	}
	needEmail := slices.ContainsFunc(claims, func(c Claim) bool { return c.Source == SourceEmail })
	needAttrs := s.Attributes && slices.ContainsFunc(claims, func(c Claim) bool { return strings.HasPrefix(c.Source, SourceAttributePrefix) })
	aid, err := newAssertionID()
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		vals, err := s.Tokens.SubjectClaims(ctx, tx, realmID, sub.UserID, sub.OrgID, needEmail, needAttrs)
		if err != nil {
			return err
		}
		subject, _ := vals["sub"].(string)
		if subject == "" {
			return fmt.Errorf("wsfed: no subject for user")
		}
		key, cert, err := s.signer(ctx, tx, realmID, rp.SigningAlg)
		if err != nil {
			return err
		}
		now := s.Clock.Now()
		exp := now.Add(time.Duration(rp.TokenLifetime) * time.Second)
		a := assertion{ID: aid, Issuer: s.Issuer, Audience: rp.Realm, Recipient: reply, Subject: subject, IssuedAt: now, Expires: exp,
			AuthTime: sub.AuthTime, Password: slices.Contains(sub.AMR, "pwd"), Attrs: attributes(claims, vals, sub.AMR, s.Attributes)}
		tok, err := a.signed(rp.TokenType, key, cert)
		if err != nil {
			return err
		}
		res, err := rstr(tok, rp.TokenType, rp.Realm, now, exp)
		if err != nil {
			return err
		}
		out = Issued{Reply: reply, Result: string(res), Context: wctx, AssertionID: aid}
		orgID, _ := vals["org_id"].(string)
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "wsfed.token_issued", Result: audit.ResultSuccess, RealmID: realmID, OrgID: orgID,
			Actor: audit.Actor{Type: "user", ID: subject}, SessionID: sub.SID, RequestID: requestID,
			Details: map[string]any{"relying_party_id": rp.ID, "realm": rp.Realm, "token_type": rp.TokenType, "assertion_id": aid},
		})
		return err
	})
	return out, err
}

// SignedOut は wsignout1.0 でセッションを終えたことを監査ログ wsfed.signed_out に残す。
func (s *Service) SignedOut(ctx context.Context, realmID string, rp port.WSFedRelyingParty, userPublicID, sid, requestID string) error {
	return s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "wsfed.signed_out", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: userPublicID},
			SessionID: sid, RequestID: requestID, Details: map[string]any{"relying_party_id": rp.ID, "realm": rp.Realm},
		})
		return err
	})
}

// attributes はクレームの対応から属性を作る。値の無いもの（未確認のメール、Org なし、属性が無いなど）は出さない。
func attributes(claims []Claim, vals map[string]any, amr []string, withAttributes bool) []attribute {
	var out []attribute
	for _, c := range claims {
		var vs []string
		switch {
		case c.Source == SourceUserID:
			vs = scalar(vals["sub"])
		case c.Source == SourceEmail:
			// WS-Federation には email_verified が無い。確認済みのものだけを出す（ADR 0110）。
			if v, _ := vals["email_verified"].(bool); v {
				vs = scalar(vals["email"])
			}
		case c.Source == SourceOrgID:
			vs = scalar(vals["org_id"])
		case c.Source == SourceAMR:
			vs = slices.Clone(amr)
		case withAttributes && strings.HasPrefix(c.Source, SourceAttributePrefix):
			m, _ := vals["attributes"].(map[string]any)
			vs = values(m[strings.TrimPrefix(c.Source, SourceAttributePrefix)])
		}
		if len(vs) > 0 {
			out = append(out, attribute{Type: c.Type, Values: vs})
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
