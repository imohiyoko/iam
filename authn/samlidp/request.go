package samlidp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// AuthnRequest（SAML Core 3.4.1）の解析と確認。知らない SP・登録に無い ACS・確かめられない署名は SP に戻さず 400 にする
// （戻り先を信用できない）。SP と ACS を確かめた後の、応えられない要求は、ACS へ失敗の Response を返す（ADR 0115）。

// MaxSkew は SP との時刻のずれとして許す幅。
const MaxSkew = 3 * time.Minute

// maxRequestAge は AuthnRequest・LogoutRequest の IssueInstant から受け付ける期間。
const maxRequestAge = 10 * time.Minute

func errBad(msg string) error { return errs.WithCode(errs.KindInvalid, "invalid_request", msg) }

// 要求の誤り（SP に戻さずに 400 にする）。
var (
	ErrUnknownSP = errs.WithCode(errs.KindInvalid, "unknown_service_provider", "unknown saml service provider")
	// ErrUnknownACS は AuthnRequest の ACS が登録と合わない（URL・番号・バインディング）こと。
	ErrUnknownACS = errs.WithCode(errs.KindInvalid, "unknown_acs", "the assertion consumer service is not registered")
	// ErrBadSignature は署名が無い（求めている）・確かめられないこと。
	ErrBadSignature = errs.WithCode(errs.KindInvalid, "bad_signature", "the saml message signature is missing or invalid")
	// ErrReplayed は同じ ID の要求を 2 度受けたこと。
	ErrReplayed = errs.WithCode(errs.KindInvalid, "replayed_request", "the saml request was already used")
	// ErrIdPInitiatedNotAllowed は IdP-initiated を許していない SP。
	ErrIdPInitiatedNotAllowed = errs.WithCode(errs.KindInvalid, "idp_initiated_not_allowed", "idp-initiated sso is not allowed for the service provider")
	// ErrRequestExpired はログイン画面で待つ間の要求が無い（期限切れ・完了済み）。
	ErrRequestExpired = errs.WithCode(errs.KindNotFound, "request_expired", "saml request expired")
)

// SAML の状態コード（SAML Core 3.2.2.2）。
const (
	StatusSuccess          = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester        = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder        = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusNoPassive        = "urn:oasis:names:tc:SAML:2.0:status:NoPassive" // #nosec G101 -- SAML の状態コードの識別子で、秘密ではない
	StatusNoAuthnContext   = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
	StatusInvalidNameID    = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	StatusRequestUnsupport = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	StatusAuthnFailed      = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusRequestDenied    = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
)

// StatusError は ACS へ失敗の Response で返す誤り（SP と ACS を確かめた後のもの）。
type StatusError struct {
	// Code は最上位の状態（Requester・Responder）、Sub は 2 段目（NoPassive など）。
	Code, Sub string
	Msg       string
}

func (e *StatusError) Error() string { return "saml status " + e.Sub + ": " + e.Msg }

func statusErr(code, sub, msg string) *StatusError {
	return &StatusError{Code: code, Sub: sub, Msg: msg}
}

// AuthnRequest は確かめた AuthnRequest の、使う値。
type AuthnRequest struct {
	ID string
	// ACS は応答を送る先（登録と一致したもの）。
	ACS string
	// ForceAuthn は今からのログインを求める。IsPassive は利用者に画面を見せない（ログインが要るなら NoPassive）。
	ForceAuthn, IsPassive bool
	// NameIDFormat は NameIDPolicy の Format（空か unspecified なら SP の登録のもの）。
	NameIDFormat string
	// ClassRefs と Comparison は RequestedAuthnContext（無ければ空）。
	ClassRefs  []string
	Comparison string
	// Status は SP と ACS を確かめた後の、応えられない要求の誤り（あれば Response で返す）。
	Status *StatusError
}

// ParseAuthnRequest は受け取った AuthnRequest を確かめ、SP の登録と、使う値を返す。
// 順序：XML の字句と形 → Issuer で SP を引く → 署名（あれば必ず確かめる。登録で求めていれば必須）→ 以後は署名を確かめた要素からだけ読む
// （XML Signature Wrapping を防ぐ）→ Destination・時刻・ID の再利用 → ACS（登録と一致しなければ SP に戻さない）→ 応えられない内容は Status。
func (s *Service) ParseAuthnRequest(ctx context.Context, realmID string, m Message) (port.SAMLServiceProvider, Config, AuthnRequest, error) {
	now := s.Clock.Now()
	root, signed, sp, cfg, err := s.verifiedMessage(ctx, realmID, m, "AuthnRequest", false, now)
	if err != nil {
		return port.SAMLServiceProvider{}, Config{}, AuthnRequest{}, err
	}
	if err := checkHeader(root, s.SSOURL(), signed, now); err != nil {
		return port.SAMLServiceProvider{}, Config{}, AuthnRequest{}, err
	}
	req := AuthnRequest{ID: root.SelectAttrValue("ID", "")}
	if req.ACS, err = selectACS(root, cfg); err != nil {
		return port.SAMLServiceProvider{}, Config{}, AuthnRequest{}, err
	}
	if err := s.once(ctx, "authn", sp.ID, req.ID); err != nil {
		return port.SAMLServiceProvider{}, Config{}, AuthnRequest{}, err
	}
	if req.ForceAuthn, err = boolAttr(root, "ForceAuthn"); err != nil {
		return port.SAMLServiceProvider{}, Config{}, AuthnRequest{}, err
	}
	if req.IsPassive, err = boolAttr(root, "IsPassive"); err != nil {
		return port.SAMLServiceProvider{}, Config{}, AuthnRequest{}, err
	}
	req.Status = readOptions(root, sp, cfg, &req)
	if req.Status == nil {
		req.Status = s.checkClassRefs(req.ClassRefs, req.Comparison)
	}
	return sp, cfg, req, nil
}

// verifiedMessage は XML を読み、Issuer の SP を引き、署名を確かめて、署名を確かめた要素（署名が無ければ読んだ要素）と、
// 署名があったかを返す。requireSig は署名を必ず求める（LogoutRequest）。
func (s *Service) verifiedMessage(ctx context.Context, realmID string, m Message, tag string, requireSig bool, now time.Time) (*etree.Element, bool, port.SAMLServiceProvider, Config, error) {
	root, err := samlxml.Parse(m.XML, "saml")
	if err != nil {
		return nil, false, port.SAMLServiceProvider{}, Config{}, errBad(err.Error())
	}
	if !samlxml.Is(root, nsProtocol, tag) {
		return nil, false, port.SAMLServiceProvider{}, Config{}, errBad("saml: not a " + tag)
	}
	if err := checkShape(root); err != nil {
		return nil, false, port.SAMLServiceProvider{}, Config{}, errBad(err.Error())
	}
	// SP を引くためだけに、確かめる前の Issuer を読む（値は署名を確かめた後で読み直して比べる）。
	entityID, err := issuerOf(root)
	if err != nil {
		return nil, false, port.SAMLServiceProvider{}, Config{}, err
	}
	sp, cfg, err := s.lookup(ctx, realmID, entityID)
	if err != nil {
		return nil, false, port.SAMLServiceProvider{}, Config{}, err
	}
	sigs := samlxml.Children(root, samlxml.NSDSig, "Signature")
	switch {
	case m.SignedByQuery() && len(sigs) > 0:
		// HTTP-Redirect では XML の署名を外す（Bindings 3.4.4.1）。両方あるものは受けない。
		return nil, false, sp, cfg, ErrBadSignature
	case m.SignedByQuery() && m.Binding != BindingRedirect:
		return nil, false, sp, cfg, ErrBadSignature
	case m.SignedByQuery():
		if len(cfg.SigningCerts) == 0 {
			return nil, false, sp, cfg, ErrBadSignature
		}
		if err := m.verifyQuery(cfg.SigningCerts); err != nil {
			s.log().InfoContext(ctx, "saml idp: query signature", "service_provider_id", sp.ID, "error", err)
			return nil, false, sp, cfg, ErrBadSignature
		}
	case len(sigs) == 1:
		if m.Binding == BindingRedirect || len(cfg.SigningCerts) == 0 {
			return nil, false, sp, cfg, ErrBadSignature
		}
		certs, err := parseCerts(cfg.SigningCerts)
		if err != nil {
			return nil, false, sp, cfg, err
		}
		verified, err := samlxml.ValidateEnveloped(root, sigs[0], certs, now)
		if err != nil {
			s.log().InfoContext(ctx, "saml idp: xml signature", "service_provider_id", sp.ID, "error", err)
			return nil, false, sp, cfg, ErrBadSignature
		}
		// ここから後は、署名を確かめたバイト列から作り直した要素だけを読む。
		root = verified
		if !samlxml.Is(root, nsProtocol, tag) {
			return nil, false, sp, cfg, ErrBadSignature
		}
	case len(sigs) > 1:
		return nil, false, sp, cfg, errBad("saml: more than one signature")
	default:
		if requireSig || cfg.RequireSignedRequests {
			return nil, false, sp, cfg, ErrBadSignature
		}
	}
	// 署名を確かめた要素の Issuer が、引いた SP のものであること。
	if got, err := issuerOf(root); err != nil || !samlxml.Same(got, sp.EntityID) {
		return nil, false, sp, cfg, ErrBadSignature
	}
	return root, m.SignedByQuery() || len(sigs) == 1, sp, cfg, nil
}

func parseCerts(ders [][]byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// checkShape は文書全体を見る：署名は根の直下に 1 つまで（ほかの位置の署名は受けない）、署名のアルゴリズムは許したものだけ、
// ID は重ならない、暗号化された要素（EncryptedID など）は受けない。
func checkShape(root *etree.Element) error {
	ids := map[string]bool{}
	var walk func(el *etree.Element, depth int) error
	walk = func(el *etree.Element, depth int) error {
		ns := el.NamespaceURI()
		switch {
		case ns == samlxml.NSDSig:
			if el.Tag == "Signature" && (depth != 1 || el.Parent() != root) {
				return errors.New("saml: unexpected signature position")
			}
			if err := samlxml.CheckAlgorithm(el, "saml"); err != nil {
				return err
			}
		case ns == nsAssertion && (el.Tag == "EncryptedID" || el.Tag == "EncryptedAssertion" || el.Tag == "EncryptedAttribute" || el.Tag == "Assertion"):
			return errors.New("saml: unexpected element " + el.Tag)
		}
		if v := el.SelectAttrValue("ID", ""); v != "" {
			if ids[v] {
				return errors.New("saml: duplicate ID")
			}
			ids[v] = true
		}
		for _, c := range el.ChildElements() {
			if err := walk(c, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}

// issuerOf は要求の Issuer（形式は entity か省略）の値を返す。無いものは受けない（SP を決められない）。
func issuerOf(root *etree.Element) (string, error) {
	iss, err := samlxml.OneChild(root, nsAssertion, "Issuer")
	if err != nil {
		return "", ErrUnknownSP
	}
	v, err := samlxml.TextOf(iss)
	if err != nil || v == "" || len(v) > maxEntityIDLen {
		return "", ErrUnknownSP
	}
	if f := iss.SelectAttrValue("Format", nameIDEntity); f != nameIDEntity {
		return "", ErrUnknownSP
	}
	return v, nil
}

// checkHeader は要求の共通の属性を確かめる：Version、ID、IssueInstant（今から maxRequestAge 前まで、ずれは MaxSkew）、
// Destination（あれば dest と完全一致。署名した要求では必須）。
func checkHeader(root *etree.Element, dest string, signed bool, now time.Time) error {
	if root.SelectAttrValue("Version", "") != "2.0" {
		return errBad("saml: unsupported version")
	}
	if v := root.SelectAttrValue("ID", ""); v == "" || len(v) > 256 || !validID(v) {
		return errBad("saml: invalid ID")
	}
	t, err := samlxml.TimeAttr(root, "IssueInstant", true)
	if err != nil {
		return errBad(err.Error())
	}
	if t.After(now.Add(MaxSkew)) || t.Before(now.Add(-maxRequestAge-MaxSkew)) {
		return errBad("saml: IssueInstant is out of range")
	}
	d := root.SelectAttr("Destination")
	if d == nil && signed {
		return errBad("saml: a signed request needs Destination")
	}
	if d != nil && !samlxml.Same(d.Value, dest) {
		return errBad("saml: Destination mismatch")
	}
	return nil
}

// validID は xs:ID らしい値か（英字か "_" で始まり、空白・制御文字を含まない）。
func validID(v string) bool {
	c := v[0]
	if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] == 0x7f || v[i] == '<' || v[i] == '&' || v[i] == '"' {
			return false
		}
	}
	return true
}

// selectACS は応答を送る ACS を決める。AssertionConsumerServiceURL（と ProtocolBinding）か AssertionConsumerServiceIndex が
// 登録と完全一致するものだけ。どちらも無ければ既定の ACS。両方あるもの、HTTP-POST 以外のバインディングは受けない。
func selectACS(root *etree.Element, cfg Config) (string, error) {
	u, hasURL := root.SelectAttrValue("AssertionConsumerServiceURL", ""), root.SelectAttr("AssertionConsumerServiceURL") != nil
	idx := root.SelectAttr("AssertionConsumerServiceIndex")
	if b := root.SelectAttr("ProtocolBinding"); b != nil && b.Value != BindingPOST {
		return "", ErrUnknownACS
	}
	switch {
	case hasURL && idx != nil:
		return "", ErrUnknownACS
	case hasURL:
		if i := slices.IndexFunc(cfg.ACS, func(e Endpoint) bool { return e.URL == u }); i >= 0 && u != "" {
			return cfg.ACS[i].URL, nil
		}
		return "", ErrUnknownACS
	case idx != nil:
		n, err := strconv.Atoi(idx.Value)
		if err != nil || n < 0 || n > maxACSIndex {
			return "", ErrUnknownACS
		}
		if i := slices.IndexFunc(cfg.ACS, func(e Endpoint) bool { return e.Index == n }); i >= 0 {
			return cfg.ACS[i].URL, nil
		}
		return "", ErrUnknownACS
	}
	e, ok := defaultACS(cfg)
	if !ok {
		return "", ErrUnknownACS
	}
	return e.URL, nil
}

// boolAttr は xs:boolean の属性を読む（無ければ false）。
func boolAttr(el *etree.Element, name string) (bool, error) {
	a := el.SelectAttr(name)
	if a == nil {
		return false, nil
	}
	switch a.Value {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return false, errBad("saml: invalid " + name)
}

// readOptions は NameIDPolicy・RequestedAuthnContext・Subject を読む。応えられない内容は StatusError。
func readOptions(root *etree.Element, sp port.SAMLServiceProvider, cfg Config, req *AuthnRequest) *StatusError {
	// Subject（特定の利用者の指定）には応えない。
	if len(samlxml.Children(root, nsAssertion, "Subject")) > 0 {
		return statusErr(StatusRequester, StatusRequestUnsupport, "Subject in AuthnRequest is not supported")
	}
	pol, err := samlxml.OptionalChild(root, nsProtocol, "NameIDPolicy")
	if err != nil {
		return statusErr(StatusRequester, StatusInvalidNameID, "more than one NameIDPolicy")
	}
	if pol != nil {
		f := pol.SelectAttrValue("Format", "")
		switch {
		case f == "" || f == NameIDUnspecified:
		case f == cfg.NameIDFormat:
			req.NameIDFormat = f
		default:
			return statusErr(StatusRequester, StatusInvalidNameID, "the requested NameID format is not configured for the service provider")
		}
		if q := pol.SelectAttr("SPNameQualifier"); q != nil && q.Value != sp.EntityID {
			return statusErr(StatusRequester, StatusInvalidNameID, "SPNameQualifier must be the service provider")
		}
	}
	rac, err := samlxml.OptionalChild(root, nsProtocol, "RequestedAuthnContext")
	if err != nil {
		return statusErr(StatusRequester, StatusNoAuthnContext, "more than one RequestedAuthnContext")
	}
	if rac == nil {
		return nil
	}
	req.Comparison = rac.SelectAttrValue("Comparison", "exact")
	if len(samlxml.Children(rac, nsAssertion, "AuthnContextDeclRef")) > 0 {
		return statusErr(StatusRequester, StatusNoAuthnContext, "AuthnContextDeclRef is not supported")
	}
	refs := samlxml.Children(rac, nsAssertion, "AuthnContextClassRef")
	if len(refs) == 0 || len(refs) > 10 {
		return statusErr(StatusRequester, StatusNoAuthnContext, "RequestedAuthnContext needs 1 to 10 AuthnContextClassRef")
	}
	for _, r := range refs {
		v, err := samlxml.TextOf(r)
		if err != nil || v == "" || len(v) > 512 {
			return statusErr(StatusRequester, StatusNoAuthnContext, "invalid AuthnContextClassRef")
		}
		if !slices.Contains(req.ClassRefs, v) {
			req.ClassRefs = append(req.ClassRefs, v)
		}
	}
	return nil
}

const (
	replayPrefix = "samlidp:request:v1:"
	replayTTL    = maxRequestAge + 2*MaxSkew
)

func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// once は SP ごとに要求の ID を 1 回だけ受ける（IssueInstant を受け付ける期間だけ覚える）。
func (s *Service) once(ctx context.Context, kind, spID, reqID string) error {
	n, err := s.Cache.Incr(ctx, replayPrefix+digest(kind+"\x00"+spID+"\x00"+reqID), replayTTL)
	if err != nil {
		return err
	}
	if n > 1 {
		return ErrReplayed
	}
	return nil
}

// Pending はログイン画面で待つ間の要求（SP-initiated と IdP-initiated）。
type Pending struct {
	RealmID string `json:"realm_id"`
	// SPID と EntityID は SP の ID と Entity ID（戻ったときに登録が変わっていないかを確かめる）。
	SPID     string `json:"sp_id"`
	EntityID string `json:"entity_id"`
	ACS      string `json:"acs"`
	// RequestID は AuthnRequest の ID（InResponseTo）。IdP-initiated では空。
	RequestID    string   `json:"request_id,omitempty"`
	RelayState   string   `json:"relay_state,omitempty"`
	IsPassive    bool     `json:"is_passive,omitempty"`
	NameIDFormat string   `json:"name_id_format,omitempty"`
	ClassRefs    []string `json:"class_refs,omitempty"`
	// LoginAfter は ForceAuthn と step-up のとき、この時刻より後の本人確認を求める。
	LoginAfter *time.Time `json:"login_after,omitempty"`
	// LoginStarted はログイン画面に一度回したか（戻ってもまだ足りなければ、ログインし直しても届かない）。
	LoginStarted bool      `json:"login_started,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// NewPending は確かめた AuthnRequest から Pending を作る。
func NewPending(realmID string, sp port.SAMLServiceProvider, req AuthnRequest, relayState string, now time.Time) Pending {
	p := Pending{RealmID: realmID, SPID: sp.ID, EntityID: sp.EntityID, ACS: req.ACS, RequestID: req.ID, RelayState: relayState,
		IsPassive: req.IsPassive, NameIDFormat: req.NameIDFormat, ClassRefs: req.ClassRefs}
	if req.ForceAuthn {
		p.LoginAfter = &now
	}
	return p
}

// NewIdPInitiated は IdP-initiated の Pending を作る（SP が許したときだけ。ACS は既定のもの）。
func (s *Service) NewIdPInitiated(ctx context.Context, realmID, entityID, relayState string) (port.SAMLServiceProvider, Pending, error) {
	if err := checkRelayState(relayState); err != nil {
		return port.SAMLServiceProvider{}, Pending{}, err
	}
	sp, cfg, err := s.lookup(ctx, realmID, entityID)
	if err != nil {
		return port.SAMLServiceProvider{}, Pending{}, err
	}
	if !cfg.AllowIdPInitiated {
		return port.SAMLServiceProvider{}, Pending{}, ErrIdPInitiatedNotAllowed
	}
	e, ok := defaultACS(cfg)
	if !ok {
		return port.SAMLServiceProvider{}, Pending{}, ErrUnknownACS
	}
	return sp, Pending{RealmID: realmID, SPID: sp.ID, EntityID: sp.EntityID, ACS: e.URL, RelayState: relayState}, nil
}

// Fresh は authAt の本人確認が ForceAuthn・step-up の条件を満たすかを返す。
func (p Pending) Fresh(authAt time.Time) bool {
	return p.LoginAfter == nil || !authAt.Before(*p.LoginAfter)
}

// Recheck は待つ間に SP の登録（Entity ID と ACS）が変わっていないかを確かめ、今の SP と設定を返す。
func (s *Service) Recheck(ctx context.Context, p Pending) (port.SAMLServiceProvider, Config, error) {
	sp, cfg, err := s.lookup(ctx, p.RealmID, p.EntityID)
	if err != nil {
		return port.SAMLServiceProvider{}, Config{}, err
	}
	if sp.ID != p.SPID || !slices.ContainsFunc(cfg.ACS, func(e Endpoint) bool { return e.URL == p.ACS }) {
		return port.SAMLServiceProvider{}, Config{}, ErrUnknownACS
	}
	if p.RequestID == "" && !cfg.AllowIdPInitiated {
		return port.SAMLServiceProvider{}, Config{}, ErrIdPInitiatedNotAllowed
	}
	return sp, cfg, nil
}

const (
	pendingPurpose = "flow.saml_idp_request"
	pendingPrefix  = "samlidp:pending:v1:"
)

func pendingKey(kind, rid string) string { return pendingPrefix + kind + ":" + digest(rid) }

func (s *Service) requestTTL() time.Duration {
	if s.RequestTTL <= 0 {
		return 10 * time.Minute
	}
	return s.RequestTTL
}

// hold は値を封をして預かり、その ID（秘密。256 bit）を返す。
func (s *Service) hold(ctx context.Context, kind string, v any) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	rid := base64.RawURLEncoding.EncodeToString(b)
	return rid, s.put(ctx, kind, rid, v)
}

func (s *Service) put(ctx context.Context, kind, rid string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := s.Crypter.Seal(ctx, pendingPurpose+"."+kind, raw)
	if err != nil {
		return err
	}
	return s.Cache.Set(ctx, pendingKey(kind, rid), sealed, s.requestTTL())
}

func (s *Service) get(ctx context.Context, kind, rid string, v any) error {
	if rid == "" || len(rid) > 128 {
		return ErrRequestExpired
	}
	b, ok, err := s.Cache.Get(ctx, pendingKey(kind, rid))
	if err != nil {
		return err
	}
	if !ok {
		return ErrRequestExpired
	}
	raw, err := s.Crypter.Open(ctx, pendingPurpose+"."+kind, b)
	if err != nil || json.Unmarshal(raw, v) != nil {
		return ErrRequestExpired
	}
	return nil
}

// Hold はログイン画面で待つ間、要求を預かり、その ID を返す。
func (s *Service) Hold(ctx context.Context, p Pending) (string, error) {
	p.ExpiresAt = s.Clock.Now().Add(s.requestTTL())
	return s.hold(ctx, "sso", p)
}

// Save は預かった要求を書き換える（ログイン画面に回したことを記録する）。期限は延ばさない。
func (s *Service) Save(ctx context.Context, rid string, p Pending) error {
	if !s.Clock.Now().Before(p.ExpiresAt) {
		return ErrRequestExpired
	}
	return s.put(ctx, "sso", rid, p)
}

// Resume は預かった要求を返す（消さない。ログインをやり直せるように）。無ければ ErrRequestExpired。
func (s *Service) Resume(ctx context.Context, realmID, rid string) (Pending, error) {
	var p Pending
	if err := s.get(ctx, "sso", rid, &p); err != nil {
		return Pending{}, err
	}
	if p.RealmID != realmID || !s.Clock.Now().Before(p.ExpiresAt) {
		return Pending{}, ErrRequestExpired
	}
	return p, nil
}

// Drop は預かった要求を消す（Response を渡した後）。
func (s *Service) Drop(ctx context.Context, rid string) error {
	return s.Cache.Delete(ctx, pendingKey("sso", rid))
}

// ErrorFor は err が ACS へ返す誤りなら、それを返す。
func ErrorFor(err error) (*StatusError, bool) {
	var se *StatusError
	ok := errors.As(err, &se)
	return se, ok
}
