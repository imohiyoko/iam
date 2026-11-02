package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Token Exchange（RFC 8693、ADR 0099）。
//
// 委任（フィーチャー token_exchange）：連携先が受け取った本人のトークン（IAM が発行したアクセストークンか ID トークン）を、
// 下流のサービス向けの狭いトークンに交換する。発行したトークンは act クレームを持ち、元の認可とログインの系列に結び付く
// （元の失効・系列の終わりが、交換したトークンにも効く）。
//
// なりすまし（フィーチャー impersonation）：運営者が、サポートのために本人として動く。運営者が連携先（サポートの道具）に
// ログインして得たアクセストークンを subject_token にし、拡張のパラメーター requested_subject で本人を指す（Keycloak と同じ形）。
// 権限・outranks・step-up は server が判定し（Impersonation.Authorize）、監査ログと本人への通知を残す。寿命は短い。

// TokenExchangeFeature は委任のフィーチャー（既定オフ）。
var TokenExchangeFeature = feature.Feature{Name: feature.TokenExchange, DataVersion: 1}

// ImpersonationFeature はなりすましのフィーチャー（既定オフ。Token Exchange の上に作る）。
var ImpersonationFeature = feature.Feature{Name: feature.Impersonation, DataVersion: 1, Requires: []string{feature.TokenExchange}}

// トークンの種類（RFC 8693 3）。
const (
	TokenTypeAccess  = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- RFC 8693 のトークンの種類の識別子で、秘密ではない
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"     // #nosec G101 -- 同上
)

// 上限。
const (
	// MaxExchangeDepth は交換を重ねられる回数（act の入れ子の深さ）。
	MaxExchangeDepth = 4
	// MaxExchangeAudiences は 1 回の交換で求められる aud の数。
	MaxExchangeAudiences = 5
	// MaxPolicyEntries は連携先の許可の、subject_clients と audiences のそれぞれの上限。
	MaxPolicyEntries = 20
	// DefaultImpersonationTTL はなりすましのトークンの既定の寿命。
	DefaultImpersonationTTL = 10 * time.Minute
)

var (
	// ErrExchangeNotAllowed は連携先に交換を許していない（unauthorized_client）。
	ErrExchangeNotAllowed = errs.WithCode(errs.KindPermissionDenied, "unauthorized_client", "token exchange is not allowed for this client")
	// ErrInvalidTarget は求めた aud を許していない（RFC 8693 2.2.2）。
	ErrInvalidTarget = errs.WithCode(errs.KindInvalid, "invalid_target", "audience is not allowed")
	// ErrInvalidScope は元のトークンの範囲を超えるスコープ。
	ErrInvalidScope = errs.WithCode(errs.KindInvalid, "invalid_scope", "scope exceeds the subject token")
	// ErrUnsupportedTokenType は扱わないトークンの種類（invalid_request）。
	ErrUnsupportedTokenType = errs.WithCode(errs.KindInvalid, "invalid_request", "unsupported token type")
)

// なりすましを拒んだ理由（監査ログの reason）。
const (
	ImpersonationDeniedStepUp     = "step_up_required"
	ImpersonationDeniedPermission = "permission_denied"
	ImpersonationDeniedOutranked  = "outranked"
	ImpersonationDeniedRateLimit  = "rate_limited"
	ImpersonationDeniedSubject    = "subject_unavailable"
)

// ImpersonationDenied はなりすましを拒んだこと。呼び出し側はトランザクションを取り消した後に RecordImpersonationDenied で
// 監査ログに残し、invalid_grant を返す（理由は返さない。step-up だけは連携先が運営者に再認証を促せるように伝える）。
type ImpersonationDenied struct {
	Reason string
	// RealmID・ClientID（公開）・OperatorID（公開）・SubjectID（求められた値）・SID は監査ログに残す。
	RealmID, ClientID, OperatorID, SubjectID, SID string
}

func (e *ImpersonationDenied) Error() string { return "impersonation denied: " + e.Reason }

// ExchangePolicy は連携先ごとの交換の許可（port.Client.TokenExchange の JSON）。既定は何も許さない。
type ExchangePolicy struct {
	// SubjectClients は、要求した連携先自身のほかに、subject_token の aud として受け付ける連携先の client_id
	// （ブラウザの連携先が受け取ったトークンを、API の連携先が交換するときなど）。
	SubjectClients []string `json:"subject_clients,omitempty"`
	// Audiences は交換で発行するトークンの aud に選べるもの（連携先の client_id か資源の URI。RFC 8707）。
	Audiences []string `json:"audiences,omitempty"`
	// Impersonation はなりすまし（フィーチャー impersonation）を許すか。
	Impersonation bool `json:"impersonation,omitempty"`
}

// ParseExchangePolicy は連携先の許可を読む。無い・読めないなら false（何も許さない）。
func ParseExchangePolicy(b []byte) (ExchangePolicy, bool) {
	var p ExchangePolicy
	if len(b) == 0 || json.Unmarshal(b, &p) != nil || len(p.Audiences) == 0 {
		return ExchangePolicy{}, false
	}
	return p, true
}

// normalize は許可を確かめる。aud が無い許可は「何も許さない」なので nil を返す。
func (p ExchangePolicy) normalize(ctx context.Context, tx port.Tx, realmID string) (*ExchangePolicy, error) {
	if len(p.SubjectClients) > MaxPolicyEntries || len(p.Audiences) > MaxPolicyEntries {
		return nil, invalidClient("token_exchange: too many entries")
	}
	if len(p.Audiences) == 0 {
		if len(p.SubjectClients) > 0 || p.Impersonation {
			return nil, invalidClient("token_exchange: audiences are required")
		}
		return nil, nil
	}
	p.SubjectClients, p.Audiences = compactStrings(p.SubjectClients), compactStrings(p.Audiences)
	for _, c := range p.SubjectClients {
		if _, err := tx.Clients().GetByPublicID(ctx, realmID, c); errors.Is(err, errs.NotFound) {
			return nil, invalidClient("token_exchange: unknown subject client " + c)
		} else if err != nil {
			return nil, err
		}
	}
	for _, a := range p.Audiences {
		if ValidRedirectURI(a) {
			continue
		}
		if _, err := tx.Clients().GetByPublicID(ctx, realmID, a); errors.Is(err, errs.NotFound) {
			return nil, invalidClient("token_exchange: audience must be a client_id or an absolute URI: " + a)
		} else if err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func compactStrings(ss []string) []string {
	out := []string{}
	for _, s := range ss {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// SetTokenExchange は連携先の交換の許可を置き換える（nil か aud の無い許可は、何も許さない）。impersonation が偽なら
// なりすましを許す設定は持てない（呼び出し側がフィーチャーで決める）。
func (c *Clients) SetTokenExchange(ctx context.Context, tx port.Tx, cl port.Client, p ExchangePolicy, impersonation bool, actor audit.Actor,
	requestID string) (port.Client, *ExchangePolicy, error) {
	if p.Impersonation && !impersonation {
		return port.Client{}, nil, invalidClient("token_exchange: impersonation is not enabled")
	}
	if cl.AuthMethod == port.ClientAuthNone && (p.Impersonation || len(p.Audiences) > 0 || len(p.SubjectClients) > 0) {
		return port.Client{}, nil, invalidClient("token_exchange: public clients cannot exchange tokens")
	}
	np, err := p.normalize(ctx, tx, cl.RealmID)
	if err != nil {
		return port.Client{}, nil, err
	}
	cl.TokenExchange = nil
	if np != nil {
		if cl.TokenExchange, err = json.Marshal(np); err != nil {
			return port.Client{}, nil, err
		}
	}
	cl.UpdatedAt = c.Clock.Now()
	if err := tx.Clients().Update(ctx, cl); err != nil {
		return port.Client{}, nil, err
	}
	details := map[string]any{"client_id": cl.PublicID, "enabled": np != nil}
	if np != nil {
		details["audiences"], details["subject_clients"], details["impersonation"] = np.Audiences, np.SubjectClients, np.Impersonation
	}
	_, err = eventlog.Record(ctx, tx, c.Clock, audit.Event{Type: "client.token_exchange_updated", Result: audit.ResultSuccess, RealmID: cl.RealmID,
		Actor: actor, RequestID: requestID, Details: details})
	return cl, np, err
}

// ExchangeRequest は token エンドポイントの交換の要求（RFC 8693 2.1）。
type ExchangeRequest struct {
	SubjectToken, SubjectTokenType string
	ActorToken, ActorTokenType     string
	RequestedTokenType             string
	// Audiences は audience、Resources は resource（RFC 8707）。どちらも発行するトークンの aud になる。
	Audiences, Resources []string
	Scopes               []string
	// RequestedSubject はなりすます本人（ユーザーの公開 ID。拡張のパラメーター requested_subject）。空なら委任。
	RequestedSubject string
}

// ImpersonationCheck は server に渡す、なりすましの判定の材料。
type ImpersonationCheck struct {
	RealmID  string
	Client   port.Client
	Operator port.User
	// Target はなりすます本人。無い・使えない本人なら空（ID が空。権限と step-up だけを確かめ、outranks は確かめない）。
	Target port.User
	// Session は運営者のログインの系列の今のセッション（step-up と認証の文脈に使う）。
	Session port.Session
}

// Impersonation はなりすましの設定（フィーチャー impersonation）。
type Impersonation struct {
	// TTL はトークンの寿命（元のアクセストークンの期限より長くはしない）。
	TTL    time.Duration
	Notify *notify.Service
	// Authorize は運営者がなりすましてよいかを確かめ、拒むなら理由（ImpersonationDenied*）を返す（権限・outranks・step-up・
	// レートリミット）。authn は authz を import しないので server が判定する。
	Authorize func(ctx context.Context, tx port.Tx, in ImpersonationCheck) (string, error)
}

// subjectToken は検証した subject_token。
type subjectToken struct {
	// grant は元の認可。ID トークンなら組み立てたもの（ID は空）。
	grant port.Grant
	// expires は元のトークンの期限。aud は元のトークンの aud。
	expires time.Time
	aud     []string
}

// ExchangeToken は Token Exchange の要求に、アクセストークンを1つ発行する（リフレッシュトークンと ID トークンは出さない）。
// 使えない subject_token・actor_token は ErrInvalidGrant。なりすましを拒んだときは *ImpersonationDenied。
func (t *Tokens) ExchangeToken(ctx context.Context, tx port.Tx, cl port.Client, in ExchangeRequest, requestID string) (Issued, error) {
	pol, ok := ParseExchangePolicy(cl.TokenExchange)
	if !t.TokenExchange || !ok || cl.AuthMethod == port.ClientAuthNone {
		return Issued{}, ErrExchangeNotAllowed
	}
	if in.RequestedTokenType != "" && in.RequestedTokenType != TokenTypeAccess {
		return Issued{}, ErrUnsupportedTokenType
	}
	aud, err := pol.target(in)
	if err != nil {
		return Issued{}, err
	}
	now := t.Clock.Now()
	if in.RequestedSubject != "" {
		return t.impersonate(ctx, tx, cl, pol, in, aud, requestID, now)
	}
	return t.delegate(ctx, tx, cl, pol, in, aud, requestID, now)
}

// target は audience と resource を合わせ、許した aud だけかを確かめる。1つも無ければ ErrInvalidTarget。
func (p ExchangePolicy) target(in ExchangeRequest) ([]string, error) {
	var aud []string
	for _, r := range in.Resources {
		// resource は絶対 URI（RFC 8707 2）。
		if !ValidRedirectURI(r) {
			return nil, ErrInvalidTarget
		}
	}
	for _, a := range append(slices.Clone(in.Audiences), in.Resources...) {
		if !slices.Contains(p.Audiences, a) {
			return nil, ErrInvalidTarget
		}
		if !slices.Contains(aud, a) {
			aud = append(aud, a)
		}
	}
	if len(aud) == 0 || len(aud) > MaxExchangeAudiences {
		return nil, ErrInvalidTarget
	}
	return aud, nil
}

// narrow はスコープを元の範囲に縮める。求めなければ元のまま。元に無いスコープは ErrInvalidScope。
func narrow(have, want []string) ([]string, error) {
	if len(want) == 0 {
		return slices.Clone(have), nil
	}
	var out []string
	for _, s := range want {
		if !slices.Contains(have, s) {
			return nil, ErrInvalidScope
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// subject は subject_token を検証する。使えなければ ErrInvalidGrant。
func (t *Tokens) subject(ctx context.Context, tx port.Tx, realmID, token, typ string, now time.Time) (subjectToken, error) {
	switch typ {
	case TokenTypeAccess:
		tok, g, err := t.accessToken(ctx, tx, realmID, token, now)
		if err != nil {
			return subjectToken{}, err
		}
		// 自前の API に向けた認可（ADR 0112）の aud はリソースの URI のまま（連携先の client_id にしない）。
		aud := g.Audiences
		if g.Exchange == "" && !ResourceBound(g) {
			c, err := tx.Clients().Get(ctx, realmID, g.ClientID)
			if errors.Is(err, errs.NotFound) {
				return subjectToken{}, ErrInvalidGrant
			}
			if err != nil {
				return subjectToken{}, err
			}
			aud = []string{c.PublicID}
		}
		return subjectToken{grant: g, expires: tok.ExpiresAt, aud: aud}, nil
	case TokenTypeIDToken:
		return t.idTokenSubject(ctx, tx, realmID, token, now)
	}
	return subjectToken{}, ErrUnsupportedTokenType
}

// accessToken はアクセストークンが今使えるか（Validate と同じ規則）を確かめる。使えなければ ErrInvalidGrant。
func (t *Tokens) accessToken(ctx context.Context, tx port.Tx, realmID, token string, now time.Time) (port.OIDCToken, port.Grant, error) {
	tok, g, err := t.token(ctx, tx, realmID, token, port.TokenAccess)
	if err == nil && !now.Before(tok.ExpiresAt) {
		err = ErrInvalidToken
	}
	if err == nil {
		_, err = t.grantAliveUntil(ctx, tx, g, now)
	}
	if errors.Is(err, ErrInvalidToken) {
		return port.OIDCToken{}, port.Grant{}, ErrInvalidGrant
	}
	return tok, g, err
}

// idTokenClaims は subject_token の ID トークンから読むクレーム。
type idTokenClaims struct {
	Iss      string          `json:"iss"`
	Sub      string          `json:"sub"`
	Aud      json.RawMessage `json:"aud"`
	Exp      int64           `json:"exp"`
	AuthTime int64           `json:"auth_time"`
	AMR      []string        `json:"amr"`
	SID      string          `json:"sid"`
	OrgID    string          `json:"org_id"`
	Events   json.RawMessage `json:"events"`
}

// idTokenSubject は IAM が発行した ID トークンを検証し、ログインの系列に結び付ける（元の認可は持たない）。
// Logout Token（typ が logout+jwt）は受け付けない。
func (t *Tokens) idTokenSubject(ctx context.Context, tx port.Tx, realmID, token string, now time.Time) (subjectToken, error) {
	payload, err := t.Keys.VerifyType(ctx, tx, realmID, token, "JWT")
	if err != nil {
		if errs.KindOf(err) == errs.KindInvalid || errors.Is(err, ErrUnknownKey) {
			return subjectToken{}, ErrInvalidGrant
		}
		return subjectToken{}, err
	}
	var c idTokenClaims
	if json.Unmarshal(payload, &c) != nil || c.Iss != t.Issuer || c.SID == "" || c.Sub == "" || len(c.Events) > 0 || !now.Before(time.Unix(c.Exp, 0)) {
		return subjectToken{}, ErrInvalidGrant
	}
	var aud []string
	if json.Unmarshal(c.Aud, &aud) != nil {
		var one string
		if json.Unmarshal(c.Aud, &one) != nil || one == "" {
			return subjectToken{}, ErrInvalidGrant
		}
		aud = []string{one}
	}
	u, err := tx.Users().GetByPublicID(ctx, realmID, c.Sub)
	if errors.Is(err, errs.NotFound) {
		return subjectToken{}, ErrInvalidGrant
	}
	if err != nil {
		return subjectToken{}, err
	}
	var orgID string
	if c.OrgID != "" {
		o, err := tx.Orgs().GetByPublicID(ctx, realmID, c.OrgID)
		if errors.Is(err, errs.NotFound) {
			return subjectToken{}, ErrInvalidGrant
		}
		if err != nil {
			return subjectToken{}, err
		}
		orgID = o.ID
	}
	if err := t.alive(ctx, tx, realmID, c.SID, u.ID, orgID, now); err != nil {
		if errors.Is(err, ErrInvalidToken) {
			return subjectToken{}, ErrInvalidGrant
		}
		return subjectToken{}, err
	}
	g := port.Grant{RealmID: realmID, UserID: u.ID, OrgID: orgID, SID: c.SID, Scopes: []string{ScopeOpenID}, AuthMethods: c.AMR,
		AuthTime: time.Unix(c.AuthTime, 0)}
	return subjectToken{grant: g, expires: time.Unix(c.Exp, 0), aud: aud}, nil
}

// accepts は subject_token の aud が、要求した連携先自身か、許した連携先かを返す。
func (p ExchangePolicy) accepts(cl port.Client, aud []string) bool {
	return slices.ContainsFunc(aud, func(a string) bool { return a == cl.PublicID || slices.Contains(p.SubjectClients, a) })
}

// exchangeDepth は g までに交換を重ねた回数（g が交換の認可なら 1 以上。MaxExchangeDepth で打ち切る）。
func (t *Tokens) exchangeDepth(ctx context.Context, tx port.Tx, g port.Grant) (int, error) {
	n := 0
	for cur := g; cur.Exchange != "" && n < MaxExchangeDepth; n++ {
		if cur.ParentID == "" {
			return n + 1, nil
		}
		pg, err := tx.Grants().Get(ctx, g.RealmID, cur.ParentID)
		if errors.Is(err, errs.NotFound) {
			return n, ErrInvalidGrant
		}
		if err != nil {
			return n, err
		}
		cur = pg
	}
	return n, nil
}

func earliestOf(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// delegate は委任：本人のトークンを、下流の aud 向けのトークンに交換する。
func (t *Tokens) delegate(ctx context.Context, tx port.Tx, cl port.Client, pol ExchangePolicy, in ExchangeRequest, aud []string, requestID string,
	now time.Time) (Issued, error) {
	sub, err := t.subject(ctx, tx, cl.RealmID, in.SubjectToken, in.SubjectTokenType, now)
	if err != nil {
		return Issued{}, err
	}
	// なりすましのトークンは、さらに交換しない。
	if !pol.accepts(cl, sub.aud) || sub.grant.Exchange == port.ExchangeImpersonation {
		return Issued{}, ErrInvalidGrant
	}
	d, err := t.exchangeDepth(ctx, tx, sub.grant)
	if err != nil {
		return Issued{}, err
	}
	if d+1 > MaxExchangeDepth {
		return Issued{}, ErrInvalidGrant
	}
	scopes, err := narrow(sub.grant.Scopes, in.Scopes)
	if err != nil {
		return Issued{}, err
	}
	act := map[string]any{"sub": cl.PublicID}
	var actorUserID string
	switch {
	case in.ActorToken != "":
		if in.ActorTokenType != TokenTypeAccess {
			return Issued{}, ErrUnsupportedTokenType
		}
		_, ag, err := t.accessToken(ctx, tx, cl.RealmID, in.ActorToken, now)
		if err != nil {
			return Issued{}, err
		}
		// actor_token は要求した連携先に発行した、交換していないトークンだけ。
		if ag.ClientID != cl.ID || ag.Exchange != "" {
			return Issued{}, ErrInvalidGrant
		}
		au, err := tx.Users().Get(ctx, cl.RealmID, ag.UserID)
		if err != nil {
			return Issued{}, err
		}
		act, actorUserID = map[string]any{"sub": au.PublicID, "client_id": cl.PublicID}, ag.UserID
	case in.ActorTokenType != "":
		return Issued{}, ErrUnsupportedTokenType
	}
	if len(sub.grant.Act) > 0 {
		var prev map[string]any
		if err := json.Unmarshal(sub.grant.Act, &prev); err != nil {
			return Issued{}, err
		}
		act["act"] = prev
	}
	actJSON, err := json.Marshal(act)
	if err != nil {
		return Issued{}, err
	}
	src := sub.grant
	g := port.Grant{ID: id.New(id.Grant), RealmID: cl.RealmID, ClientID: cl.ID, UserID: src.UserID, OrgID: src.OrgID, SID: src.SID, Scopes: scopes,
		AuthMethods: src.AuthMethods, AuthTime: src.AuthTime, CreatedAt: now,
		ExpiresAt: earliestOf(now.Add(ttlOr(t.AccessTokenTTL, DefaultAccessTokenTTL)), sub.expires),
		Exchange:  port.ExchangeDelegation, ParentID: src.ID, ActorUserID: actorUserID, Act: actJSON, Audiences: aud}
	out, err := t.issueExchanged(ctx, tx, g, now)
	if err != nil {
		return Issued{}, err
	}
	u, err := tx.Users().Get(ctx, cl.RealmID, g.UserID)
	if err != nil {
		return Issued{}, err
	}
	orgPublicID, err := t.orgPublicID(ctx, tx, cl.RealmID, g.OrgID)
	if err != nil {
		return Issued{}, err
	}
	details := map[string]any{"client_id": cl.PublicID, "audiences": aud, "scopes": scopes, "subject_token_type": in.SubjectTokenType,
		"act": act}
	_, err = eventlog.Record(ctx, tx, t.Clock, audit.Event{
		Type: "oidc.token_exchanged", Result: audit.ResultSuccess, RealmID: cl.RealmID, OrgID: orgPublicID,
		Actor: audit.Actor{Type: "user", ID: u.PublicID}, SessionID: g.SID, RequestID: requestID, Details: details,
	})
	return out, err
}

// issueExchanged は交換の認可を作り、その期限までのアクセストークンを発行する。
func (t *Tokens) issueExchanged(ctx context.Context, tx port.Tx, g port.Grant, now time.Time) (Issued, error) {
	if err := tx.Grants().Create(ctx, g); err != nil {
		return Issued{}, err
	}
	tid, token, hash, err := newOpaque(id.AccessToken)
	if err != nil {
		return Issued{}, err
	}
	if err := tx.OIDCTokens().Create(ctx, port.OIDCToken{ID: tid, RealmID: g.RealmID, GrantID: g.ID, Kind: port.TokenAccess, Hash: hash,
		CreatedAt: now, ExpiresAt: g.ExpiresAt}); err != nil {
		return Issued{}, err
	}
	return Issued{AccessToken: token, ExpiresIn: g.ExpiresAt.Sub(now), Scopes: g.Scopes, Grant: g}, nil
}

// impersonate はなりすまし：運営者のアクセストークンを、本人（requested_subject）として動くトークンに交換する。
func (t *Tokens) impersonate(ctx context.Context, tx port.Tx, cl port.Client, pol ExchangePolicy, in ExchangeRequest, aud []string, requestID string,
	now time.Time) (Issued, error) {
	imp := t.Impersonation
	if imp == nil || !pol.Impersonation {
		return Issued{}, ErrExchangeNotAllowed
	}
	if in.SubjectTokenType != TokenTypeAccess || in.ActorToken != "" || in.ActorTokenType != "" {
		return Issued{}, ErrUnsupportedTokenType
	}
	tok, g, err := t.accessToken(ctx, tx, cl.RealmID, in.SubjectToken, now)
	if err != nil {
		return Issued{}, err
	}
	// 運営者がこの連携先（サポートの道具）にログインして得た、交換していないトークンだけ。
	if g.ClientID != cl.ID || g.Exchange != "" {
		return Issued{}, ErrInvalidGrant
	}
	s, _, err := t.Sessions.CheckLineage(ctx, tx, cl.RealmID, g.SID, now)
	if errors.Is(err, session.ErrInvalid) || err == nil && s.PrincipalID != g.UserID {
		return Issued{}, ErrInvalidGrant
	}
	if err != nil {
		return Issued{}, err
	}
	operator, err := tx.Users().Get(ctx, cl.RealmID, g.UserID)
	if err != nil {
		return Issued{}, err
	}
	deny := func(reason string) error {
		return &ImpersonationDenied{Reason: reason, RealmID: cl.RealmID, ClientID: cl.PublicID, OperatorID: operator.PublicID,
			SubjectID: in.RequestedSubject, SID: g.SID}
	}
	// 本人が使えるかは、運営者の権限と step-up を確かめてから伝える（権限の無い運営者に、ユーザーの有無を見せない）。
	target, err := tx.Users().GetByPublicID(ctx, cl.RealmID, in.RequestedSubject)
	usable := err == nil
	if err != nil && !errors.Is(err, errs.NotFound) {
		return Issued{}, err
	}
	if usable && (target.ID == operator.ID || target.DeletionScheduledAt != nil) {
		usable = false
	}
	if usable {
		if _, err := account.Check(ctx, tx, target, now, now); err != nil {
			if !errors.Is(err, account.ErrInactive) && !errors.As(err, new(*account.UnavailableError)) {
				return Issued{}, err
			}
			usable = false
		}
	}
	if imp.Authorize == nil {
		return Issued{}, deny(ImpersonationDeniedPermission)
	}
	check := ImpersonationCheck{RealmID: cl.RealmID, Client: cl, Operator: operator, Session: s}
	if usable {
		check.Target = target
	}
	reason, err := imp.Authorize(ctx, tx, check)
	if err != nil {
		return Issued{}, err
	}
	if reason != "" {
		return Issued{}, deny(reason)
	}
	if !usable {
		return Issued{}, deny(ImpersonationDeniedSubject)
	}
	scopes, err := narrow(g.Scopes, in.Scopes)
	if err != nil {
		return Issued{}, err
	}
	act, err := json.Marshal(map[string]any{"sub": operator.PublicID})
	if err != nil {
		return Issued{}, err
	}
	ng := port.Grant{ID: id.New(id.Grant), RealmID: cl.RealmID, ClientID: cl.ID, UserID: target.ID, SID: g.SID, Scopes: scopes,
		AuthMethods: s.AuthMethods, AuthTime: s.AuthenticatedAt, CreatedAt: now,
		ExpiresAt: earliestOf(now.Add(ttlOr(imp.TTL, DefaultImpersonationTTL)), tok.ExpiresAt),
		Exchange:  port.ExchangeImpersonation, ParentID: g.ID, ActorUserID: operator.ID, Act: act, Audiences: aud}
	out, err := t.issueExchanged(ctx, tx, ng, now)
	if err != nil {
		return Issued{}, err
	}
	if _, err := eventlog.Record(ctx, tx, t.Clock, audit.Event{
		Type: "oidc.impersonated", Result: audit.ResultSuccess, RealmID: cl.RealmID, Actor: audit.Actor{Type: "user", ID: operator.PublicID},
		SessionID: g.SID, RequestID: requestID,
		Details: map[string]any{"client_id": cl.PublicID, "user_id": target.PublicID, "audiences": aud, "scopes": scopes,
			"expires_at": ng.ExpiresAt.UTC().Format(time.RFC3339)},
	}); err != nil {
		return Issued{}, err
	}
	return out, t.notifyImpersonated(ctx, tx, imp, target, now)
}

// notifyImpersonated は本人に、なりすましを知らせる（確認済みの全メールへ。宛先は claim で取り出させる。復旧の完了と同じ形。
// アドレスを保存しない構成のメールがあれば、宛先なしの通知を1件出し、外部が user_id から宛先を解決する）。
func (t *Tokens) notifyImpersonated(ctx context.Context, tx port.Tx, imp *Impersonation, u port.User, now time.Time) error {
	if imp.Notify == nil {
		return nil
	}
	es, err := tx.Emails().ListByUser(ctx, u.RealmID, u.ID)
	if err != nil {
		return err
	}
	n := port.Notification{Type: notify.TypeImpersonated, RealmID: u.RealmID, UserID: u.PublicID}
	unresolved, sent := false, false
	for _, e := range es {
		if e.VerifiedAt == nil {
			continue
		}
		if t.Accounts.IndexOnly || len(e.Ciphertext) == 0 {
			unresolved = true
			continue
		}
		addr, err := t.Accounts.EmailAddress(ctx, tx, e)
		if err != nil {
			return err
		}
		if _, err := imp.Notify.Enqueue(ctx, tx, n, &notify.Secret{To: addr, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			return err
		}
		sent = true
	}
	if unresolved || !sent {
		_, err = imp.Notify.Enqueue(ctx, tx, n, nil)
	}
	return err
}

// RecordImpersonationDenied はなりすましを拒んだことを監査ログに残す（ExchangeToken のトランザクションを取り消した後に、別の
// トランザクションで呼ぶ）。
func (t *Tokens) RecordImpersonationDenied(ctx context.Context, tx port.Tx, d *ImpersonationDenied, requestID string) error {
	_, err := eventlog.Record(ctx, tx, t.Clock, audit.Event{
		Type: "oidc.impersonated", Result: audit.ResultFailure, RealmID: d.RealmID, Actor: audit.Actor{Type: "user", ID: d.OperatorID},
		SessionID: d.SID, RequestID: requestID,
		Details: map[string]any{"client_id": d.ClientID, "requested_subject": d.SubjectID, "reason": d.Reason},
	})
	return err
}

// grantAliveUntil は認可が今使えるか（失効・期限、ログインの系列、Org、交換の元の認可、なりすましの本人）を確かめ、次に状態が
// 変わりうる時刻を返す。使えなければ ErrInvalidToken。交換の認可は、そのフィーチャーが止まっていれば使えない（fail-closed）。
func (t *Tokens) grantAliveUntil(ctx context.Context, tx port.Tx, g port.Grant, now time.Time) (time.Time, error) {
	if revoked(g, now) {
		return time.Time{}, ErrInvalidToken
	}
	switch g.Exchange {
	case "":
		if ResourceBound(g) {
			cl, err := tx.Clients().Get(ctx, g.RealmID, g.ClientID)
			if errors.Is(err, errs.NotFound) {
				return time.Time{}, ErrInvalidToken
			}
			if err != nil {
				return time.Time{}, err
			}
			if err := t.resourceAlive(ctx, tx, g, cl); err != nil {
				return time.Time{}, err
			}
		}
		return t.aliveUntil(ctx, tx, g.RealmID, g.SID, g.UserID, g.OrgID, now)
	case port.ExchangeDelegation:
		if !t.TokenExchange {
			return time.Time{}, ErrInvalidToken
		}
	case port.ExchangeImpersonation:
		if !t.TokenExchange || t.Impersonation == nil {
			return time.Time{}, ErrInvalidToken
		}
	default:
		return time.Time{}, ErrInvalidToken
	}
	next := g.ExpiresAt
	for p, n := g.ParentID, 0; p != ""; n++ {
		if n > MaxExchangeDepth {
			return time.Time{}, ErrInvalidToken
		}
		pg, err := tx.Grants().Get(ctx, g.RealmID, p)
		if errors.Is(err, errs.NotFound) {
			return time.Time{}, ErrInvalidToken
		}
		if err != nil {
			return time.Time{}, err
		}
		if revoked(pg, now) {
			return time.Time{}, ErrInvalidToken
		}
		next = earliestOf(next, pg.ExpiresAt)
		if pg.RevokedAt != nil {
			next = earliestOf(next, *pg.RevokedAt)
		}
		p = pg.ParentID
	}
	if g.Exchange == port.ExchangeDelegation {
		at, err := t.aliveUntil(ctx, tx, g.RealmID, g.SID, g.UserID, g.OrgID, now)
		return earliestOf(next, at), err
	}
	// なりすまし：系列は運営者のもの。本人が使えなくなれば（停止・削除・統合・削除の予定）トークンも使えない。
	at, err := t.aliveUntil(ctx, tx, g.RealmID, g.SID, g.ActorUserID, "", now)
	if err != nil {
		return time.Time{}, err
	}
	next = earliestOf(next, at)
	u, err := tx.Users().Get(ctx, g.RealmID, g.UserID)
	if errors.Is(err, errs.NotFound) {
		return time.Time{}, ErrInvalidToken
	}
	if err != nil {
		return time.Time{}, err
	}
	if u.DeletionScheduledAt != nil {
		return time.Time{}, ErrInvalidToken
	}
	nu, err := account.Check(ctx, tx, u, g.CreatedAt, now)
	if errors.Is(err, account.ErrInactive) || errors.As(err, new(*account.UnavailableError)) {
		return time.Time{}, ErrInvalidToken
	}
	if err != nil {
		return time.Time{}, err
	}
	if nu != nil {
		next = earliestOf(next, *nu)
	}
	return next, nil
}

// exchangeIntrospection は交換の認可のイントロスペクションの項目（act、なりすましの印）を足す。
func exchangeIntrospection(out *Introspection, g port.Grant) error {
	if g.Exchange == "" {
		return nil
	}
	out.Aud = slices.Clone(g.Audiences)
	if len(g.Act) > 0 {
		out.Act = json.RawMessage(slices.Clone(g.Act))
	}
	if g.Exchange == port.ExchangeImpersonation {
		// sid は運営者のログインの系列なので、本人の sid として出さない。
		out.Impersonation, out.SID = true, ""
	}
	if out.Aud == nil {
		return fmt.Errorf("provider: exchanged grant %s has no audience", g.ID)
	}
	return nil
}
