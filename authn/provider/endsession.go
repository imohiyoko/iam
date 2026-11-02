package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// RP-Initiated Logout 1.0 と Front-Channel Logout 1.0（design.md 5.2、ADR 0094）。
//
// 連携先がブラウザを end_session_endpoint に送り、ログアウトを求める。id_token_hint（この realm が発行した ID トークン。
// 期限切れも受け付ける）で連携先と系列を示せる。戻り先（post_logout_redirect_uri）は連携先に登録した値と完全に一致するときだけ
// 使う。ここでは要求の検証と、確認を待つ間の預かり、Front-Channel Logout の送り先を受け持つ。画面とセッションの失効は server。

// LogoutFeature はフィーチャー oidc_logout の宣言（features/oidclogout が登録する）。
var LogoutFeature = feature.Feature{Name: feature.OIDCLogout, DataVersion: 1}

// 上限と既定の値。
const (
	// MaxIDTokenHint は id_token_hint の長さの上限（ML-DSA-65 の署名でも 8KB に収まる）。
	MaxIDTokenHint = 16 << 10
	// MaxLogoutState は state の長さの上限。
	MaxLogoutState = 2048
	// DefaultLogoutRequestTTL は確認の画面で待つ間のログアウトの要求の期限。
	DefaultLogoutRequestTTL = 10 * time.Minute
)

var (
	// ErrInvalidLogoutRequest はログアウトの要求が正しくない（理由は返さない。戻り先にも送らない）。
	ErrInvalidLogoutRequest = errs.WithCode(errs.KindInvalid, "invalid_request", "invalid logout request")
	// ErrLogoutRequestExpired は確認を待つ間のログアウトの要求が無い（期限切れ・完了済み・別のセッション）。
	ErrLogoutRequestExpired = errs.WithCode(errs.KindNotFound, "request_expired", "logout request expired")
)

// EndSessionInput は end_session_endpoint の要求（OIDC RP-Initiated Logout 2）。logout_hint と ui_locales は server が扱う。
type EndSessionInput struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
}

// EndSession は検証済みのログアウトの要求。
type EndSession struct {
	RealmID string `json:"realm_id"`
	// ClientID は連携先の client_id（外部 ID）。client_id か id_token_hint で示されたときだけ。ClientName はその名前。
	ClientID   string `json:"client_id,omitempty"`
	ClientName string `json:"client_name,omitempty"`
	// RedirectURI は登録と完全に一致した post_logout_redirect_uri。空なら戻さない。
	RedirectURI string `json:"redirect_uri,omitempty"`
	State       string `json:"state,omitempty"`
	// HintSub と HintSID は検証した id_token_hint の sub（ユーザーの外部 ID）と sid。
	HintSub string `json:"hint_sub,omitempty"`
	HintSID string `json:"hint_sid,omitempty"`
	// SID と PrincipalID は確認を求めたときのセッション（系列と主体の内部 ID）。確認はこのセッションでだけ通る。
	SID         string    `json:"sid,omitempty"`
	PrincipalID string    `json:"principal_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// RedirectURL は戻り先の URL（state を付ける）。戻さないなら空。
func (e EndSession) RedirectURL() string {
	if e.RedirectURI == "" {
		return ""
	}
	if e.State == "" {
		return e.RedirectURI
	}
	u, err := url.Parse(e.RedirectURI)
	if err != nil {
		return ""
	}
	q := url.Values{"state": {e.State}}.Encode()
	if u.RawQuery == "" {
		u.RawQuery = q
	} else {
		u.RawQuery += "&" + q
	}
	return u.String()
}

// audience は aud（文字列か配列）。
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = audience{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}
	*a = ss
	return nil
}

// hintClaims は id_token_hint から読むクレーム。
type hintClaims struct {
	Iss    string          `json:"iss"`
	Sub    string          `json:"sub"`
	Aud    audience        `json:"aud"`
	Azp    string          `json:"azp"`
	SID    string          `json:"sid"`
	Events json.RawMessage `json:"events"`
}

// EndSession はログアウトの要求を確かめる。id_token_hint は realm の鍵での署名・typ・iss・aud（この realm の連携先）を
// 確かめ、期限は見ない（OIDC RP-Initiated Logout 2：期限切れのものも受け付ける）。client_id と id_token_hint の連携先が
// 違う、戻り先が登録と一致しない、戻り先があるのに連携先が分からないときは ErrInvalidLogoutRequest。
func (t *Tokens) EndSession(ctx context.Context, tx port.Tx, realmID string, in EndSessionInput) (EndSession, error) {
	if len(in.IDTokenHint) > MaxIDTokenHint || len(in.State) > MaxLogoutState || len(in.ClientID) > 256 {
		return EndSession{}, ErrInvalidLogoutRequest
	}
	e := EndSession{RealmID: realmID, State: in.State, ClientID: in.ClientID}
	if in.IDTokenHint != "" {
		c, err := t.verifyHint(ctx, tx, realmID, in.IDTokenHint)
		if err != nil {
			return EndSession{}, err
		}
		if e.ClientID != "" && e.ClientID != c.client {
			return EndSession{}, ErrInvalidLogoutRequest
		}
		e.ClientID, e.HintSub, e.HintSID = c.client, c.Sub, c.SID
	}
	var cl port.Client
	if e.ClientID != "" {
		var err error
		cl, err = tx.Clients().GetByPublicID(ctx, realmID, e.ClientID)
		if errors.Is(err, errs.NotFound) {
			return EndSession{}, ErrInvalidLogoutRequest
		}
		if err != nil {
			return EndSession{}, err
		}
		e.ClientName = cl.Name
	}
	if in.PostLogoutRedirectURI != "" {
		// 登録した値との完全な一致だけ（オープンリダイレクトを防ぐ）。連携先が分からなければ確かめられないので拒む。
		if e.ClientID == "" || !slices.Contains(cl.PostLogoutRedirectURIs, in.PostLogoutRedirectURI) {
			return EndSession{}, ErrInvalidLogoutRequest
		}
		e.RedirectURI = in.PostLogoutRedirectURI
	}
	return e, nil
}

type verifiedHint struct {
	hintClaims
	client string
}

func (t *Tokens) verifyHint(ctx context.Context, tx port.Tx, realmID, hint string) (verifiedHint, error) {
	payload, err := t.Keys.VerifyType(ctx, tx, realmID, hint, "JWT")
	if errs.KindOf(err) == errs.KindInvalid {
		return verifiedHint{}, ErrInvalidLogoutRequest
	}
	if err != nil {
		return verifiedHint{}, err
	}
	var c hintClaims
	if json.Unmarshal(payload, &c) != nil || c.Iss != t.Issuer || c.Sub == "" || len(c.Aud) == 0 || len(c.Events) > 0 {
		return verifiedHint{}, ErrInvalidLogoutRequest
	}
	// 連携先は aud（1つのとき）か azp（aud に含まれること。OIDC Core 2）。
	client := c.Azp
	switch {
	case client != "" && !slices.Contains(c.Aud, client):
		return verifiedHint{}, ErrInvalidLogoutRequest
	case client == "" && len(c.Aud) == 1:
		client = c.Aud[0]
	case client == "":
		return verifiedHint{}, ErrInvalidLogoutRequest
	}
	return verifiedHint{hintClaims: c, client: client}, nil
}

// FrontChannelURLs は系列 sid の認可を持つ連携先のうち、frontchannel_logout_uri を登録したものの URL を返す（認可を作った順、
// 連携先ごとに1つ）。frontchannel_logout_session_required なら iss と sid を付ける（OIDC Front-Channel Logout 2）。
// 認可の失効や期限は問わない（連携先のログインは認可とは別に残りうる。Back-Channel Logout と同じ）。
func (t *Tokens) FrontChannelURLs(ctx context.Context, tx port.Tx, realmID, sid string) ([]string, error) {
	if sid == "" {
		return nil, nil
	}
	gs, err := tx.Grants().ListBySID(ctx, realmID, sid)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, g := range gs {
		if seen[g.ClientID] {
			continue
		}
		seen[g.ClientID] = true
		cl, err := tx.Clients().Get(ctx, realmID, g.ClientID)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if cl.FrontchannelLogoutURI == "" {
			continue
		}
		u := cl.FrontchannelLogoutURI
		if cl.FrontchannelLogoutSessionRequired {
			q := url.Values{"iss": {t.Issuer}, "sid": {sid}}.Encode()
			if strings.Contains(u, "?") {
				u += "&" + q
			} else {
				u += "?" + q
			}
		}
		out = append(out, u)
	}
	return out, nil
}

const logoutPurpose = "flow.oidc_logout"

// HoldLogout は確認の画面で待つ間、ログアウトの要求を預かり、その ID（秘密。確認のフォームに入れる）を返す。
func (f *Flow) HoldLogout(ctx context.Context, e EndSession) (string, error) {
	rid, err := randomString()
	if err != nil {
		return "", err
	}
	ttl := DefaultLogoutRequestTTL
	e.ExpiresAt = f.Clock.Now().Add(ttl)
	return rid, f.put(ctx, digestKey("oidc:logout:v1:", rid), logoutPurpose, e, ttl)
}

// TakeLogout は預かったログアウトの要求を1回だけ取り出す。無ければ ErrLogoutRequestExpired。
func (f *Flow) TakeLogout(ctx context.Context, realmID, rid string) (EndSession, error) {
	if rid == "" || len(rid) > 128 {
		return EndSession{}, ErrLogoutRequestExpired
	}
	b, ok, err := f.Cache.Take(ctx, digestKey("oidc:logout:v1:", rid))
	if err != nil {
		return EndSession{}, err
	}
	var e EndSession
	if !ok || f.open(ctx, logoutPurpose, b, &e) != nil || e.RealmID != realmID || !f.Clock.Now().Before(e.ExpiresAt) {
		return EndSession{}, ErrLogoutRequestExpired
	}
	return e, nil
}
