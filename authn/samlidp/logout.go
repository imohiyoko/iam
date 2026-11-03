package samlidp

import (
	"context"
	"encoding/base64"
	"slices"
	"time"

	"github.com/beevik/etree"

	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// Single Logout（SAML Profiles 4.4）の IdP の側：SP からの LogoutRequest を受け、ブラウザのセッションを終えて LogoutResponse を返す。
// LogoutRequest はいつも署名を求める（署名の無いものでは、どの SP の要求か確かめられない）。ほかの SP への伝播はしない（ADR 0115）。

// ErrNoSLO は SP に SingleLogoutService の登録が無いこと（応答を返す先が無いので 400）。
var ErrNoSLO = errs.WithCode(errs.KindInvalid, "slo_not_registered", "the service provider has no single logout service")

// LogoutPending は確かめた LogoutRequest（HTTP-POST ではブラウザのセッションの Cookie が届かないので、預けて GET で戻る）。
type LogoutPending struct {
	RealmID        string   `json:"realm_id"`
	SPID           string   `json:"sp_id"`
	EntityID       string   `json:"entity_id"`
	RequestID      string   `json:"request_id"`
	NameID         string   `json:"name_id"`
	NameIDFormat   string   `json:"name_id_format,omitempty"`
	SessionIndexes []string `json:"session_indexes,omitempty"`
	RelayState     string   `json:"relay_state,omitempty"`
	// Reply は LogoutResponse を返す SP の SingleLogoutService。
	Reply     Endpoint  `json:"reply"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ParseLogoutRequest は LogoutRequest を確かめる（署名は必須。Destination は SLO の URL）。
func (s *Service) ParseLogoutRequest(ctx context.Context, realmID string, m Message) (LogoutPending, error) {
	now := s.Clock.Now()
	root, _, sp, cfg, err := s.verifiedMessage(ctx, realmID, m, "LogoutRequest", true, now)
	if err != nil {
		return LogoutPending{}, err
	}
	if err := checkHeader(root, s.SLOURL(), true, now); err != nil {
		return LogoutPending{}, err
	}
	if t, err := samlxml.TimeAttr(root, "NotOnOrAfter", false); err != nil {
		return LogoutPending{}, errBad(err.Error())
	} else if !t.IsZero() && !now.Before(t.Add(MaxSkew)) {
		return LogoutPending{}, errBad("saml: the logout request expired")
	}
	if len(samlxml.Children(root, nsAssertion, "BaseID")) > 0 {
		return LogoutPending{}, errBad("saml: BaseID is not supported")
	}
	n, err := samlxml.OneChild(root, nsAssertion, "NameID")
	if err != nil {
		return LogoutPending{}, errBad(err.Error())
	}
	lp := LogoutPending{RealmID: realmID, SPID: sp.ID, EntityID: sp.EntityID, RequestID: root.SelectAttrValue("ID", ""),
		NameIDFormat: n.SelectAttrValue("Format", ""), RelayState: m.RelayState}
	if lp.NameID, err = samlxml.TextOf(n); err != nil || lp.NameID == "" {
		return LogoutPending{}, errBad("saml: invalid NameID")
	}
	idx := samlxml.Children(root, nsProtocol, "SessionIndex")
	if len(idx) > 10 {
		return LogoutPending{}, errBad("saml: too many SessionIndex")
	}
	for _, e := range idx {
		v, err := samlxml.TextOf(e)
		if err != nil || v == "" {
			return LogoutPending{}, errBad("saml: invalid SessionIndex")
		}
		lp.SessionIndexes = append(lp.SessionIndexes, v)
	}
	if len(cfg.SLO) == 0 {
		return LogoutPending{}, ErrNoSLO
	}
	lp.Reply = cfg.SLO[0]
	if i := slices.IndexFunc(cfg.SLO, func(e Endpoint) bool { return e.Binding == m.Binding }); i >= 0 {
		lp.Reply = cfg.SLO[i]
	}
	if err := s.once(ctx, "logout", sp.ID, lp.RequestID); err != nil {
		return LogoutPending{}, err
	}
	return lp, nil
}

// HoldLogout は LogoutRequest を預かり、その ID を返す（HTTP-POST の要求を GET で処理するため）。
func (s *Service) HoldLogout(ctx context.Context, lp LogoutPending) (string, error) {
	lp.ExpiresAt = s.Clock.Now().Add(s.requestTTL())
	return s.hold(ctx, "slo", lp)
}

// TakeLogout は預かった LogoutRequest を 1 回だけ取り出す。
func (s *Service) TakeLogout(ctx context.Context, realmID, rid string) (LogoutPending, error) {
	var lp LogoutPending
	if err := s.get(ctx, "slo", rid, &lp); err != nil {
		return LogoutPending{}, err
	}
	if err := s.Cache.Delete(ctx, pendingKey("slo", rid)); err != nil {
		return LogoutPending{}, err
	}
	if lp.RealmID != realmID || !s.Clock.Now().Before(lp.ExpiresAt) {
		return LogoutPending{}, ErrRequestExpired
	}
	return lp, nil
}

// Matches は LogoutRequest がブラウザのセッション（userID・orgID・sid）の本人を指すかを返す。SessionIndex があれば、その SP に
// このセッションで渡した値を含むこと。NameID は、transient でなければ、このセッションの本人にその SP へ渡す値と一致すること
// （transient は毎回変わるので SessionIndex で決める）。
func (s *Service) Matches(ctx context.Context, lp LogoutPending, userID, orgID, sid string) (bool, error) {
	sp, cfg, err := s.lookup(ctx, lp.RealmID, lp.EntityID)
	if err != nil || sp.ID != lp.SPID {
		return false, err
	}
	hasIndex := len(lp.SessionIndexes) > 0
	if hasIndex && !slices.Contains(lp.SessionIndexes, sessionIndex(sp.ID, sid)) {
		return false, nil
	}
	format := lp.NameIDFormat
	if format == "" || format == NameIDUnspecified {
		format = cfg.NameIDFormat
	}
	if format == NameIDTransient || cfg.NameIDFormat == NameIDTransient {
		return hasIndex && format == cfg.NameIDFormat, nil
	}
	if format != cfg.NameIDFormat {
		return false, nil
	}
	var want string
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		vals, err := s.Tokens.SubjectClaims(ctx, tx, lp.RealmID, userID, orgID, cfg.NameIDSource == SourceEmail, s.Attributes)
		if err != nil {
			return err
		}
		if editable, err := editableNameIDSource(ctx, tx, lp.RealmID, cfg.NameIDSource); err != nil {
			return err
		} else if editable {
			return errNoNameID
		}
		want, err = s.nameID(format, cfg.NameIDSource, vals)
		return err
	})
	if _, ok := ErrorFor(err); ok {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return samlxml.Same(want, lp.NameID), nil
}

// LoggedOut は LogoutRequest でセッションを終えたことを監査ログ saml_idp.logged_out に残す。
func (s *Service) LoggedOut(ctx context.Context, lp LogoutPending, userPublicID, sid, requestID string) error {
	return s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "saml_idp.logged_out", Result: audit.ResultSuccess, RealmID: lp.RealmID, Actor: audit.Actor{Type: "user", ID: userPublicID},
			SessionID: sid, RequestID: requestID,
			Details: map[string]any{"service_provider_id": lp.SPID, "entity_id": lp.EntityID, "logout_request_id": lp.RequestID},
		})
		return err
	})
}

// LogoutReply は SP へ返す LogoutResponse。HTTP-Redirect なら URL へ転送し、HTTP-POST なら Location へ SAMLResponse を POST する。
type LogoutReply struct {
	Binding, Location string
	// URL は HTTP-Redirect の転送先（署名付きのクエリ）。
	URL string
	// SAMLResponse は HTTP-POST の値（base64）。
	SAMLResponse, RelayState string
}

// LogoutResponse は LogoutResponse を組み立てて署名する（st が nil なら Success）。
func (s *Service) LogoutResponse(ctx context.Context, lp LogoutPending, st *StatusError) (LogoutReply, error) {
	id, err := newID()
	if err != nil {
		return LogoutReply{}, err
	}
	out := LogoutReply{Binding: lp.Reply.Binding, Location: lp.Reply.URL, RelayState: lp.RelayState}
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		key, cert, err := s.signer(ctx, tx, lp.RealmID)
		if err != nil {
			return err
		}
		r := etree.NewElement("samlp:LogoutResponse")
		r.CreateAttr("xmlns:samlp", nsProtocol)
		r.CreateAttr("xmlns:saml", nsAssertion)
		r.CreateAttr("ID", id)
		r.CreateAttr("Version", "2.0")
		r.CreateAttr("IssueInstant", xmlTime(s.Clock.Now()))
		r.CreateAttr("Destination", lp.Reply.URL)
		r.CreateAttr("InResponseTo", lp.RequestID)
		r.CreateElement("saml:Issuer").SetText(s.Issuer)
		status(r, st)
		if lp.Reply.Binding == BindingRedirect {
			raw, err := s.finish(r, false, key, cert)
			if err != nil {
				return err
			}
			out.URL, err = EncodeRedirect(lp.Reply.URL, "SAMLResponse", raw, lp.RelayState, key)
			return err
		}
		raw, err := s.finish(r, true, key, cert)
		if err != nil {
			return err
		}
		out.SAMLResponse = base64.StdEncoding.EncodeToString(raw)
		return nil
	})
	return out, err
}
