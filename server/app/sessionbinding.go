package app

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/sessionbinding"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// セッションの端末・接続元の監視（フィーチャー session_binding。ADR 0128）。

// sessionBinding は監視を組み立てる。assemble から呼ぶ（a.accounts・a.notify・a.sessions の後）。
func (a *App) sessionBinding(cfg config.Config, d Deps, plan feature.Plan) {
	a.binding = nil
	if !plan.IsActive(feature.SessionBinding) {
		return
	}
	sb := cfg.Security.SessionBinding
	ignore, _ := sb.IgnorePrefixes() // 設定の検査で確かめ済み
	rules := map[sessionbinding.Signal]sessionbinding.Rule{}
	for name, sig := range sb.Signals() {
		r := sessionbinding.Rule{Enabled: sig.Enabled, Score: sig.Score}
		for _, x := range sig.Actions {
			r.Actions = append(r.Actions, sessionbinding.Action(x))
		}
		rules[sessionbinding.Signal(name)] = r
	}
	ttl := max(cfg.Security.Session.AbsoluteLifetime.Default.D(), cfg.Security.Session.AbsoluteLifetime.Max.D())
	pc := sessionbinding.ProfileConfig{Enabled: sb.Profile.Enabled, MinObservations: sb.Profile.MinObservations, MaxNetworks: sb.Profile.MaxNetworks,
		MaxBrowsers: sb.Profile.MaxBrowsers, Retention: sb.Profile.Retention.D()}
	a.binding = &sessionbinding.Guard{Cache: d.Ephemeral, GeoIP: d.GeoIP, Clock: d.Clock, Notify: a.notify, Accounts: a.accounts, Crypter: a.pii,
		Log: d.Logger, Config: sessionbinding.Config{Window: sb.Window.D(), MaxNetworks: sb.MaxNetworks, IgnoreNetworks: ignore, Rules: rules, TTL: ttl,
			Profile: pc}}
}

// networkProfileCleaner はフィーチャー session_binding の片付け。普段の接続元の一覧を消す（系列の状態は EphemeralStore の TTL で消える）。
var networkProfileCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.NetworkProfiles().Count(ctx) },
	Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
		return tx.NetworkProfiles().Purge(ctx, limit)
	},
}

// bindingActor は監視が取ったアクション（リスクの引き上げ・失効）の監査ログの主体。
var bindingActor = audit.Actor{Type: "system", ID: "session_binding"}

// checkBinding はセッションの要求を系列の端末・接続元と比べ、系列が新しいネットワークから使われたら普段の接続元の一覧と比べて
// 一覧に足し、兆候があれば監査ログに残し、設定のアクションを取る。
// 系列を失効させたら偽を返す（呼び出し側は未ログインとして扱う）。リスクを上げたら v の点数も上げる（この要求から効く）。
// 監視の障害（状態を読めない・書けない、記録できない）では要求を止めない（ログに残し、そのまま通す）。
func (a *App) checkBinding(ctx context.Context, r *http.Request, v *session.Validated, viaCookie bool) bool {
	if a.binding == nil || v.PrincipalType != port.PrincipalUser {
		return true
	}
	c, _ := ctx.Value(clientKey{}).(client)
	device := ""
	if ck, err := r.Cookie(a.cookie(deviceCookie)); err == nil {
		device = ck.Value
	}
	obs, err := a.binding.Observe(ctx, sessionbinding.Request{RealmID: a.realm.ID, SID: v.SID, IP: c.IP, UserAgent: c.UserAgent,
		Device: device, ViaCookie: viaCookie})
	if err != nil {
		a.deps.Logger.WarnContext(ctx, "session binding", "session_id", v.SessionID, "error", err)
	}
	if len(obs.Found) == 0 && obs.Visit == nil {
		return true
	}
	actor, reqID := v.Actor(), requestID(ctx)
	_, revoke, _ := bindingActions(obs.Found)
	var found []sessionbinding.Anomaly
	var notify bool
	var learned *sessionbinding.Visit
	var changed []string
	var applied map[string]int
	err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		found, changed, applied, learned = slices.Clone(obs.Found), nil, nil, nil
		if obs.Visit != nil {
			// 一覧と比べて足す。一覧を読めない（鍵を取り出せないなど）ときは、ほかの兆候の記録を止めず、次の要求で比べ直す。
			more, err := a.binding.Learn(ctx, tx, a.realm.ID, v.PrincipalID, *obs.Visit)
			if err != nil {
				a.deps.Logger.WarnContext(ctx, "session binding profile", "session_id", v.SessionID, "error", err)
			} else {
				learned = obs.Visit
			}
			found = append(found, more...)
		}
		var raise map[string]int
		raise, revoke, notify = bindingActions(found)
		for _, x := range found {
			details := map[string]any{"signal": string(x.Signal), "sid": v.SID, "user_id": v.PublicID, "actions": nonNilActions(x.Actions)}
			for k, val := range x.Details {
				details[k] = val
			}
			if _, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{Type: sessionbinding.EventAnomaly, Result: audit.ResultSuccess,
				RealmID: a.realm.ID, Actor: actor, SessionID: v.SessionID, IP: c.IP, UserAgent: c.UserAgent, RequestID: reqID, Details: details}); err != nil {
				return err
			}
		}
		if revoke {
			ids, err := a.sessions.RevokeLineageTx(ctx, tx, a.realm.ID, v.SessionID, session.ReasonAnomaly, bindingActor, reqID)
			if err != nil {
				return err
			}
			changed = append(changed, ids...)
		} else if len(raise) > 0 {
			ids, kept, err := a.sessions.RaiseRiskTx(ctx, tx, a.realm.ID, v.SessionID, raise, bindingActor, reqID)
			if err != nil {
				return err
			}
			changed, applied = append(changed, ids...), kept
		}
		return nil
	})
	if err != nil {
		// 記録できなければ知らせ済みにも一覧に足し終えたことにもしないので、次の要求（同じネットワークでも）でもう一度比べる。
		// 失効させるはずだったなら、この要求は止める。
		a.deps.Logger.ErrorContext(ctx, "session binding actions", "session_id", v.SessionID, "error", err)
		return !revoke
	}
	// 要求が切られても、記録できたことは覚える（要求の ctx の取り消しに巻き込まない）。
	detached := context.WithoutCancel(ctx)
	a.binding.Confirm(detached, a.realm.ID, v.SID, found, learned)
	a.sessions.ForgetIDs(detached, a.realm.ID, changed)
	if notify {
		// 通知は別のトランザクションにし、失敗しても記録・リスク・失効を取り消さない（ログに残すだけ）。
		if err := a.deps.Storage.Tx(detached, func(ctx context.Context, tx port.Tx) error {
			return a.binding.NotifyUser(ctx, tx, a.realm.ID, v.PrincipalID, v.PublicID)
		}); err != nil {
			a.deps.Logger.ErrorContext(ctx, "session binding notification", "session_id", v.SessionID, "error", err)
		}
	}
	if revoke {
		return false
	}
	if len(applied) > 0 {
		v.Risk = maps.Clone(v.Risk)
		if v.Risk == nil {
			v.Risk = map[string]int{}
		}
		for k, val := range applied {
			v.Risk[k] = max(v.Risk[k], val)
		}
	}
	return true
}

// bindingActions は兆候のアクションをまとめる（上げるリスクの点数、失効させるか、知らせるか）。
func bindingActions(found []sessionbinding.Anomaly) (raise map[string]int, revoke, notify bool) {
	raise = map[string]int{}
	for _, x := range found {
		if x.Has(sessionbinding.ActionRisk) {
			t := x.Signal.RiskType()
			raise[t] = max(raise[t], x.Score)
		}
		revoke = revoke || x.Has(sessionbinding.ActionRevoke)
		notify = notify || x.Has(sessionbinding.ActionNotify)
	}
	return raise, revoke, notify
}

// nonNilActions は監査ログに残すアクション（無ければ null ではなく空の配列）。
func nonNilActions(xs []sessionbinding.Action) []sessionbinding.Action {
	if xs == nil {
		return []sessionbinding.Action{}
	}
	return xs
}

// GetUserNetworks はユーザーが普段使う接続元の一覧（ADR 0128）。接続元とブラウザは監査ログの接続元と同じ扱いで、
// audit:read_client_data も要る。
func (s adminServer) GetUserNetworks(ctx context.Context, req adminapi.GetUserNetworksRequestObject) (adminapi.GetUserNetworksResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermUsersRead)
	o, ok, err := outcomeOf(d, err)
	if ok {
		_, d, err = s.a.authorize(ctx, role.PermAuditReadClientData)
		o, ok, err = outcomeOf(d, err)
	}
	if ok && (s.a.binding == nil || !s.a.binding.ProfilesEnabled()) {
		o, ok = failed(http.StatusNotFound, "not_found"), false
	}
	if ok {
		var out adminapi.UserNetworks
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, req.Id)
			if err != nil {
				return err
			}
			prof, err := s.a.binding.LoadProfile(ctx, tx, s.a.realm.ID, u.ID)
			if err != nil {
				return err
			}
			out = userNetworksView(prof, s.a.binding.Established(prof))
			_, err = eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: "user.pii_read", Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
				Actor: p.Actor, RequestID: requestID(ctx), Details: map[string]any{"user_id": u.PublicID, "fields": []string{"networks"}}})
			return err
		})
		if o, ok, err = outcomeOf(nil, err); ok {
			return adminapi.GetUserNetworks200JSONResponse(out), nil
		}
	}
	if err != nil {
		return nil, err
	}
	switch o.status {
	case http.StatusUnauthorized:
		return adminapi.GetUserNetworks401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(o.body)}, nil
	case http.StatusForbidden:
		return adminapi.GetUserNetworks403JSONResponse(o.body), nil
	default:
		return adminapi.GetUserNetworks404JSONResponse(o.body), nil
	}
}

func userNetworksView(p sessionbinding.Profile, established bool) adminapi.UserNetworks {
	out := adminapi.UserNetworks{Observations: p.Observations(), Established: established, Networks: make([]adminapi.UserNetwork, 0, len(p.Networks))}
	for _, n := range p.Networks {
		v := adminapi.UserNetwork{Cidr: n.CIDR, Count: n.Count, FirstSeen: n.FirstSeen, LastSeen: n.LastSeen,
			Browsers: make([]adminapi.UserNetworkBrowser, 0, len(n.Browsers))}
		if n.ASN != 0 {
			asn := int64(n.ASN)
			v.Asn = &asn
		}
		if n.Country != "" {
			v.Country = &n.Country
		}
		for _, b := range n.Browsers {
			v.Browsers = append(v.Browsers, adminapi.UserNetworkBrowser{Family: b.Family, UserAgent: b.UserAgent, Count: b.Count,
				FirstSeen: b.FirstSeen, LastSeen: b.LastSeen})
		}
		out.Networks = append(out.Networks, v)
	}
	return out
}
