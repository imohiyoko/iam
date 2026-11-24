package app

import (
	"context"
	"maps"
	"net/http"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/sessionbinding"
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
	a.binding = &sessionbinding.Guard{Cache: d.Ephemeral, GeoIP: d.GeoIP, Clock: d.Clock, Notify: a.notify, Accounts: a.accounts, Log: d.Logger,
		Config: sessionbinding.Config{Window: sb.Window.D(), MaxNetworks: sb.MaxNetworks, IgnoreNetworks: ignore, Rules: rules, TTL: ttl}}
}

// bindingActor は監視が取ったアクション（リスクの引き上げ・失効）の監査ログの主体。
var bindingActor = audit.Actor{Type: "system", ID: "session_binding"}

// checkBinding はセッションの要求を系列の端末・接続元と比べ、兆候があれば監査ログに残し、設定のアクションを取る。
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
	found, err := a.binding.Observe(ctx, sessionbinding.Request{RealmID: a.realm.ID, SID: v.SID, IP: c.IP, UserAgent: c.UserAgent,
		Device: device, ViaCookie: viaCookie})
	if err != nil {
		a.deps.Logger.WarnContext(ctx, "session binding", "session_id", v.SessionID, "error", err)
	}
	if len(found) == 0 {
		return true
	}
	actor, reqID := v.Actor(), requestID(ctx)
	raise := map[string]int{}
	revoke, notify := false, false
	for _, x := range found {
		if x.Has(sessionbinding.ActionRisk) {
			t := x.Signal.RiskType()
			raise[t] = max(raise[t], x.Score)
		}
		revoke = revoke || x.Has(sessionbinding.ActionRevoke)
		notify = notify || x.Has(sessionbinding.ActionNotify)
	}
	var changed []string
	var applied map[string]int
	err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		changed, applied = nil, nil
		for _, x := range found {
			details := map[string]any{"signal": string(x.Signal), "sid": v.SID, "user_id": v.PublicID, "actions": x.Actions}
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
		// 記録できなければ知らせ済みにしないので、次の要求でもう一度見つかる。失効させるはずだったなら、この要求は止める。
		a.deps.Logger.ErrorContext(ctx, "session binding actions", "session_id", v.SessionID, "error", err)
		return !revoke
	}
	// 要求が切られても、記録できたことは覚える（要求の ctx の取り消しに巻き込まない）。
	detached := context.WithoutCancel(ctx)
	a.binding.Confirm(detached, a.realm.ID, v.SID, found)
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
