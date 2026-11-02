package app

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/botcheck"
	"github.com/imohiyoko/iam/authn/device"
	"github.com/imohiyoko/iam/authn/lockout"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// ログインの守り（ADR 0105）：アカウント単位のロックアウト（account_lockout）、端末の記憶（device_recognition）、
// ログインのリスク（login_risk）、ボット対策（bot_protection）。

// deviceCookie は端末を見分ける Cookie（realm ごと。ユーザーには結び付けない）。
const deviceCookie = "__Host-iam_device"

// ---------------------------------------------------------------------------
// 端末の記憶

// deviceObserver は session.DeviceObserver。リクエストの Cookie を読み、端末を記録し、Cookie を置き直す。
type deviceObserver struct{ a *App }

func (o deviceObserver) Observe(ctx context.Context, tx port.Tx, in session.DeviceLogin) (session.DeviceResult, error) {
	a := o.a
	res, err := a.devices.Observe(ctx, tx, device.Input{RealmID: in.RealmID, UserID: in.UserID, UserPublicID: in.UserPublicID,
		Token: cookie(ctx, a.cookie(deviceCookie)), AAL: acr.AAL(in.AuthMethods), IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID})
	if err != nil {
		return session.DeviceResult{}, err
	}
	// トランザクションが取り消されても、Cookie の値は次のログインでそのまま使う（同じ端末として記録される）。
	// 認証の Cookie ではないので SameSite=None にし、外部 IdP からのクロスサイトの POST（SAML の ACS など）でも送らせる。
	setCookie(ctx, &http.Cookie{Name: a.cookie(deviceCookie), Value: res.Token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteNoneMode, MaxAge: int(a.cfg.Security.Devices.CookieTTL.D() / time.Second)})
	return session.DeviceResult{New: res.New, Risk: res.Risk}, nil
}

func (s publicServer) ListMyDevices(ctx context.Context, _ publicapi.ListMyDevicesRequestObject) (publicapi.ListMyDevicesResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyDevices401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.devices == nil {
		return publicapi.ListMyDevices404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var vs []device.View
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		vs, err = s.a.devices.List(ctx, tx, s.a.realm.ID, au.PrincipalID, cookie(ctx, s.a.cookie(deviceCookie)))
		return err
	})
	if err != nil {
		return nil, err
	}
	out := publicapi.ListMyDevices200JSONResponse{Devices: make([]publicapi.MyDevice, 0, len(vs))}
	for _, v := range vs {
		d := publicapi.MyDevice{Id: v.PublicID, CreatedAt: v.CreatedAt, LastSeenAt: v.LastSeenAt, Confirmed: v.Confirmed, Current: v.Current}
		if v.UserAgent != "" {
			d.UserAgent = &v.UserAgent
		}
		if v.Country != "" {
			d.Country = &v.Country
		}
		out.Devices = append(out.Devices, d)
	}
	return out, nil
}

func (s publicServer) ForgetMyDevice(ctx context.Context, req publicapi.ForgetMyDeviceRequestObject) (publicapi.ForgetMyDeviceResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ForgetMyDevice401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if s.a.devices == nil {
		return publicapi.ForgetMyDevice404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	c := s.a.clientOf(ctx)
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return s.a.devices.Forget(ctx, tx, s.a.realm.ID, au.PrincipalID, req.Id, au.Actor(), c.IP, c.UserAgent, c.RequestID)
	})
	if errors.Is(err, errs.NotFound) {
		return publicapi.ForgetMyDevice404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.ForgetMyDevice204Response{}, nil
}

// deviceCleaner はフィーチャー device_recognition の片付け。端末の記録を消す。
var deviceCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.KnownDevices().Count(ctx) },
	Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
		return tx.KnownDevices().Purge(ctx, limit)
	},
}

// ---------------------------------------------------------------------------
// アカウント単位のロックアウト（2要素目のコード。パスワードは authn/password が数える）

// secondFactorLocked は 2 要素目のコードがロックか待ち時間の間なら *ratelimit.ExceededError を返す。
func (a *App) secondFactorLocked(ctx context.Context, userID string) error {
	return a.lockout.Check(ctx, a.realm.ID, lockout.ScopeSecondFactor, userID)
}

// secondFactorResult は 2 要素目のコードの照合の結果を数える。失敗でロックしたなら監査ログに残す。
func (a *App) secondFactorResult(ctx context.Context, au auth, failed bool) error {
	if a.lockout == nil {
		return nil
	}
	if !failed {
		return a.lockout.Succeeded(ctx, a.realm.ID, lockout.ScopeSecondFactor, au.PrincipalID)
	}
	l, err := a.lockout.Failed(ctx, a.realm.ID, lockout.ScopeSecondFactor, au.PrincipalID)
	if err != nil || l == nil {
		return err
	}
	c := a.clientOf(ctx)
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return lockout.RecordLocked(ctx, tx, a.deps.Clock, a.realm.ID, au.PublicID, lockout.ScopeSecondFactor, l, c.IP, c.UserAgent, c.RequestID)
	}); err != nil {
		a.deps.Logger.WarnContext(ctx, "could not record account lock", "error", err)
	}
	return nil
}

// lockoutSubjects はユーザーのロックアウトの対象（パスワードはすべてのメールアドレス、2要素目はユーザー）。
func (a *App) lockoutSubjects(ctx context.Context, tx port.Tx, u port.User) ([]string, error) {
	es, err := tx.Emails().ListByUser(ctx, a.realm.ID, u.ID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, base64.RawURLEncoding.EncodeToString(e.Index))
	}
	return out, nil
}

func lockoutStateOut(sts []lockout.Status) adminapi.LockoutState {
	var out adminapi.LockoutState
	for _, st := range sts {
		out.Failures, out.Level = max(out.Failures, st.Failures), max(out.Level, st.Level)
		if st.LockedUntil != nil && (out.LockedUntil == nil || st.LockedUntil.After(*out.LockedUntil)) {
			out.LockedUntil = st.LockedUntil
		}
		if st.WaitUntil != nil && (out.WaitUntil == nil || st.WaitUntil.After(*out.WaitUntil)) {
			out.WaitUntil = st.WaitUntil
		}
	}
	return out
}

// userLockout はユーザーのロックアウトの状態を返す。unlock なら消す（消す前の状態を返す）。
func (s adminServer) userLockout(ctx context.Context, publicID string, unlock bool, actor audit.Actor) (adminapi.UserLockout, *outcome, error) {
	var out adminapi.UserLockout
	if s.a.lockout == nil {
		o := failed(http.StatusNotFound, "not_found")
		return out, &o, nil
	}
	var u port.User
	var subjects []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID); err != nil {
			return err
		}
		subjects, err = s.a.lockoutSubjects(ctx, tx, u)
		return err
	})
	if errors.Is(err, errs.NotFound) {
		o := failed(http.StatusNotFound, "not_found")
		return out, &o, nil
	}
	if err != nil {
		return out, nil, err
	}
	op := s.a.lockout.Status
	if unlock {
		op = s.a.lockout.Unlock
	}
	var pw []lockout.Status
	for _, sub := range subjects {
		st, err := op(ctx, s.a.realm.ID, lockout.ScopePassword, sub)
		if err != nil {
			return out, nil, err
		}
		pw = append(pw, st)
	}
	sf, err := op(ctx, s.a.realm.ID, lockout.ScopeSecondFactor, u.ID)
	if err != nil {
		return out, nil, err
	}
	out.Password, out.SecondFactor = lockoutStateOut(pw), lockoutStateOut([]lockout.Status{sf})
	out.Locked = out.Password.LockedUntil != nil || out.Password.WaitUntil != nil || out.SecondFactor.LockedUntil != nil || out.SecondFactor.WaitUntil != nil
	if unlock {
		c := s.a.clientOf(ctx)
		err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: lockout.EventUnlocked, Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
				Actor: actor, IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID,
				Details: map[string]any{"user_id": u.PublicID, "was_locked": out.Locked}})
			return err
		})
	}
	return out, nil, err
}

func (s adminServer) GetUserLockout(ctx context.Context, req adminapi.GetUserLockoutRequestObject) (adminapi.GetUserLockoutResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.GetUserLockout401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.GetUserLockout403JSONResponse(d.Body), nil
	}
	out, o, err := s.userLockout(ctx, req.Id, false, audit.Actor{})
	switch {
	case err != nil:
		return nil, err
	case o != nil:
		return adminapi.GetUserLockout404JSONResponse(o.body), nil
	}
	return adminapi.GetUserLockout200JSONResponse(out), nil
}

func (s adminServer) UnlockUser(ctx context.Context, req adminapi.UnlockUserRequestObject) (adminapi.UnlockUserResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermCredentialsRevoke)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.UnlockUser401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.UnlockUser403JSONResponse(d.Body), nil
	}
	out, o, err := s.userLockout(ctx, req.Id, true, p.Actor)
	switch {
	case err != nil:
		return nil, err
	case o != nil:
		return adminapi.UnlockUser404JSONResponse(o.body), nil
	}
	return adminapi.UnlockUser200JSONResponse(out), nil
}

// ---------------------------------------------------------------------------
// ボット対策

// codeBotCheckRequired はボットの確認が要り、トークンが無いか通らなかったこと。
const codeBotCheckRequired = "bot_check_required"

// botEntry はボットの確認を求めるログインの入口か（パスは realm の接頭辞を外したもの）。
func botEntry(path string) bool {
	switch path {
	case "/v1/login/email:start", "/v1/login/password", "/v1/recovery/email:start", "/v1/recovery/code:redeem":
		return true
	}
	return strings.HasPrefix(path, "/v1/login/methods/") && strings.HasSuffix(path, ":complete")
}

// withBotCheck は withLoginGuard の内側で、入口ならボットの確認を求め、応答が失敗（401・429）なら接続元の失敗を数える。
func (a *App) withBotCheck(bw *bufferedWriter, h http.Handler) http.Handler {
	if a.bot == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Context().Value(clientKey{}).(client)
		if botEntry(r.URL.Path) {
			err := a.bot.Check(r.Context(), a.realm.ID, c.IP, r.Header.Get(botcheck.Header))
			if errors.Is(err, botcheck.ErrRequired) {
				writeError(w, http.StatusForbidden, codeBotCheckRequired)
				return
			}
			if err != nil {
				a.responseError(w, r, err)
				return
			}
		}
		h.ServeHTTP(w, r)
		if bw.status == http.StatusUnauthorized || bw.status == http.StatusTooManyRequests {
			if err := a.bot.Failed(r.Context(), a.realm.ID, c.IP); err != nil {
				a.deps.Logger.WarnContext(r.Context(), "could not count login failure", "error", err)
			}
		}
	})
}

// loginProtection はログインの守り（ADR 0105）を組み立てる。assemble から呼ぶ（a.accounts・a.notify・a.sessions の後）。
func (a *App) loginProtection(cfg config.Config, d Deps, plan feature.Plan) {
	a.lockout, a.devices, a.bot, a.sessions.Devices = nil, nil, nil, nil
	if plan.IsActive(feature.AccountLockout) {
		l := cfg.Security.Lockout
		a.lockout = &lockout.Guard{Cache: d.Ephemeral, Clock: d.Clock, Config: lockout.Config{Threshold: l.Threshold, Window: l.Window.D(),
			LockDuration: l.LockDuration.D(), MaxLockDuration: l.MaxLockDuration.D(), DelayAfter: l.DelayAfter,
			BaseDelay: l.BaseDelay.D(), MaxDelay: l.MaxDelay.D()}}
	}
	if plan.IsActive(feature.DeviceRecognition) {
		dc := cfg.Security.Devices
		a.devices = &device.Service{Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Notify: a.notify, Log: d.Logger,
			Config: device.Config{MaxPerUser: dc.MaxPerUser, Notify: dc.Notify}}
		if plan.IsActive(feature.LoginRisk) {
			r := cfg.Security.LoginRisk
			a.devices.Risk = &device.RiskConfig{NewDeviceScore: r.NewDeviceScore, UnconfirmedDeviceScore: r.UnconfirmedDeviceScore,
				NewCountryScore: r.NewCountryScore, NewASNScore: r.NewASNScore, ImpossibleTravelScore: r.ImpossibleTravelScore,
				MaxSpeedKmh: float64(r.MaxSpeedKmh)}
			a.devices.GeoIP = d.GeoIP
		}
		a.sessions.Devices = deviceObserver{a}
	}
	if plan.IsActive(feature.BotProtection) {
		b := cfg.Security.BotProtection
		a.bot = &botcheck.Guard{Verifier: d.BotVerifier, Cache: d.Ephemeral, Clock: d.Clock, Mode: botcheck.Mode(b.Mode),
			AfterFailures: b.AfterFailures, Window: b.Window.D(), Log: d.Logger}
	}
}
