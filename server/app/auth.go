package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
)

// sessionCookie はセッションの Cookie の名前。`__Host-` で Secure・Path=/・Domain なしを強制する（design.md 5.2）。
const sessionCookie = "__Host-iam_session"

type authKey struct{}

// auth はリクエストのセッション（検証済み）。
type auth struct {
	session.Validated
	viaCookie bool
}

// recent は本人の重要な操作 action に足りる、直近に認証したセッションか（5.4）。active な Org の max_auth_age の内であることに
// 加えて、名前空間 `me` と active な Org の要件（ADR 0084。auth_within などで操作ごとに厳しくできる）を満たすこと。
// 要件を読めなければ満たさない（fail-closed）。
func (s publicServer) recent(ctx context.Context, au auth, action string) bool {
	age := au.MaxAuthAge
	if age <= 0 {
		age = s.a.cfg.Security.Session.MaxAuthAge.Default.D()
	}
	if s.a.deps.Clock.Now().Sub(au.AuthenticatedAt) > age {
		return false
	}
	d, err := s.a.authz.Require(ctx, s.a.realm.ID, check.Request{Principal: check.Principal{Type: au.PrincipalType, ID: au.PrincipalID}, Action: action,
		OrgID: au.ActiveOrgID, Context: sessionContext(au.Validated)})
	if err != nil {
		s.a.deps.Logger.ErrorContext(ctx, "requirements of a sensitive operation", "action", action, "error", err)
		return false
	}
	return d.Allow
}

func authFrom(ctx context.Context) (auth, bool) {
	a, ok := ctx.Value(authKey{}).(auth)
	return a, ok
}

// sessionToken は Cookie か Bearer のトークンを返す。Bearer を優先する（別ドメインのアプリ）。
func (a *App) sessionToken(r *http.Request) (token string, viaCookie bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		if t, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(t), false
		}
		return "", false
	}
	if c, err := r.Cookie(a.cookie(sessionCookie)); err == nil {
		return c.Value, true
	}
	return "", false
}

func (a *App) sessionCookieFor(token string, expires time.Time, now time.Time) *http.Cookie {
	return &http.Cookie{
		Name: a.cookie(sessionCookie), Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: max(int(expires.Sub(now).Seconds()), 1),
	}
}

func (a *App) clearSessionCookie() *http.Cookie {
	return &http.Cookie{Name: a.cookie(sessionCookie), Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

// withSession はセッションを検証し、リクエストの context に載せる。
// Cookie のセッションは、入れ替えの時期を過ぎていれば ID を入れ替えて Cookie を差し替える（5.2）。
// 無効なトークンは未ログインとして扱う（理由は返さない。4.9）。ストレージの障害は 503。
func (a *App) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, viaCookie := a.sessionToken(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		v, err := a.sessions.Validate(ctx, a.realm.ID, token)
		if err != nil && !errors.Is(err, session.ErrInvalid) {
			// ストレージの障害では有効なセッションかもしれないので、Cookie を消さずに 503 を返す。
			a.unavailable(w, r, err)
			return
		}
		if err != nil {
			if viaCookie {
				http.SetCookie(w, a.clearSessionCookie())
			}
			next.ServeHTTP(w, r)
			return
		}
		// 制限つき（2要素目の確認待ちなど）のセッションは、決まった API の他では未ログインとして扱う（4.1）。
		if !restrictionAllows(v.Restriction, r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if viaCookie && v.RotateDue {
			if is, err := a.sessions.Rotate(ctx, a.realm.ID, v.SessionID, requestID(ctx)); err == nil {
				http.SetCookie(w, a.sessionCookieFor(is.Token, is.Session.ExpiresAt, a.deps.Clock.Now()))
				v.SessionID, v.RotateDue = is.Session.ID, false
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, authKey{}, auth{Validated: v, viaCookie: viaCookie})))
	})
}

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey{}).(string)
	return s
}

type clientKey struct{}

// client は監査ログに残す接続元。信頼できるプロキシの扱い（X-Forwarded-For）は M6 で足す。
type client struct{ IP, UserAgent string }

func clientOf(r *http.Request) client {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	return client{IP: host, UserAgent: ua}
}
