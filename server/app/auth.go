package app

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/session"
)

// sessionCookie はセッションの Cookie の名前。`__Host-` で Secure・Path=/・Domain なしを強制する（design.md 5.2）。
const sessionCookie = "__Host-iam_session"

type authKey struct{}

// auth はリクエストのセッション（検証済み）。
type auth struct {
	session.Validated
	viaCookie bool
}

func authFrom(ctx context.Context) (auth, bool) {
	a, ok := ctx.Value(authKey{}).(auth)
	return a, ok
}

// sessionToken は Cookie か Bearer のトークンを返す。Bearer を優先する（別ドメインのアプリ）。
func sessionToken(r *http.Request) (token string, viaCookie bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		if t, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(t), false
		}
		return "", false
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value, true
	}
	return "", false
}

func sessionCookieFor(token string, expires time.Time, now time.Time) *http.Cookie {
	return &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: max(int(expires.Sub(now).Seconds()), 1),
	}
}

func clearSessionCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

// withSession はセッションを検証し、リクエストの context に載せる。
// Cookie のセッションは、入れ替えの時期を過ぎていれば ID を入れ替えて Cookie を差し替える（5.2）。
// 無効なトークンは未ログインとして扱う（理由は返さない。4.9）。
func (a *App) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, viaCookie := sessionToken(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		v, err := a.sessions.Validate(ctx, a.realm.ID, token)
		if err != nil {
			if viaCookie {
				http.SetCookie(w, clearSessionCookie())
			}
			next.ServeHTTP(w, r)
			return
		}
		if viaCookie && v.RotateDue {
			if is, err := a.sessions.Rotate(ctx, a.realm.ID, v.SessionID, requestID(ctx)); err == nil {
				http.SetCookie(w, sessionCookieFor(is.Token, is.Session.ExpiresAt, a.deps.Clock.Now()))
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
