package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/port"
)

type downStorage struct{ port.Storage }

func (downStorage) Tx(context.Context, func(context.Context, port.Tx) error) error {
	return errors.New("db down")
}

// ストレージの障害では 503 を返し、セッションの Cookie を消さない。
func TestSessionStorageErrorKeepsCookie(t *testing.T) {
	l := newLoginEnv(t)
	_, cookie := l.login(t, "kate@example.com")
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(l.e.cfg.Security.Session.ValidityMaxDelay.D()) // キャッシュを外す
	l.a.sessions.Storage = downStorage{l.a.deps.Storage}
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/sessions", nil, "Cookie", sessionCookie+"="+cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			t.Fatalf("session cookie touched: %v", c)
		}
	}
}

// return_token: true でも Cookie は差し替える（送られてきた Cookie のセッションは入れ替えで失効する）。
func TestReturnTokenAlsoSetsCookie(t *testing.T) {
	l := newLoginEnv(t)
	op, err := l.a.CreateOperator(context.Background(), "liam@example.com", role.RealmOwner, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/link:redeem", map[string]any{"token": op.LinkToken, "return_token": true})
	if w.Code != 200 {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" && strings.Contains(w.Body.String(), c.Value) {
			return
		}
	}
	t.Fatalf("no session cookie matching the returned token: %v", w.Result().Cookies())
}

// 大きすぎる本文は読み切らずに 400 invalid_request。
func TestRequestBodyLimit(t *testing.T) {
	l := newLoginEnv(t)
	body := `{"email":"` + strings.Repeat("a", maxBodyBytes) + `@example.com"}`
	r := httptest.NewRequest("POST", "/v1/login/email:start", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
}

// サービスアカウントの API キーでも、ストレージの障害は 503（未認証の 401 にしない）。
func TestAdminStorageErrorIsUnavailable(t *testing.T) {
	l := newLoginEnv(t)
	l.a.deps.Storage = downStorage{l.a.deps.Storage}
	w := l.do(t, l.a.AdminHandler(), "POST", "/v1/admin/notifications/x:claim", nil, "Authorization", "Bearer "+l.apiKey)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
}
