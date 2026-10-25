package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func newApp(t *testing.T) (*App, *clock.Fake) {
	t.Helper()
	e := newEnv(t)
	a, err := New(context.Background(), e.cfg, e.deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, e.deps.Clock.(*clock.Fake)
}

// login はユーザーを作り、セッションを発行してトークンを返す（ログインの流れは #16 で足す）。
func login(t *testing.T, a *App) (userID, token string) {
	t.Helper()
	u := port.User{ID: id.New(id.User), PublicID: id.NewExternal(id.User), RealmID: a.realm.ID, Status: port.UserActive, CreatedAt: a.deps.Clock.Now(), UpdatedAt: a.deps.Clock.Now()}
	err := a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		if err := a.pii.CreateDataKey(ctx, tx.DataKeys(), u.ID, a.deps.Clock.Now()); err != nil {
			return err
		}
		is, err := a.sessions.Issue(ctx, tx, session.Issue{RealmID: a.realm.ID, UserID: u.ID, AuthMethods: []string{"otp"}})
		token = is.Token
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID, token
}

func call(a *App, method, path, cookie, bearer string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	a.PublicHandler().ServeHTTP(w, r)
	return w
}

func listSessions(t *testing.T, a *App, cookie, bearer string) []map[string]any {
	t.Helper()
	w := call(a, "GET", "/v1/me/sessions", cookie, bearer)
	if w.Code != 200 {
		t.Fatalf("list sessions: %d %s", w.Code, w.Body)
	}
	var body struct{ Sessions []map[string]any }
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Sessions
}

func TestMeSessionsRequiresAuthentication(t *testing.T) {
	a, _ := newApp(t)
	for _, tc := range []struct{ cookie, bearer string }{{"", ""}, {"garbage", ""}, {"", "ses_x.y"}} {
		w := call(a, "GET", "/v1/me/sessions", tc.cookie, tc.bearer)
		if w.Code != 401 || !strings.Contains(w.Body.String(), `"authentication_failed"`) {
			t.Fatalf("%+v: %d %s", tc, w.Code, w.Body)
		}
	}
	// 無効な Cookie は消す。
	w := call(a, "GET", "/v1/me/sessions", "garbage", "")
	if !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("invalid cookie not cleared: %q", w.Header().Get("Set-Cookie"))
	}
}

func TestListAndRevokeMySessions(t *testing.T) {
	a, _ := newApp(t)
	uid, tok := login(t, a)
	var second string
	err := a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		is, err := a.sessions.Issue(ctx, tx, session.Issue{RealmID: a.realm.ID, UserID: uid})
		second = is.Token
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	list := listSessions(t, a, "", tok)
	if len(list) != 2 {
		t.Fatalf("sessions = %v", list)
	}
	cur, _, _ := session.SplitToken(tok)
	for _, s := range list {
		if (s["id"] == cur) != (s["current"] == true) {
			t.Fatalf("current flag wrong: %v", s)
		}
	}
	sid, _, _ := session.SplitToken(second)
	if w := call(a, "POST", "/v1/me/sessions/"+sid+":revoke", "", tok); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w := call(a, "GET", "/v1/me/sessions", "", second); w.Code != 401 {
		t.Fatalf("revoked session still works: %d", w.Code)
	}
	// 他人のセッションは失効できず、有無も明かさない。
	_, other := login(t, a)
	osid, _, _ := session.SplitToken(other)
	for _, target := range []string{osid, id.New(id.Session)} {
		if w := call(a, "POST", "/v1/me/sessions/"+target+":revoke", "", tok); w.Code != 404 || !strings.Contains(w.Body.String(), "not_found") {
			t.Fatalf("revoke %s: %d %s", target, w.Code, w.Body)
		}
	}
	if len(listSessions(t, a, "", other)) != 1 {
		t.Fatal("other user's session was affected")
	}
}

func TestLogout(t *testing.T) {
	a, _ := newApp(t)
	_, tok := login(t, a)
	w := call(a, "POST", "/v1/logout", tok, "")
	if w.Code != 204 || !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	if w := call(a, "GET", "/v1/me/sessions", tok, ""); w.Code != 401 {
		t.Fatalf("session usable after logout: %d", w.Code)
	}
	// 未ログインでも 204。
	if w := call(a, "POST", "/v1/logout", "", ""); w.Code != 204 {
		t.Fatalf("logout without session: %d", w.Code)
	}
}

func TestCookieSessionRotates(t *testing.T) {
	a, clk := newApp(t)
	_, tok := login(t, a)
	clk.Advance(time.Hour)
	w := call(a, "GET", "/v1/me/sessions", tok, "")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var next string
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			next = c.Value
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
				t.Fatalf("cookie attributes: %+v", c)
			}
		}
	}
	if next == "" || next == tok {
		t.Fatal("cookie session was not rotated")
	}
	list := listSessions(t, a, next, "")
	nsid, _, _ := session.SplitToken(next)
	if len(list) != 1 || list[0]["id"] != nsid || list[0]["current"] != true {
		t.Fatalf("after rotation: %v", list)
	}
	// Bearer のセッションは入れ替えない（Set-Cookie を受け取れないため）。
	_, bt := login(t, a)
	clk.Advance(time.Hour)
	if w := call(a, "GET", "/v1/me/sessions", "", bt); w.Header().Get("Set-Cookie") != "" {
		t.Fatal("bearer session must not be rotated via cookie")
	}
}

func TestCrossOriginWriteRejected(t *testing.T) {
	a, _ := newApp(t)
	_, tok := login(t, a)
	w := call(a, "POST", "/v1/logout", tok, "", "Sec-Fetch-Site", "cross-site")
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST: %d", w.Code)
	}
	if w := call(a, "GET", "/v1/me/sessions", tok, ""); w.Code != 200 {
		t.Fatalf("session must survive the rejected request: %d", w.Code)
	}
}
