package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// フロー フック（design.md 11.8、ADR 0081）を HTTP で確かめる。

// fakeHook は Go のインターフェースで実装したフック。呼ばれた入力を残し、decide の結果を返す。
type fakeHook struct {
	mu     sync.Mutex
	calls  []port.HookInput
	decide func(port.HookInput) (port.HookResult, error)
}

func (h *fakeHook) Call(_ context.Context, in port.HookInput) (port.HookResult, error) {
	h.mu.Lock()
	h.calls = append(h.calls, in)
	h.mu.Unlock()
	if h.decide == nil {
		return port.HookResult{Allow: true}, nil
	}
	return h.decide(in)
}

func (h *fakeHook) last(t *testing.T) port.HookInput {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.calls) == 0 {
		t.Fatal("hook not called")
	}
	return h.calls[len(h.calls)-1]
}

func hooksEnv(t *testing.T, hooks map[string]*fakeHook, failOpen map[string]bool) *loginEnv {
	t.Helper()
	return newLoginEnvDeps(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.FlowHooks)
		c.Features = &names
		c.Hooks = map[string]config.Hook{}
		for name := range hooks {
			c.Hooks[name] = config.Hook{Timeout: config.Duration(100 * time.Millisecond), FailOpen: failOpen[name]}
		}
	}, feature.Registered(), func(d *Deps) {
		d.Hooks = map[string]port.FlowHook{}
		for name, h := range hooks {
			d.Hooks[name] = h
		}
	})
}

func bodyReasons(w []byte) string {
	var out map[string]any
	_ = json.Unmarshal(w, &out)
	return reasonsOf(out)
}

func TestFlowHooksRegistrationAndLogin(t *testing.T) {
	pre := &fakeHook{decide: func(in port.HookInput) (port.HookResult, error) {
		return port.HookResult{Allow: strings.HasSuffix(in.Email, "@example.com"), Reason: "domain"}, nil
	}}
	blocked := ""
	post := &fakeHook{decide: func(in port.HookInput) (port.HookResult, error) {
		if in.UserID == blocked {
			return port.HookResult{Allow: false}, nil
		}
		return port.HookResult{Allow: true}, nil
	}}
	l := hooksEnv(t, map[string]*fakeHook{port.HookPreRegistration: pre, port.HookPostAuthentication: post}, nil)

	// pre_registration：登録を止める。止められた登録はユーザーを作らない。
	w := l.loginVerify(t, "eve@evil.example")
	if w.Code != 403 || !strings.Contains(bodyReasons(w.Body.Bytes()), "hook_denied.pre_registration") {
		t.Fatalf("denied signup: %d %s", w.Code, w.Body)
	}
	if in := pre.last(t); in.Email != "eve@evil.example" || in.Realm == "" || in.VerifiedVia != string(port.VerifiedViaCode) {
		t.Fatalf("pre_registration input: %+v", in)
	}
	_, cookie := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	if in := post.last(t); in.Hook != port.HookPostAuthentication || in.UserID != aliceID || len(in.AuthMethods) == 0 {
		t.Fatalf("post_authentication input: %+v", in)
	}
	if code, _ := l.me(t, cookie); code != 200 {
		t.Fatalf("me: %d", code)
	}
	// 既存のユーザーのログインでは pre_registration を呼ばない。
	n := len(pre.calls)
	l.login(t, "alice@example.com")
	if len(pre.calls) != n {
		t.Fatal("pre_registration called for an existing user")
	}

	// post_authentication：ログインを止める。セッションは作らない。
	blocked = aliceID
	w = l.loginVerify(t, "alice@example.com")
	if w.Code != 403 || !strings.Contains(bodyReasons(w.Body.Bytes()), "hook_denied.post_authentication") {
		t.Fatalf("denied login: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("session cookie on a denied login")
		}
	}
}

func TestFlowHooksFailure(t *testing.T) {
	broken := func(port.HookInput) (port.HookResult, error) { return port.HookResult{}, errors.New("down") }
	slow := func(in port.HookInput) (port.HookResult, error) {
		time.Sleep(300 * time.Millisecond)
		return port.HookResult{Allow: true}, nil
	}
	// fail-closed：失敗は止める。fail-open：失敗は通す。
	l := hooksEnv(t, map[string]*fakeHook{port.HookPreRegistration: {decide: broken}}, nil)
	if w := l.loginVerify(t, "bob@example.com"); w.Code != 403 {
		t.Fatalf("fail-closed: %d %s", w.Code, w.Body)
	}
	l = hooksEnv(t, map[string]*fakeHook{port.HookPreRegistration: {decide: broken}, port.HookPostAuthentication: {decide: slow}},
		map[string]bool{port.HookPreRegistration: true, port.HookPostAuthentication: true})
	if w := l.loginVerify(t, "bob@example.com"); w.Code != 200 {
		t.Fatalf("fail-open: %d %s", w.Code, w.Body)
	}
	// タイムアウトは失敗として扱う（fail-closed なら止める）。
	l = hooksEnv(t, map[string]*fakeHook{port.HookPostAuthentication: {decide: slow}}, nil)
	if w := l.loginVerify(t, "bob@example.com"); w.Code != 403 {
		t.Fatalf("timeout: %d %s", w.Code, w.Body)
	}
}

func TestFlowHooksMembershipEnd(t *testing.T) {
	hold := true
	end := &fakeHook{decide: func(port.HookInput) (port.HookResult, error) { return port.HookResult{Allow: !hold}, nil }}
	l := hooksEnv(t, map[string]*fakeHook{port.HookPreMembershipEnd: end}, nil)
	_, owner := l.login(t, "boss@example.com")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@example.com", "member")
	_, pat := l.login(t, "pat@example.com")
	if code, body := l.mePost(t, pat, "/v1/me/orgs/"+acme+":leave", nil); code != 409 || body["error"] != "membership_end_held" {
		t.Fatalf("held leave: %d %v", code, body)
	}
	in := end.last(t)
	if in.OrgID != acme || in.UserID != l.userID(t, "pat@example.com") || in.EndReason != "left" || in.MembershipID == "" {
		t.Fatalf("pre_membership_end input: %+v", in)
	}
	hold = false
	if code, body := l.mePost(t, pat, "/v1/me/orgs/"+acme+":leave", nil); code != 204 {
		t.Fatalf("leave: %d %v", code, body)
	}
}

func TestFlowHooksPreToken(t *testing.T) {
	claims := map[string]any{"tenant": "acme", "level": 3}
	tok := &fakeHook{decide: func(port.HookInput) (port.HookResult, error) {
		return port.HookResult{Allow: true, Claims: claims}, nil
	}}
	l := hooksEnv(t, map[string]*fakeHook{port.HookPreToken: tok}, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	code, _ := p.login(t, "alice@example.com", url.Values{"scope": {"openid email"}})
	status, out := p.exchange(t, code, nil)
	if status != 200 {
		t.Fatalf("token: %d %v", status, out)
	}
	c := l.idClaims(t, out["id_token"].(string), port.AlgES256)
	if c["tenant"] != "acme" || c["level"] != float64(3) {
		t.Fatalf("id token claims: %v", c)
	}
	if in := tok.last(t); in.ClientID != p.clientID || !strings.Contains(strings.Join(in.Scopes, " "), "email") {
		t.Fatalf("pre_token input: %+v", in)
	}

	// 予約済みのクレームは足せない（トークンを発行しない）。
	claims = map[string]any{"sub": "someone-else"}
	code, _ = p.login(t, "alice@example.com", nil)
	if status, out := p.exchange(t, code, nil); status == 200 {
		t.Fatalf("reserved claim: %d %v", status, out)
	}
	// 止めれば invalid_grant。
	tok.decide = func(port.HookInput) (port.HookResult, error) { return port.HookResult{Allow: false}, nil }
	code, _ = p.login(t, "alice@example.com", nil)
	if status, out := p.exchange(t, code, nil); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("denied token: %d %v", status, out)
	}
}
