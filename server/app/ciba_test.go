package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// CIBA（ADR 0114）を HTTP で確かめる。

func cibaEnv(t *testing.T, extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
		if slices.Contains(extra, feature.PushAuth) {
			c.Methods = methodOptions(t, map[string]map[string]string{"push": {"per_user": "20"}})
		}
	}, feature.Registered())
}

// cibaRP は CIBA の連携先を登録する（戻り先なし、client_secret）。
func (l *loginEnv) cibaRP(t *testing.T, owner string, body map[string]any) *rp {
	t.Helper()
	if body["name"] == nil {
		body["name"] = "Call Center"
	}
	if body["redirect_uris"] == nil {
		body["redirect_uris"] = []string{}
	}
	if body["token_endpoint_auth_method"] == nil {
		body["token_endpoint_auth_method"] = "client_secret"
	}
	code, out := l.admin(t, "/v1/admin/clients", owner, body)
	if code != 201 || out["backchannel_token_delivery_mode"] != body["backchannel_token_delivery_mode"] {
		t.Fatalf("register ciba client: %d %v", code, out)
	}
	return &rp{l: l, clientID: out["client_id"].(string), secret: out["client_secret"].(string)}
}

func (p *rp) bcAuthorize(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	return p.post(t, oidcBackchannel, form)
}

func (p *rp) pollCIBA(t *testing.T, id string) (int, map[string]any) {
	t.Helper()
	return p.post(t, oidcToken, url.Values{"grant_type": {provider.GrantTypeCIBA}, "auth_req_id": {id}})
}

func discoveryOf(t *testing.T, l *loginEnv) map[string]any {
	t.Helper()
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	var disc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	return disc
}

func TestCIBAOff(t *testing.T) {
	l := cibaEnv(t)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	disc := discoveryOf(t, l)
	gt, _ := disc["grant_types_supported"].([]any)
	if disc["backchannel_authentication_endpoint"] != nil || disc["backchannel_token_delivery_modes_supported"] != nil ||
		slices.Contains(gt, any(provider.GrantTypeCIBA)) {
		t.Fatalf("discovery shows CIBA: %v", disc)
	}
	if code, out := l.admin(t, "/v1/admin/clients", owner, map[string]any{"name": "CC", "redirect_uris": []string{"https://cc.example.com/cb"},
		"token_endpoint_auth_method": "client_secret", "backchannel_token_delivery_mode": "poll"}); code != 400 {
		t.Fatalf("ciba registration while off: %d %v", code, out)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if w := l.oidcDo(t, "POST", oidcBackchannel, url.Values{"client_id": {p.clientID}}, ""); w.Code != 404 {
		t.Fatalf("bc-authorize while off: %d", w.Code)
	}
	if status, out := p.pollCIBA(t, "x"); status != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("ciba grant while off: %d %v", status, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil); code != 404 {
		t.Fatalf("me api while off: %d", code)
	}
}

func TestCIBAClients(t *testing.T) {
	l := cibaEnv(t, feature.CIBA)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for name, body := range map[string]map[string]any{
		"public client":      {"token_endpoint_auth_method": "none", "backchannel_token_delivery_mode": "poll"},
		"ping without uri":   {"token_endpoint_auth_method": "client_secret", "backchannel_token_delivery_mode": "ping"},
		"ping with http uri": {"token_endpoint_auth_method": "client_secret", "backchannel_token_delivery_mode": "ping", "backchannel_client_notification_endpoint": "http://cc.example.com/n"},
		"poll with uri":      {"token_endpoint_auth_method": "client_secret", "backchannel_token_delivery_mode": "poll", "backchannel_client_notification_endpoint": "https://cc.example.com/n"},
		"uri without mode":   {"token_endpoint_auth_method": "client_secret", "backchannel_client_notification_endpoint": "https://cc.example.com/n"},
		"push mode":          {"token_endpoint_auth_method": "client_secret", "backchannel_token_delivery_mode": "push"},
	} {
		body["name"], body["redirect_uris"] = "CC", []string{}
		if code, out := l.admin(t, "/v1/admin/clients", owner, body); code != 400 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	p := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "ping", "backchannel_client_notification_endpoint": "https://cc.example.com/n"})
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/clients/"+p.clientID, nil); code != 200 ||
		out["backchannel_client_notification_endpoint"] != "https://cc.example.com/n" {
		t.Fatalf("client: %d %v", code, out)
	}
	disc := discoveryOf(t, l)
	gt, _ := disc["grant_types_supported"].([]any)
	modes, _ := disc["backchannel_token_delivery_modes_supported"].([]any)
	if disc["backchannel_authentication_endpoint"] != testIssuer+oidcBackchannel || !slices.Contains(gt, any(provider.GrantTypeCIBA)) ||
		!slices.Equal(modes, []any{"poll", "ping"}) || disc["backchannel_user_code_parameter_supported"] != false {
		t.Fatalf("discovery: %v", disc)
	}
	// CIBA を登録していない連携先は使えない。
	web := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	if status, out := web.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}}); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("not registered: %d %v", status, out)
	}
	if status, out := web.pollCIBA(t, "x"); status != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("not registered at token: %d %v", status, out)
	}
	// 連携先の認証が要る。
	if w := l.oidcDo(t, "POST", oidcBackchannel, url.Values{"client_id": {p.clientID}, "scope": {"openid"}, "login_hint": {"alice@example.com"}}, ""); w.Code != 401 {
		t.Fatalf("no client auth: %d %s", w.Code, w.Body)
	}
	bad := &rp{l: l, clientID: p.clientID, secret: "wrong"}
	if status, out := bad.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}}); status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("bad secret: %d %v", status, out)
	}
}

func TestCIBAPollSelfService(t *testing.T) {
	l := cibaEnv(t, feature.CIBA)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "poll"})
	_, cookie := l.login(t, "alice@example.com")
	alice := l.userID(t, "alice@example.com")

	// 要求の誤り。
	for name, c := range map[string]struct {
		form url.Values
		want string
	}{
		"no openid":         {url.Values{"scope": {"email"}, "login_hint": {"alice@example.com"}}, "invalid_scope"},
		"no hint":           {url.Values{"scope": {"openid"}}, "invalid_request"},
		"two hints":         {url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}, "id_token_hint": {"x"}}, "invalid_request"},
		"login_hint_token":  {url.Values{"scope": {"openid"}, "login_hint_token": {"x"}}, "invalid_request"},
		"signed request":    {url.Values{"request": {"x.y.z"}}, "invalid_request"},
		"binding message":   {url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}, "binding_message": {"a\nb"}}, "invalid_binding_message"},
		"long binding":      {url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}, "binding_message": {strings.Repeat("x", 65)}}, "invalid_binding_message"},
		"requested_expiry":  {url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}, "requested_expiry": {"-1"}}, "invalid_request"},
		"unknown email":     {url.Values{"scope": {"openid"}, "login_hint": {"nobody@example.com"}}, "unknown_user_id"},
		"unknown public id": {url.Values{"scope": {"openid"}, "login_hint": {"usr_nobody"}}, "unknown_user_id"},
		"bad id_token_hint": {url.Values{"scope": {"openid"}, "id_token_hint": {"a.b.c"}}, "unknown_user_id"},
	} {
		if status, out := p.bcAuthorize(t, c.form); status != 400 || out["error"] != c.want {
			t.Fatalf("%s: %d %v", name, status, out)
		}
	}

	status, res := p.bcAuthorize(t, url.Values{"scope": {"openid email"}, "login_hint": {"alice@example.com"}, "binding_message": {"W4SCT"}})
	id, _ := res["auth_req_id"].(string)
	if status != 200 || id == "" || res["expires_in"] != float64(300) || res["interval"] != float64(5) {
		t.Fatalf("bc-authorize: %d %v", status, res)
	}
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", status, out)
	}
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "slow_down" {
		t.Fatalf("slow down: %d %v", status, out)
	}
	// 別の連携先の auth_req_id は使えない。
	other := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "poll"})
	if status, out := other.pollCIBA(t, id); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("other client: %d %v", status, out)
	}

	// 本人の API で一覧し、承認する。別人には見えない。
	code, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	reqs, _ := list["backchannel_requests"].([]any)
	if code != 200 || len(reqs) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	r0 := reqs[0].(map[string]any)
	if r0["client_id"] != p.clientID || r0["client_name"] != "Call Center" || r0["binding_message"] != "W4SCT" || r0["auth_req_id"] != nil ||
		!slices.Equal(r0["scopes"].([]any), []any{"openid", "email"}) {
		t.Fatalf("request: %v", r0)
	}
	_, bobCookie := l.login(t, "bob@example.com")
	if code, list := l.meDo(t, "GET", bobCookie, "/v1/me/backchannel-requests", nil); code != 200 || len(list["backchannel_requests"].([]any)) != 0 {
		t.Fatalf("bob sees alice's request: %v", list)
	}
	rid := r0["id"].(string)
	if code, _ := l.meDo(t, "POST", bobCookie, "/v1/me/backchannel-requests/"+rid+":approve", nil); code != 404 {
		t.Fatalf("bob approves alice's request: %d", code)
	}
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":approve", nil); code != 204 {
		t.Fatalf("approve: %d", code)
	}
	// 判断は1回だけ。
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":deny", nil); code != 404 {
		t.Fatalf("decide twice: %d", code)
	}
	l.advance(10 * time.Second)
	status, tok := p.pollCIBA(t, id)
	if status != 200 || tok["access_token"] == nil || tok["id_token"] == nil || tok["refresh_token"] == nil || tok["scope"] != "openid email" {
		t.Fatalf("token: %d %v", status, tok)
	}
	claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256)
	if claims["sub"] != alice || claims["aud"] != p.clientID || claims["sid"] == nil || claims["nonce"] != nil {
		t.Fatalf("id token: %v", claims)
	}
	if status, info := l.userinfo(t, tok["access_token"].(string)); status != 200 || info["sub"] != alice {
		t.Fatalf("userinfo: %d %v", status, info)
	}
	l.advance(10 * time.Second)
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("poll after tokens: %d %v", status, out)
	}

	// id_token_hint（この連携先に発行した ID トークン）で本人を指せる。別の連携先のものは使えない。
	if status, out := other.bcAuthorize(t, url.Values{"scope": {"openid"}, "id_token_hint": {tok["id_token"].(string)}}); status != 400 || out["error"] != "unknown_user_id" {
		t.Fatalf("id_token_hint of another client: %d %v", status, out)
	}
	status, res = p.bcAuthorize(t, url.Values{"scope": {"openid"}, "id_token_hint": {tok["id_token"].(string)}, "requested_expiry": {"60"}})
	if status != 200 || res["expires_in"] != float64(60) {
		t.Fatalf("id_token_hint: %d %v", status, res)
	}
	id = res["auth_req_id"].(string)
	_, list = l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	rid = list["backchannel_requests"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":deny", nil); code != 204 {
		t.Fatalf("deny: %d", code)
	}
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "access_denied" {
		t.Fatalf("denied: %d %v", status, out)
	}

	// 公開 ID の login_hint、期限切れは expired_token。
	status, res = p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {alice}})
	if status != 200 {
		t.Fatalf("public id hint: %d %v", status, res)
	}
	l.advance(l.a.cfg.OIDC.CIBATTL.D())
	if status, out := p.pollCIBA(t, res["auth_req_id"].(string)); status != 400 || out["error"] != "expired_token" {
		t.Fatalf("expired: %d %v", status, out)
	}
	if code, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil); code != 200 || len(list["backchannel_requests"].([]any)) != 0 {
		t.Fatalf("expired request listed: %v", list)
	}

	types := map[string]map[string]any{}
	for _, e := range l.auditTypes(t) {
		types[e.Type] = e.Details
	}
	if types["oidc.ciba_requested"]["client_id"] != p.clientID || types["oidc.ciba_approved"]["channel"] != "self_service" ||
		types["oidc.ciba_denied"] == nil || types["oidc.authorized"]["grant_type"] != provider.GrantTypeCIBA {
		t.Fatalf("audit: %v", types)
	}
	for _, e := range l.auditTypes(t) {
		if b, _ := json.Marshal(e); strings.Contains(string(b), id) || strings.Contains(string(b), "W4SCT") {
			t.Fatalf("secret or binding message in audit log: %s", b)
		}
	}
}

// TestCIBAPushPing は、本人の端末（プッシュの承認）で承認し、ping の連携先に通知が届くことを確かめる。
func TestCIBAPushPing(t *testing.T) {
	l := cibaEnv(t, feature.CIBA, feature.PushAuth)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	type note struct{ auth, id string }
	notes := make(chan note, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]string
		_ = json.Unmarshal(b, &v)
		notes <- note{auth: r.Header.Get("Authorization"), id: v["auth_req_id"]}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	p := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "ping", "backchannel_client_notification_endpoint": srv.URL + "/ciba"})

	_, cookie := l.login(t, "pat@example.com")
	d := newDevice(t)
	if status, res := d.enroll(t, l, cookie); status != 200 {
		t.Fatalf("enroll: %d %v", status, res)
	}
	// ping は client_notification_token が要る。
	if status, out := p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"pat@example.com"}}); status != 400 || out["error"] != "invalid_request" {
		t.Fatalf("ping without token: %d %v", status, out)
	}
	const token = "notify-token-0123456789"
	start := func() (string, port.PushMessage) {
		t.Helper()
		before := len(l.pushes().sent)
		status, res := p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"pat@example.com"}, "binding_message": {"Order 42"},
			"client_notification_token": {token}})
		if status != 200 || len(l.pushes().sent) != before+1 {
			t.Fatalf("bc-authorize: %d %v", status, res)
		}
		return res["auth_req_id"].(string), l.pushes().last(t)
	}
	callback := func(payload map[string]any) (int, map[string]any) {
		w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/methods/push:callback", map[string]any{"payload": payload})
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	id, msg := start()
	if msg.DeviceID != d.id {
		t.Fatalf("push: %+v", msg)
	}
	// 端末は中身を取って見せる。
	status, out := callback(map[string]any{"action": "context", "device_id": d.id, "challenge_id": msg.ChallengeID,
		"signature": d.sign(t, "context", msg.ChallengeID, d.id)})
	ctxv, _ := out["payload"].(map[string]any)
	if status != 200 || ctxv["kind"] != "backchannel" || ctxv["client"] != "Call Center" || ctxv["binding_message"] != "Order 42" {
		t.Fatalf("context: %d %v", status, out)
	}
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", status, out)
	}
	if status, out := d.respond(t, l, msg.ChallengeID, "approve", "00"); status != 200 || out["payload"].(map[string]any)["result"] != "approved" {
		t.Fatalf("approve: %d %v", status, out)
	}
	select {
	case n := <-notes:
		if n.auth != "Bearer "+token || n.id != id {
			t.Fatalf("notification: %+v", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ping notification")
	}
	// 判断の後は本人の一覧に出ない。
	if code, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil); code != 200 || len(list["backchannel_requests"].([]any)) != 0 {
		t.Fatalf("decided request listed: %v", list)
	}
	l.advance(10 * time.Second)
	status, tok := p.pollCIBA(t, id)
	if status != 200 || tok["id_token"] == nil {
		t.Fatalf("token: %d %v", status, tok)
	}
	claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256)
	if claims["sub"] != l.userID(t, "pat@example.com") || !slices.Equal(claims["amr"].([]any), []any{"swk"}) || claims["sid"] == nil {
		t.Fatalf("id token: %v", claims)
	}
	// CIBA 用のセッションは本人のセッションの一覧に出て、失効させればトークンも止まる。
	sid := claims["sid"].(string)
	if status, info := l.userinfo(t, tok["access_token"].(string)); status != 200 {
		t.Fatalf("userinfo: %d %v", status, info)
	}
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/sessions/"+sid+":revoke", nil); code != 204 {
		t.Fatalf("revoke the backchannel session: %d", code)
	}
	if status, _ := l.userinfo(t, tok["access_token"].(string)); status != 401 {
		t.Fatalf("token after revoking the backchannel session: %d", status)
	}

	// 端末で拒否すれば access_denied（通知も届く）。
	id, msg = start()
	if status, _ := d.respond(t, l, msg.ChallengeID, "deny", "00"); status != 200 {
		t.Fatalf("deny: %d", status)
	}
	<-notes
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "access_denied" {
		t.Fatalf("denied: %d %v", status, out)
	}
	// 本人の API で先に判断したら、端末の応答は記録しない。
	id, msg = start()
	_, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	rid := list["backchannel_requests"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":deny", nil); code != 204 {
		t.Fatalf("deny via api: %d", code)
	}
	<-notes
	if status, _ := d.respond(t, l, msg.ChallengeID, "approve", "00"); status != 200 {
		t.Fatalf("late approve: %d", status)
	}
	if status, out := p.pollCIBA(t, id); status != 400 || out["error"] != "access_denied" {
		t.Fatalf("api decision first: %d %v", status, out)
	}

	if ev := l.auditOf(t, "oidc.ciba_approved"); len(ev) != 1 || ev[0].Details["channel"] != "push" {
		t.Fatalf("approved events: %+v", ev)
	}
	if ev := l.auditOf(t, "oidc.ciba_requested"); len(ev) != 3 || ev[0].Details["channel"] != "push" {
		t.Fatalf("requested events: %+v", ev)
	}
}

// TestCIBAPushWithoutDevice は、端末の無い本人の要求も受け付け、本人の API で承認できることを確かめる。
func TestCIBAPushWithoutDevice(t *testing.T) {
	l := cibaEnv(t, feature.CIBA, feature.PushAuth)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "poll"})
	_, cookie := l.login(t, "alice@example.com")
	status, res := p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}})
	if status != 200 || len(l.pushes().sent) != 0 {
		t.Fatalf("bc-authorize: %d %v", status, res)
	}
	if ev := l.auditOf(t, "oidc.ciba_requested"); len(ev) != 1 || ev[0].Details["channel"] != "none" {
		t.Fatalf("requested events: %+v", ev)
	}
	_, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	rid := list["backchannel_requests"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":approve", nil); code != 204 {
		t.Fatalf("approve: %d", code)
	}
	if status, tok := p.pollCIBA(t, res["auth_req_id"].(string)); status != 200 || tok["access_token"] == nil {
		t.Fatalf("token: %d %v", status, tok)
	}
}

func TestDisableCIBAWithData(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		names := []string{}
		for _, f := range feature.Registered() {
			names = append(names, f.Name)
		}
		c.Features = &names
		c.Methods = methodOptions(t, map[string]map[string]string{"push": {"per_user": "20"}})
	}, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "poll"})
	disableWithData(t, l, feature.CIBA, 1)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		cs, err := tx.Clients().List(ctx, l.a.realm.ID)
		if err == nil && (len(cs) != 1 || cs[0].CIBAMode != "") {
			t.Fatalf("clients after disable: %+v", cs)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCIBAACR は、要求の acr_values を承認したセッションが満たさなければ拒否として記録することを確かめる（ADR 0093、0114）。
func TestCIBAACR(t *testing.T) {
	l := cibaEnv(t, feature.CIBA, feature.ACR)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.cibaRP(t, owner, map[string]any{"backchannel_token_delivery_mode": "poll"})
	_, cookie := l.login(t, "alice@example.com")
	status, res := p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}, "acr_values": {acr.AAL2}})
	if status != 200 {
		t.Fatalf("bc-authorize: %d %v", status, res)
	}
	_, list := l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	rid := list["backchannel_requests"].([]any)[0].(map[string]any)["id"].(string)
	if code, out := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":approve", nil); code != 403 || out["error"] != "unmet_authentication_requirements" {
		t.Fatalf("approve with a weaker session: %d %v", code, out)
	}
	if status, out := p.pollCIBA(t, res["auth_req_id"].(string)); status != 400 || out["error"] != "access_denied" {
		t.Fatalf("poll: %d %v", status, out)
	}
	// 満たす要求なら acr が ID トークンに載る。
	status, res = p.bcAuthorize(t, url.Values{"scope": {"openid"}, "login_hint": {"alice@example.com"}, "acr_values": {acr.AAL1}})
	if status != 200 {
		t.Fatalf("bc-authorize: %d %v", status, res)
	}
	_, list = l.meDo(t, "GET", cookie, "/v1/me/backchannel-requests", nil)
	rid = list["backchannel_requests"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := l.meDo(t, "POST", cookie, "/v1/me/backchannel-requests/"+rid+":approve", nil); code != 204 {
		t.Fatalf("approve: %d", code)
	}
	status, tok := p.pollCIBA(t, res["auth_req_id"].(string))
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	if claims := l.idClaims(t, tok["id_token"].(string), port.AlgES256); claims["acr"] != acr.AAL1 {
		t.Fatalf("acr: %v", claims)
	}
}
