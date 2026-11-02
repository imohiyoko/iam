package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt/sdjwttest"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// OpenID4VP の検証者（ADR 0108）を、公開の HTTP（方式のエンドポイントと汎用のパス）で確かめる。

const vpVCT = "urn:eudi:pid:1"

type vpWallet struct {
	issuer *sdjwttest.Issuer
	holder *sdjwttest.Holder
}

func newVPEnv(t *testing.T, w *vpWallet) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Features = &[]string{feature.Org, feature.Warnings, feature.OpenID4VP}
		c.Server.PublicURL = "https://id.example"
		src := map[string]any{"openid4vp": map[string]any{"realms": map[string]any{c.Realm.Slug: map[string]any{
			"flows": []string{"cross_device", "same_device"}, "same_device_redirect_uri": "https://app.example/wallet",
			"vct_values": []string{vpVCT}, "subject_claim": []string{"sub"}, "attributes": map[string]any{"given_name": []string{"given_name"}},
			"issuers": []any{map[string]any{"iss": w.issuer.ISS, "jwks": w.issuer.JWKS()}},
		}}}}
		b, err := yaml.Marshal(src)
		if err != nil {
			t.Fatal(err)
		}
		var n map[string]yaml.Node
		if err := yaml.Unmarshal(b, &n); err != nil {
			t.Fatal(err)
		}
		c.Methods = n
	}, feature.Registered())
}

// read はウォレットとして authorization_request を読む。
func (w *vpWallet) read(t *testing.T, ch map[string]any) url.Values {
	t.Helper()
	u, err := url.Parse(ch["payload"].(map[string]any)["authorization_request"].(string))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("response_uri") != "https://id.example/v1/login/methods/openid4vp/endpoints/response" {
		t.Fatalf("response_uri = %s", q.Get("response_uri"))
	}
	return q
}

// respond はウォレットとして direct_post で提示を送る（別オリジンのフォームの POST）。
func (w *vpWallet) respond(t *testing.T, l *loginEnv, q url.Values, l2 *loginEnv) *httptest.ResponseRecorder {
	t.Helper()
	now := l.e.deps.Clock.Now()
	c := w.issuer.Issue(vpVCT, w.holder, map[string]any{"sub": "subject-1"}, map[string]any{"given_name": "Pat"}, now)
	vp, _ := json.Marshal(map[string]any{"credential": []string{w.holder.Present(c, q.Get("client_id"), q.Get("nonce"), now)}})
	form := url.Values{"state": {q.Get("state")}, "vp_token": {string(vp)}}
	return postForm(l2, "/v1/login/methods/openid4vp/endpoints/response", form)
}

func postForm(l *loginEnv, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// ウォレットは別のオリジンから送る（CrossOriginProtection の外であること）。
	r.Header.Set("Origin", "https://wallet.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(rec, r)
	return rec
}

func TestOpenID4VPEnrollAndLogin(t *testing.T) {
	w := &vpWallet{issuer: sdjwttest.NewIssuer("https://pid.example", "k1"), holder: sdjwttest.NewHolder()}
	l := newVPEnv(t, w)
	enrolled, full := l.login(t, "pat@example.com")

	// 登録（別の端末）。ウォレットの応答の前は 202。
	status, st := l.mePost(t, full, "/v1/me/credentials/openid4vp:enroll-begin", map[string]any{})
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	q := w.read(t, st)
	for range 3 {
		if status, res, _ := l.post(t, full, "/v1/me/credentials/openid4vp:enroll-complete", map[string]any{"flow_id": st["flow_id"]}); status != 202 || res["status"] != "pending" {
			t.Fatalf("pending enrollment: %d %v", status, res)
		}
	}
	if rec := w.respond(t, l, q, l); rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("wallet response: %d %s", rec.Code, rec.Body)
	}
	status, res, _ := l.post(t, full, "/v1/me/credentials/openid4vp:enroll-complete", map[string]any{"flow_id": st["flow_id"]})
	if status != 200 || res["credential"].(map[string]any)["method"] != "openid4vp" || res["payload"].(map[string]any)["attributes"].(map[string]any)["given_name"] != "Pat" {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}

	// 1要素目のログイン（同じ端末。ウォレットが戻す response_code を添える）。
	status, ch, _ := l.post(t, "", "/v1/login/methods/openid4vp:begin", map[string]any{"payload": map[string]any{"flow": "same_device"}})
	if status != 200 {
		t.Fatalf("begin: %d %v", status, ch)
	}
	q = w.read(t, ch)
	rec := w.respond(t, l, q, l)
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	code, ok := strings.CutPrefix(body["redirect_uri"], "https://app.example/wallet#response_code=")
	if rec.Code != 200 || !ok {
		t.Fatalf("same-device response: %d %s", rec.Code, rec.Body)
	}
	if status, _, _ := l.post(t, "", "/v1/login/methods/openid4vp:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"response_code": "wrong"}}); status != 401 {
		t.Fatalf("wrong response_code: %d", status)
	}
	status, login, cookie := l.post(t, "", "/v1/login/methods/openid4vp:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"response_code": code}})
	if status != 200 || cookie == "" || login["user_id"] == nil || login["user_id"] != enrolled["user_id"] {
		t.Fatalf("login: %d %v (enrolled by %v)", status, login, enrolled["user_id"])
	}
	if got := amr(t, l, cookie); !slices.Contains(got, any("swk")) {
		t.Fatalf("amr: %v", got)
	}
	if len(l.auditOf(t, "method.openid4vp.presentation_received")) != 2 || len(l.auditOf(t, "login.succeeded")) == 0 {
		t.Fatal("presentation not audited")
	}

	// 同じ応答は 2 度受けない。知らない state も 400。
	if rec := w.respond(t, l, q, l); rec.Code != 400 {
		t.Fatalf("replayed response: %d", rec.Code)
	}
	// フォーム以外の本文、知らないエンドポイント・方式は受けない。
	r := httptest.NewRequest("POST", "/v1/login/methods/openid4vp/endpoints/response", strings.NewReader(`{"state":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(rr, r)
	if rr.Code != 400 {
		t.Fatalf("json body: %d", rr.Code)
	}
	if rec := postForm(l, "/v1/login/methods/hotp/endpoints/response", url.Values{}); rec.Code != 404 {
		t.Fatalf("method without endpoints: %d", rec.Code)
	}
	if rec := postForm(l, "/v1/login/methods/openid4vp/endpoints/Bad", url.Values{}); rec.Code == 200 {
		t.Fatalf("invalid endpoint name: %d", rec.Code)
	}
	r = httptest.NewRequest("GET", "/v1/login/methods/openid4vp/endpoints/request?id=unknown", nil)
	rr = httptest.NewRecorder()
	l.a.PublicHandler().ServeHTTP(rr, r)
	if rr.Code != 400 {
		t.Fatalf("unknown request object: %d", rr.Code)
	}

	// 失敗した提示は監査ログに残り、ブラウザの complete も失敗する。
	status, ch, _ = l.post(t, "", "/v1/login/methods/openid4vp:begin", map[string]any{"payload": map[string]any{"flow": "cross_device"}})
	if status != 200 {
		t.Fatal(status)
	}
	q = w.read(t, ch)
	if rec := postForm(l, "/v1/login/methods/openid4vp/endpoints/response", url.Values{"state": {q.Get("state")}, "error": {"access_denied"}}); rec.Code != 400 {
		t.Fatalf("wallet error: %d", rec.Code)
	}
	if status, _, _ := l.post(t, "", "/v1/login/methods/openid4vp:complete", map[string]any{"flow_id": ch["flow_id"]}); status != 401 {
		t.Fatalf("complete after wallet error: %d", status)
	}
	if len(l.auditOf(t, "method.openid4vp.presentation_rejected")) != 1 {
		t.Fatal("rejection not audited")
	}

	// フィーチャーの無効化で結び付けを消す。
	disableWithData(t, l, feature.OpenID4VP, 1)
}

func TestOpenID4VPOffOrUnconfigured(t *testing.T) {
	// フィーチャーが動いていなければ、方式もエンドポイントも無い。
	l := newLoginEnvWith(t, func(c *config.Config) { c.Features = &[]string{feature.Org, feature.Warnings} }, feature.Registered())
	if rec := postForm(l, "/v1/login/methods/openid4vp/endpoints/response", url.Values{}); rec.Code != http.StatusNotFound {
		t.Fatalf("feature off: %d", rec.Code)
	}
	if status, _, _ := l.post(t, "", "/v1/login/methods/openid4vp:begin", map[string]any{}); status != 404 {
		t.Fatalf("feature off begin: %d", status)
	}
	// 動いていても、realm の設定が無ければ方式を動かさない。
	l = newLoginEnvWith(t, func(c *config.Config) { c.Features = &[]string{feature.Org, feature.Warnings, feature.OpenID4VP} }, feature.Registered())
	if status, _, _ := l.post(t, "", "/v1/login/methods/openid4vp:begin", map[string]any{}); status != 404 {
		t.Fatalf("unconfigured begin: %d", status)
	}
}
