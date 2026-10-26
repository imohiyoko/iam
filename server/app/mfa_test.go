package app

import (
	"encoding/base32"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authn/totp"
	"github.com/imohiyoko/iam/server/config"
)

// 2段階認証（design.md 4.1、2.8）を HTTP で確かめる。

// post は Cookie のセッションで POST し、応答と差し替えたセッションの Cookie（無ければ空）を返す。
func (l *loginEnv) post(t *testing.T, cookie, path string, body any) (int, map[string]any, string) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", path, body, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return w.Code, out, c.Value
		}
	}
	return w.Code, out, ""
}

func (l *loginEnv) advance(d time.Duration) {
	l.e.deps.Clock.(interface{ Advance(time.Duration) }).Advance(d)
}

func (l *loginEnv) code(t *testing.T, secret []byte) string {
	t.Helper()
	return totp.Code(secret, totp.Step(l.e.deps.Clock.Now()))
}

// enrollTOTP は Cookie のユーザーに TOTP を登録し、秘密と確認の応答を返す。
func (l *loginEnv) enrollTOTP(t *testing.T, cookie string) ([]byte, int, map[string]any, string) {
	t.Helper()
	status, st := l.mePost(t, cookie, "/v1/me/totp:start", nil)
	if status != 200 {
		t.Fatalf("totp start: %d %v", status, st)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(st["secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	status, res, swapped := l.post(t, cookie, "/v1/me/totp:confirm", map[string]string{"flow_id": st["flow_id"].(string), "code": l.code(t, secret)})
	return secret, status, res, swapped
}

func amr(t *testing.T, l *loginEnv, cookie string) []any {
	t.Helper()
	status, ss := l.me(t, cookie)
	if status != 200 || len(ss) == 0 {
		t.Fatalf("me: %d", status)
	}
	for _, s := range ss {
		if s["current"] == true {
			return s["auth_methods"].([]any)
		}
	}
	t.Fatal("no current session")
	return nil
}

func TestTOTPSecondFactor(t *testing.T) {
	l := newLoginEnv(t)
	_, full := l.login(t, "pat@example.com")
	secret, status, res, swapped := l.enrollTOTP(t, full)
	if status != 200 || res["login"] != nil || swapped != "" {
		t.Fatalf("totp confirm: %d %v", status, res)
	}
	id := res["totp"].(map[string]any)["id"].(string)
	if status, res := l.mePost(t, full, "/v1/me/totp:start", nil); status != 409 || res["error"] != "totp_exists" {
		t.Fatalf("enroll twice: %d %v", status, res)
	}
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+full)
	var m struct{ Totp []struct{ ID string } }
	if json.Unmarshal(w.Body.Bytes(), &m) != nil || len(m.Totp) != 1 || m.Totp[0].ID != id {
		t.Fatalf("methods: %s", w.Body)
	}

	// TOTP を登録したユーザーは、メールの後に2要素目を求められる。
	login, restricted := l.login(t, "pat@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"totp"}) {
		t.Fatalf("login: %v", login)
	}
	// 制限つきのセッションは、決まった API の他では未ログインの扱い。
	if status, _ := l.me(t, restricted); status != 401 {
		t.Fatalf("restricted session used for me: %d", status)
	}
	if status, _ := l.mePost(t, restricted, "/v1/me/totp:start", nil); status != 401 {
		t.Fatalf("restricted session enrolls: %d", status)
	}
	if status, _ := l.mePost(t, full, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)}); status != 401 {
		t.Fatalf("verify on a full session: %d", status)
	}
	l.advance(30 * time.Second)
	wrong := "000000"
	if l.code(t, secret) == wrong {
		wrong = "000001"
	}
	if status, _, _ := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": wrong}); status != 401 {
		t.Fatalf("wrong code: %d", status)
	}
	code := l.code(t, secret)
	status, res, upgraded := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": code})
	if status != 200 || res["next"] != nil || res["user_id"] != login["user_id"] || upgraded == "" {
		t.Fatalf("verify: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "mfa"}) { // メールのコードも TOTP も otp（RFC 8176）
		t.Fatalf("amr: %v", got)
	}
	if status, _ := l.mePost(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": code}); status != 401 {
		t.Fatalf("restricted session after upgrade: %d", status)
	}
	// 同じ窓のコードは2度使えない。
	_, again := l.login(t, "pat@example.com")
	if status, _ := l.mePost(t, again, "/v1/login/second-factor:verify", map[string]string{"totp_code": code}); status != 401 {
		t.Fatalf("reused code: %d", status)
	}
	// 制限つきのセッションは短い期限で失効する。
	l.advance(11 * time.Minute)
	if status, _ := l.mePost(t, again, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)}); status != 401 {
		t.Fatalf("expired restricted session: %d", status)
	}
	// 無効化すると2要素目を求めない。
	if status, _ := l.mePost(t, upgraded, "/v1/me/totp/"+id+":revoke", nil); status != 204 {
		t.Fatalf("revoke: %d", status)
	}
	if login, _ := l.login(t, "pat@example.com"); login["next"] != nil {
		t.Fatalf("login after revoke: %v", login)
	}
}

func TestRequireSecondFactorEnroll(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Security.SecondFactor.Required = true }, nil)
	login, enroll := l.login(t, "quinn@example.com")
	if login["next"] != "enroll" {
		t.Fatalf("login: %v", login)
	}
	if status, _ := l.me(t, enroll); status != 401 {
		t.Fatalf("enroll session used for me: %d", status)
	}
	if w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+enroll); w.Code != 200 {
		t.Fatalf("methods on enroll session: %d", w.Code)
	}
	_, status, res, upgraded := l.enrollTOTP(t, enroll)
	lr, _ := res["login"].(map[string]any)
	if status != 200 || lr == nil || lr["next"] != nil || upgraded == "" {
		t.Fatalf("confirm on enroll session: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Contains(got, "mfa") || !slices.Contains(got, "otp") {
		t.Fatalf("amr: %v", got)
	}
}

func TestPasskeySecondFactor(t *testing.T) {
	l := newPasskeyEnv(t)
	_, full := l.login(t, "rae@example.com")
	a := passkeytest.New(passkeyOrigin)
	if status, res := l.registerPasskey(t, full, a, "Key"); status != 200 {
		t.Fatalf("register: %d %v", status, res)
	}
	// 本人確認（UV）つきの passkey でのログインは、それだけで2要素とみなす。
	if status, login, _ := l.passkeyLogin(t, a); status != 200 || login["next"] != nil {
		t.Fatalf("passkey login: %d %v", status, login)
	}
	login, restricted := l.login(t, "rae@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"passkey"}) {
		t.Fatalf("login: %v", login)
	}
	status, start := l.mePost(t, restricted, "/v1/login/second-factor/passkey:start", nil)
	flow, opts := ceremony(t, status, start)
	a.Flags = passkeytest.FlagUP // 2要素目では UV を求めない
	cred, err := a.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	status, res, upgraded := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]any{"flow_id": flow, "credential": json.RawMessage(cred)})
	if status != 200 || res["next"] != nil || upgraded == "" {
		t.Fatalf("verify: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Contains(got, "hwk") || !slices.Contains(got, "mfa") {
		t.Fatalf("amr: %v", got)
	}
}
