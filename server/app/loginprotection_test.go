package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/geoip/static"
	"github.com/imohiyoko/iam/authn/botcheck"
	"github.com/imohiyoko/iam/authn/device"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// ログインの守り（ADR 0105）を HTTP で確かめる。

// newProtectEnv は既定のフィーチャーに password・acr と extra を足した環境。接続元・アカウントごとの回数の制限は外し、
// ロックアウトだけで止まることを確かめられるようにする。プロキシの後ろとして X-Forwarded-For で接続元を変えられる。
func newProtectEnv(t *testing.T, extra []string, edit func(*config.Config), editDeps func(*Deps)) *loginEnv {
	t.Helper()
	return newLoginEnvDeps(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.Password, feature.ACR)
		names = append(names, extra...)
		c.Features = &names
		c.Security.Login.RateLimit.PerIP, c.Security.Login.RateLimit.PerAccount, c.Security.Login.RateLimit.PerAccountTotal = 0, 0, 0
		c.Server.TrustedProxies = []string{"192.0.2.0/24"} // httptest の RemoteAddr は 192.0.2.1
		c.Security.Lockout = config.Lockout{Threshold: 4, Window: config.Duration(15 * time.Minute), LockDuration: config.Duration(10 * time.Minute),
			MaxLockDuration: config.Duration(time.Hour), DelayAfter: 2, BaseDelay: config.Duration(time.Second), MaxDelay: config.Duration(4 * time.Second)}
		if edit != nil {
			edit(c)
		}
	}, feature.Registered(), editDeps)
}

// pwFrom は接続元 ip からパスワードでログインする。
func (l *loginEnv) pwFrom(t *testing.T, ip, email, pw string) (int, map[string]any, string) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/password", map[string]string{"email": email, "password": pw}, "X-Forwarded-For", ip)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return w.Code, out, c.Value
		}
	}
	return w.Code, out, w.Header().Get("Retry-After")
}

// 接続元を変えても、アカウントごとに待ち時間とロックがかかる。無いアカウントも同じ応答になる。運営者は状態を見て解除できる。
func TestAccountLockoutPassword(t *testing.T) {
	l := newProtectEnv(t, []string{feature.AccountLockout}, nil, nil)
	l.strongUser(t, "pat@example.com")
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	patID := l.userID(t, "pat@example.com")

	type step struct {
		code  int
		retry string
	}
	run := func(email string) []step {
		var out []step
		for _, at := range []struct {
			ip   string
			wait time.Duration
		}{{"198.51.100.1", 0}, {"198.51.100.2", 0}, {"203.0.113.3", 0}, {"203.0.113.3", 5 * time.Second}, {"203.0.113.4", 5 * time.Second}, {"198.51.100.1", 5 * time.Second}} {
			l.advance(at.wait)
			code, res, extra := l.pwFrom(t, at.ip, email, "wrong password")
			if code == 429 && res["error"] != "rate_limited" {
				t.Fatalf("%s: %v", email, res)
			}
			if code != 429 {
				extra = ""
			}
			out = append(out, step{code, extra})
		}
		l.advance(time.Minute)
		return out
	}
	// 2 回目の失敗の後は 1 秒の待ち時間（すぐの再試行は 429 で、数えない）、4 回目の失敗でロックする。接続元は問わない。
	want := []step{{401, ""}, {401, ""}, {429, "1"}, {401, ""}, {401, ""}, {429, "595"}}
	known, unknown := run("pat@example.com"), run("nobody@example.com")
	if !slices.Equal(known, want) {
		t.Fatalf("known = %v, want %v", known, want)
	}
	if !slices.Equal(unknown, want) {
		t.Fatalf("unknown account = %v, want %v", unknown, want)
	}
	if code, res, retry := l.pwFrom(t, "198.51.100.9", "pat@example.com", acrPassword); code != 429 || res["error"] != "rate_limited" || retry == "" {
		t.Fatalf("locked, right password: %d %v %q", code, res, retry)
	}
	locked := l.auditOf(t, "account.locked")
	if len(locked) != 1 || locked[0].Details["user_id"] != patID || locked[0].Details["scope"] != "password" {
		t.Fatalf("account.locked = %+v", locked)
	}
	if strings.Contains(l.e.out.String(), "nobody@example.com") {
		t.Fatal("unknown address leaked to the event sink")
	}

	code, st := l.adminDo(t, "GET", owner, "/v1/admin/users/"+patID+"/lockout", nil)
	pw, _ := st["password"].(map[string]any)
	if code != 200 || st["locked"] != true || pw["locked_until"] == nil || pw["level"] != float64(1) {
		t.Fatalf("lockout: %d %v", code, st)
	}
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	if code, _ := l.adminDo(t, "POST", support, "/v1/admin/users/"+patID+":unlock", nil); code != 403 {
		t.Fatalf("unlock by support: %d", code)
	}
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/users/"+patID+":unlock", nil); code != 200 || out["locked"] != true {
		t.Fatalf("unlock: %d %v", code, out)
	}
	if ev := l.lastAudit(t, "account.unlocked"); ev.Details["user_id"] != patID || ev.Actor.Type != "user" {
		t.Fatalf("account.unlocked = %+v", ev)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/users/"+patID+"/lockout", nil); code != 200 || out["locked"] != false {
		t.Fatalf("after unlock: %d %v", code, out)
	}
	if code, res, _ := l.pwFrom(t, "198.51.100.9", "pat@example.com", acrPassword); code != 200 {
		t.Fatalf("login after unlock: %d %v", code, res)
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/users/usr_nope/lockout", nil); code != 404 {
		t.Fatalf("unknown user: %d", code)
	}
}

// フィーチャーが無ければ数えず、管理の API も 404。
func TestAccountLockoutOff(t *testing.T) {
	l := newProtectEnv(t, nil, nil, nil)
	l.strongUser(t, "pat@example.com")
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for i := range 10 {
		if code, _, _ := l.pwFrom(t, "198.51.100.1", "pat@example.com", "wrong"); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, _ := l.adminDo(t, "GET", owner, "/v1/admin/users/"+l.userID(t, "pat@example.com")+"/lockout", nil); code != 404 {
		t.Fatalf("lockout without feature: %d", code)
	}
}

// 2要素目のコードもユーザーごとに数え、ロックの間は正しいコードも通さない。
func TestAccountLockoutSecondFactor(t *testing.T) {
	l := newProtectEnv(t, []string{feature.AccountLockout}, func(c *config.Config) { c.Security.Lockout.DelayAfter = 0 }, nil)
	secret := l.strongUser(t, "pat@example.com")
	l.advance(30 * time.Second)
	for i := range 4 {
		code, res, restricted := l.passwordLogin(t, "pat@example.com", acrPassword)
		if code != 200 || res["next"] != "second_factor" {
			t.Fatalf("password %d: %d %v", i, code, res)
		}
		code, res, _ = l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": "000000"})
		if code != 401 {
			t.Fatalf("wrong code %d: %d %v", i, code, res)
		}
	}
	_, _, restricted := l.passwordLogin(t, "pat@example.com", acrPassword)
	if code, res, _ := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)}); code != 429 || res["error"] != "rate_limited" {
		t.Fatalf("locked second factor: %d %v", code, res)
	}
	if ev := l.lastAudit(t, "account.locked"); ev.Details["scope"] != "second_factor" {
		t.Fatalf("account.locked = %+v", ev)
	}
	l.advance(11 * time.Minute)
	l.strongLogin(t, "pat@example.com", secret)
}

// 端末の Cookie を置き、2台目からのログインを ID だけで知らせる。本人は一覧で見て忘れられる。
func TestDeviceRecognition(t *testing.T) {
	l := newProtectEnv(t, []string{feature.DeviceRecognition}, func(c *config.Config) {
		c.Security.Warnings = map[string]string{"new_device": "warn"}
	}, nil)
	laptop, phone := "", ""
	l.device = &laptop
	l.ua = "Laptop/1.0"
	res, cookie := l.login(t, "pat@example.com")
	if laptop == "" || !device.ValidToken(laptop) {
		t.Fatalf("device cookie = %q", laptop)
	}
	if ws, _ := res["warnings"].([]any); len(ws) != 0 {
		t.Fatalf("first device warned: %v", ws)
	}
	notes := l.notes.count()
	first := laptop
	l.login(t, "pat@example.com")
	if laptop != first {
		t.Fatal("device cookie changed on the same device")
	}
	if l.notes.count() != notes+1 { // ログインのメールだけ
		t.Fatalf("notifications on a known device: %d", l.notes.count()-notes)
	}

	l.advance(time.Second)
	l.device, l.ua = &phone, "Phone/2.0"
	res, _ = l.login(t, "pat@example.com")
	ws, _ := res["warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["code"] != "new_device" {
		t.Fatalf("warnings = %v", res["warnings"])
	}
	if _, err := l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := l.notes.last(t)
	if n.Type != device.TypeNewDeviceLogin || n.UserID != res["user_id"] || !strings.HasPrefix(n.DeviceID, "dev_") {
		t.Fatalf("notification = %+v", n)
	}
	if strings.Contains(l.notes.sent.String(), "Phone/2.0") || strings.Contains(l.notes.sent.String(), phone) {
		t.Fatal("notification carries more than IDs")
	}
	if strings.Contains(l.e.out.String(), phone) || strings.Contains(l.e.logs.String(), phone) {
		t.Fatal("device token leaked")
	}

	l.device = &laptop
	code, out := l.meDo(t, "GET", cookie, "/v1/me/devices", nil)
	ds, _ := out["devices"].([]any)
	if code != 200 || len(ds) != 2 {
		t.Fatalf("devices: %d %v", code, out)
	}
	d0, d1 := ds[0].(map[string]any), ds[1].(map[string]any)
	// 最後に使った順。
	if d0["current"] != false || d1["current"] != true || d1["user_agent"] != "Laptop/1.0" || d0["id"] != n.DeviceID || d1["confirmed"] != false {
		t.Fatalf("devices = %v", ds)
	}
	if code, _ := l.meDo(t, "DELETE", cookie, "/v1/me/devices/"+n.DeviceID, nil); code != 204 {
		t.Fatalf("forget: %d", code)
	}
	if code, _ := l.meDo(t, "DELETE", cookie, "/v1/me/devices/"+n.DeviceID, nil); code != 404 {
		t.Fatalf("forget twice: %d", code)
	}
	if ev := l.lastAudit(t, device.EventForgotten); ev.Details["device_id"] != n.DeviceID {
		t.Fatalf("device.forgotten = %+v", ev)
	}
	// 他人の端末は見えない（404）。
	_, other := l.login(t, "eve@example.com")
	if code, _ := l.meDo(t, "DELETE", other, "/v1/me/devices/"+d1["id"].(string), nil); code != 404 {
		t.Fatalf("forget someone else's device: %d", code)
	}
	// 忘れた端末からのログインは、また新しい端末になる。
	l.device = &phone
	if res, _ := l.login(t, "pat@example.com"); len(res["warnings"].([]any)) != 1 {
		t.Fatalf("forgotten device: %v", res["warnings"])
	}
}

// new_device は deny にできない（本人の端末を増やせなくなるため）。
func TestDeviceWarningCannotDeny(t *testing.T) {
	e := newEnv(t)
	e.cfg.Security.Warnings = map[string]string{"new_device": "deny"}
	if _, err := New(context.Background(), e.cfg, e.deps, nil); err == nil || !strings.Contains(err.Error(), "new_device") {
		t.Fatalf("deny accepted: %v", err)
	}
}

// フィーチャーを無効にすると端末の記録を消し、一覧は 404 になる。
func TestDeviceRecognitionDisable(t *testing.T) {
	l := newProtectEnv(t, []string{feature.DeviceRecognition}, nil, nil)
	jar := ""
	l.device = &jar
	_, cookie := l.login(t, "pat@example.com")
	if code, out := l.meDo(t, "GET", cookie, "/v1/me/devices", nil); code != 200 || len(out["devices"].([]any)) != 1 {
		t.Fatalf("devices: %d %v", code, out)
	}
	enabled := slices.DeleteFunc(slices.Clone(*l.e.cfg.Features), func(s string) bool { return s == feature.DeviceRecognition })
	a, err := l.restart(t, enabled, feature.Registered())
	if err != nil {
		t.Fatal(err)
	}
	if res, err := a.DisableFeature(context.Background(), feature.DeviceRecognition, false); err != nil || res.Done || res.Remaining != 1 {
		t.Fatalf("disable without purge: %+v %v", res, err)
	}
	if res, err := a.DisableFeature(context.Background(), feature.DeviceRecognition, true); err != nil || !res.Done || res.Purged != 1 {
		t.Fatalf("disable with purge: %+v %v", res, err)
	}
	var n int
	err = a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		n, err = tx.KnownDevices().Count(ctx)
		return err
	})
	if err != nil || n != 0 {
		t.Fatalf("devices after disable: %d %v", n, err)
	}
}

const riskGeo = `198.51.100.0/24,JP,64500,35.68,139.76
203.0.113.0/24,US,64501,40.71,-74.00
192.0.2.0/24,JP,64502,35.68,139.76
`

// loginRisk は最後のログインで組み込みの評価器が付けた点数（監査ログ session.risk_updated の source login_risk）。
func (l *loginEnv) loginRisk(t *testing.T) map[string]any {
	t.Helper()
	evs := l.auditOf(t, "session.risk_updated")
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Details["source"] == "login_risk" {
			r, _ := evs[i].Details["risk"].(map[string]any)
			return r
		}
	}
	t.Fatal("no login_risk score")
	return nil
}

// リスクの点数：新しい端末・国と impossible travel。要件の risk_at_most で step-up（acr_values）を求め、AAL2 のログインで端末を確かめる。
func TestLoginRiskStepUp(t *testing.T) {
	geo, err := static.Parse(strings.NewReader(riskGeo))
	if err != nil {
		t.Fatal(err)
	}
	l := newProtectEnv(t, []string{feature.DeviceRecognition, feature.LoginRisk}, nil, func(d *Deps) { d.GeoIP = geo })
	_, op := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "PUT", op, "/v1/admin/action-namespaces/me", map[string]any{"requirements": map[string]any{
		role.ActionMeDelete: map[string]any{"any": []any{
			map[string]any{"risk_at_most": map[string]any{"type": "device", "level": "low"}},
			map[string]any{"aal_at_least": 2}}}}}); code != 200 {
		t.Fatalf("put me: %d %v", code, out)
	}
	jar := ""
	l.device = &jar
	l.hdr = []string{"X-Forwarded-For", "198.51.100.10"}
	_, cookie := l.login(t, "pat@example.com")
	if got := l.loginRisk(t); got["device"] != float64(60) || got["ip"] != float64(0) {
		t.Fatalf("first login: %v", got)
	}
	// 2 回目は知っている端末だが、確かめていない（メールのログインは AAL1）。
	_, cookie = l.login(t, "pat@example.com")
	if got := l.loginRisk(t); got["device"] != float64(30) || got["ip"] != float64(0) {
		t.Fatalf("known unconfirmed device: %v", got)
	}
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/account:delete", nil, "Cookie", sessionCookie+"="+cookie)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `acr_values="`+acr.AAL2+`"`) {
		t.Fatalf("step-up: %d %s %q", w.Code, w.Body, w.Header().Get("WWW-Authenticate"))
	}

	// AAL2 のログインで端末を確かめ、次のログインから device は 0。
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": acrPassword}); status != 204 {
		t.Fatalf("set password: %d %v", status, res)
	}
	secret, status, res, _ := l.enrollTOTP(t, cookie)
	if status != 200 {
		t.Fatalf("totp: %d %v", status, res)
	}
	l.strongLogin(t, "pat@example.com", secret)
	if got := l.loginRisk(t); got["device"] != float64(30) {
		t.Fatalf("confirming login: %v", got)
	}
	full := l.strongLogin(t, "pat@example.com", secret)
	if got := l.loginRisk(t); got["device"] != float64(0) || got["ip"] != float64(0) {
		t.Fatalf("confirmed device: %v", got)
	}

	// 1 分後に別の大陸から：新しい国・ASN と impossible travel（ip は 90）。
	l.advance(time.Minute)
	l.hdr = []string{"X-Forwarded-For", "203.0.113.10"}
	l.strongLogin(t, "pat@example.com", secret)
	if got := l.loginRisk(t); got["device"] != float64(0) || got["ip"] != float64(90) {
		t.Fatalf("impossible travel: %v", got)
	}
	// 一覧に国が出る。
	code, out := l.meDo(t, "GET", full, "/v1/me/devices", nil)
	if ds, _ := out["devices"].([]any); code != 200 || len(ds) != 1 || ds[0].(map[string]any)["country"] != "US" || ds[0].(map[string]any)["confirmed"] != true {
		t.Fatalf("devices: %d %v", code, out)
	}
}

// ボット対策：always は入口で必ず、suspicious は接続元の失敗が続いた後だけトークンを求める。
func TestBotProtection(t *testing.T) {
	t.Run("always", func(t *testing.T) {
		l := newProtectEnv(t, []string{feature.BotProtection}, func(c *config.Config) { c.Security.BotProtection.Mode = "always" }, nil)
		start := func(token string) (int, map[string]any) {
			w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:start", map[string]string{"email": "pat@example.com"}, botcheck.Header, token)
			var out map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			return w.Code, out
		}
		for _, tok := range []string{"", "robot", strings.Repeat("x", 5000)} {
			if code, out := start(tok); code != 403 || out["error"] != "bot_check_required" {
				t.Fatalf("token %.10q: %d %v", tok, code, out)
			}
		}
		if code, out := start(testBotToken); code != 200 {
			t.Fatalf("human: %d %v", code, out)
		}
		// 入口でなければ求めない。
		if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/email:verify", map[string]string{"flow_id": "x", "code": "1"}); w.Code != 401 {
			t.Fatalf("verify: %d %s", w.Code, w.Body)
		}
		l.hdr = []string{botcheck.Header, testBotToken}
		if _, cookie := l.login(t, "pat@example.com"); cookie == "" {
			t.Fatal("login with a token")
		}
	})
	t.Run("suspicious", func(t *testing.T) {
		l := newProtectEnv(t, []string{feature.BotProtection}, func(c *config.Config) { c.Security.BotProtection.AfterFailures = 3 }, nil)
		l.strongUser(t, "pat@example.com")
		for i := range 3 {
			if code, res, _ := l.pwFrom(t, "198.51.100.1", "pat@example.com", "wrong"); code != 401 {
				t.Fatalf("attempt %d: %d %v", i, code, res)
			}
		}
		if code, res, _ := l.pwFrom(t, "198.51.100.1", "pat@example.com", acrPassword); code != 403 || res["error"] != "bot_check_required" {
			t.Fatalf("after failures: %d %v", code, res)
		}
		// 別の接続元は止めない。
		if code, res, _ := l.pwFrom(t, "198.51.100.2", "pat@example.com", acrPassword); code != 200 {
			t.Fatalf("another client: %d %v", code, res)
		}
		l.hdr = []string{botcheck.Header, testBotToken}
		if code, res, _ := l.pwFrom(t, "198.51.100.1", "pat@example.com", acrPassword); code != 200 {
			t.Fatalf("with a token: %d %v", code, res)
		}
		l.hdr = nil
		l.advance(11 * time.Minute)
		if code, res, _ := l.pwFrom(t, "198.51.100.1", "pat@example.com", acrPassword); code != 200 {
			t.Fatalf("after the window: %d %v", code, res)
		}
	})
}
