package app

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/method/hotp"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 認証方式のプラグイン（ADR 0090、0092）を HTTP で確かめる。HOTP は参照実装（フィーチャー hotp）、testKey はテスト用の1要素目の方式。

// rfcSecret と rfcCodes は RFC 4226 付録 D のテストベクタ。
var (
	rfcSecret = []byte("12345678901234567890")
	rfcCodes  = []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
)

func newHOTPEnv(t *testing.T, edit func(*config.Config)) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Features = &[]string{feature.Org, feature.Warnings, feature.HOTP}
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

// enrollHOTP は Cookie のセッションで RFC の種の HOTP を登録し、確認の応答を返す（カウンター 1 のコードで確かめる）。
func (l *loginEnv) enrollHOTP(t *testing.T, cookie string) (int, map[string]any, string) {
	t.Helper()
	status, st := l.mePost(t, cookie, "/v1/me/credentials/hotp:enroll-begin",
		map[string]any{"payload": map[string]any{"secret": base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rfcSecret)}})
	if status != 200 {
		t.Fatalf("hotp enroll-begin: %d %v", status, st)
	}
	p := st["payload"].(map[string]any)
	if p["uri"] == nil || p["counter"] != float64(0) {
		t.Fatalf("enroll payload: %v", p)
	}
	return l.post(t, cookie, "/v1/me/credentials/hotp:enroll-complete",
		map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": rfcCodes[1]}})
}

// secondFactor は制限つきのセッションで方式 m の2要素目を始めて、payload で完了する。
func (l *loginEnv) secondFactor(t *testing.T, cookie, m string, payload map[string]any) (int, map[string]any, string) {
	t.Helper()
	status, st := l.mePost(t, cookie, "/v1/login/second-factor/"+m+":begin", nil)
	if status != 200 {
		return status, st, ""
	}
	return l.post(t, cookie, "/v1/login/second-factor/"+m+":complete", map[string]any{"flow_id": st["flow_id"], "payload": payload})
}

func TestHOTPSecondFactor(t *testing.T) {
	// 照合はユーザーごとに数える（per_account）。このテストでは多めに試すので上げる。
	l := newHOTPEnv(t, func(c *config.Config) {
		c.Security.Login.RateLimit.PerAccount, c.Security.Login.RateLimit.PerAccountTotal = 20, 20
	})
	_, full := l.login(t, "pat@example.com")
	status, res, swapped := l.enrollHOTP(t, full)
	if status != 200 || res["login"] != nil || swapped != "" || res["recovery_codes"] == nil {
		t.Fatalf("hotp enroll-complete: %d %v", status, res)
	}
	cred := res["credential"].(map[string]any)
	if cred["method"] != "hotp" {
		t.Fatalf("credential: %v", cred)
	}
	id := cred["id"].(string)
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/methods", nil, "Cookie", sessionCookie+"="+full)
	var m struct {
		Credentials []struct{ ID, Method string }
	}
	if json.Unmarshal(w.Body.Bytes(), &m) != nil || len(m.Credentials) != 1 || m.Credentials[0].ID != id || m.Credentials[0].Method != "hotp" {
		t.Fatalf("methods: %s", w.Body)
	}
	// 秘密は暗号化して置く（平文で持たない）。
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		c, err := tx.Credentials().GetByPublicID(ctx, l.a.realm.ID, id)
		if err == nil && subtleContains(c.Data, rfcSecret) {
			t.Fatal("hotp secret stored in plaintext")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// HOTP を登録したユーザーは、メールの後に2要素目を求められる。
	login, restricted := l.login(t, "pat@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"hotp"}) {
		t.Fatalf("login: %v", login)
	}
	// 制限つきのセッションでは登録できず、2要素目の確認の前は本人の API を使えない。
	if status, _ := l.mePost(t, restricted, "/v1/me/credentials/hotp:enroll-begin", nil); status != 401 {
		t.Fatalf("restricted session enrolls: %d", status)
	}
	if status, _ := l.me(t, restricted); status != 401 {
		t.Fatalf("restricted session used for me: %d", status)
	}
	// 通常のセッションでは2要素目の API は使えない。
	if status, _, _ := l.secondFactor(t, full, "hotp", map[string]any{"code": rfcCodes[2]}); status != 401 {
		t.Fatalf("second factor on a full session: %d", status)
	}
	// 未知の方式・1要素目に使えない方式は 404。
	if status, _ := l.mePost(t, restricted, "/v1/login/second-factor/nosuch:begin", nil); status != 404 {
		t.Fatalf("unknown method: %d", status)
	}
	if status, _ := l.mePost(t, "", "/v1/login/methods/hotp:begin", nil); status != 404 {
		t.Fatalf("hotp as a first factor: %d", status)
	}
	// 違うコード・登録に使ったコードは通らない。
	for _, code := range []string{"000000", rfcCodes[1], rfcCodes[0]} {
		if status, _, _ := l.secondFactor(t, restricted, "hotp", map[string]any{"code": code}); status != 401 {
			t.Fatalf("code %s: %d", code, status)
		}
	}
	// フロー ID が無い・別の種類のフローは通らない。
	if status, _, _ := l.post(t, restricted, "/v1/login/second-factor/hotp:complete", map[string]any{"flow_id": "x", "payload": map[string]any{"code": rfcCodes[2]}}); status != 401 {
		t.Fatalf("unknown flow: %d", status)
	}
	status, res, upgraded := l.secondFactor(t, restricted, "hotp", map[string]any{"code": rfcCodes[2]})
	if status != 200 || res["next"] != nil || res["user_id"] != login["user_id"] || upgraded == "" {
		t.Fatalf("second factor: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	// 同じカウンターのコードは2度使えない。
	_, again := l.login(t, "pat@example.com")
	if status, _, _ := l.secondFactor(t, again, "hotp", map[string]any{"code": rfcCodes[2]}); status != 401 {
		t.Fatalf("reused code: %d", status)
	}
	// 窓の外のコードは、続けて出した2つで再同期する。
	far := func(n uint64) string { return hotp.Code(rfcSecret, n, 6) }
	if status, _, _ := l.secondFactor(t, again, "hotp", map[string]any{"code": far(50)}); status != 401 {
		t.Fatalf("code outside the window: %d", status)
	}
	if status, res, _ := l.secondFactor(t, again, "hotp", map[string]any{"code": far(50), "next_code": far(51)}); status != 200 {
		t.Fatalf("resync: %d %v", status, res)
	}

	// 無効化すると2要素目を求めず、それで2要素目を確かめたセッションは使えなくなる。
	if status, res := l.mePost(t, upgraded, "/v1/me/credentials/"+id+":revoke", nil); status != 204 {
		t.Fatalf("revoke: %d %v", status, res)
	}
	if status, _ := l.mePost(t, full, "/v1/me/credentials/"+id+":revoke", nil); status != 404 {
		t.Fatalf("revoke twice: %d", status)
	}
	l.advance(l.e.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
	if status, _ := l.me(t, upgraded); status != 401 {
		t.Fatalf("session after revoking its second factor: %d", status)
	}
	if login, _ := l.login(t, "pat@example.com"); login["next"] != nil {
		t.Fatalf("login after revoke: %v", login)
	}
}

func TestHOTPRateLimit(t *testing.T) {
	l := newHOTPEnv(t, nil)
	_, full := l.login(t, "pat@example.com")
	if status, res, _ := l.enrollHOTP(t, full); status != 200 {
		t.Fatalf("enroll: %d %v", status, res)
	}
	_, restricted := l.login(t, "pat@example.com")
	status := 0
	for range 10 {
		if status, _, _ = l.secondFactor(t, restricted, "hotp", map[string]any{"code": "000000"}); status == 429 {
			break
		}
	}
	if status != 429 {
		t.Fatalf("no rate limit: %d", status)
	}
}

func subtleContains(b, sub []byte) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		if subtle.ConstantTimeCompare(b[i:i+len(sub)], sub) == 1 {
			return true
		}
	}
	return false
}

func TestHOTPEnrollWhenRequired(t *testing.T) {
	l := newHOTPEnv(t, func(c *config.Config) { c.Security.SecondFactor.Required = true })
	login, enroll := l.login(t, "sam@example.com")
	if login["next"] != "enroll" {
		t.Fatalf("login: %v", login)
	}
	status, res, upgraded := l.enrollHOTP(t, enroll)
	if status != 200 || res["login"] == nil || upgraded == "" {
		t.Fatalf("enroll on an enroll-only session: %d %v", status, res)
	}
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
}

func TestHOTPDisabledByDefault(t *testing.T) {
	l := newLoginEnv(t)
	_, full := l.login(t, "pat@example.com")
	if status, _ := l.mePost(t, full, "/v1/me/credentials/hotp:enroll-begin", nil); status != 404 {
		t.Fatalf("hotp without the feature: %d", status)
	}
}

func TestDisableHOTPWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, cookie := l.login(t, "pat@example.com")
	if status, res, _ := l.enrollHOTP(t, cookie); status != 200 {
		t.Fatalf("enroll: %d %v", status, res)
	}
	disableWithData(t, l, feature.HOTP, 1)
}

// testKey はテスト用の1要素目の方式。登録で鍵の文字列を検索キーにし、ログインで同じ鍵を送る。
type testKey struct{}

func (testKey) Info() port.MethodInfo {
	return port.MethodInfo{Name: "testkey", Feature: "testkey", Kind: port.FactorPossession, AMR: []string{"hwk"}, AAL: 1,
		Usages: []port.MethodUsage{port.UsageFirstFactor}, DataVersion: 1}
}

type keyPayload struct {
	Key string `json:"key"`
}

func (testKey) Begin(context.Context, port.MethodEnv, port.MethodRequest) (port.MethodChallenge, error) {
	return port.MethodChallenge{Payload: json.RawMessage(`{"nonce":"n"}`), State: []byte("n")}, nil
}

func (testKey) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	var p keyPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil || string(in.State) != "n" {
		return port.MethodResult{}, errs.AuthenticationFailed
	}
	c, err := env.Credentials.FindByLookup(ctx, p.Key)
	if err != nil {
		return port.MethodResult{}, err
	}
	if string(c.Data) != p.Key {
		return port.MethodResult{}, errs.AuthenticationFailed
	}
	return port.MethodResult{Credential: c}, nil
}

func (testKey) EnrollBegin(context.Context, port.MethodEnv, port.MethodRequest) (port.MethodChallenge, error) {
	return port.MethodChallenge{State: []byte("e")}, nil
}

func (testKey) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	var p keyPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil || p.Key == "" {
		return port.MethodEnrollment{}, errs.WithCode(errs.KindInvalid, "invalid_key", "bad key")
	}
	c, err := env.Credentials.Create(ctx, env.UserID, p.Key, []byte(p.Key))
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	return port.MethodEnrollment{Credential: c, Payload: json.RawMessage(`{"ok":true}`)}, nil
}

func (testKey) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }

func (l *loginEnv) keyLogin(t *testing.T, key string) (int, map[string]any, string) {
	t.Helper()
	status, st := l.mePost(t, "", "/v1/login/methods/testkey:begin", nil)
	if status != 200 || st["payload"].(map[string]any)["nonce"] != "n" {
		t.Fatalf("begin: %d %v", status, st)
	}
	return l.post(t, "", "/v1/login/methods/testkey:complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"key": key}})
}

func TestMethodFirstFactor(t *testing.T) {
	l := newLoginEnvDeps(t, nil, nil, func(d *Deps) { d.Methods = []port.Authenticator{testKey{}} })
	login, full := l.login(t, "kim@example.com")
	enroll := func(key string) (int, map[string]any) {
		status, st := l.mePost(t, full, "/v1/me/credentials/testkey:enroll-begin", nil)
		if status != 200 {
			t.Fatalf("enroll-begin: %d %v", status, st)
		}
		return l.mePost(t, full, "/v1/me/credentials/testkey:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"key": key}})
	}
	if status, res := enroll(""); status != 400 || res["error"] != "invalid_key" {
		t.Fatalf("invalid enrollment: %d %v", status, res)
	}
	status, res := enroll("key-1")
	if status != 200 || res["payload"].(map[string]any)["ok"] != true {
		t.Fatalf("enroll: %d %v", status, res)
	}
	id := res["credential"].(map[string]any)["id"].(string)
	// 検索キーは realm と方式の中で一意（同じ鍵を2度登録できない）。
	if status, _ := enroll("key-1"); status == 200 {
		t.Fatal("same lookup enrolled twice")
	}

	// 理由を区別しない失敗（4.9）。
	if status, res, _ := l.keyLogin(t, "unknown"); status != 401 || res["error"] != "authentication_failed" {
		t.Fatalf("unknown key: %d %v", status, res)
	}
	status, res, cookie := l.keyLogin(t, "key-1")
	if status != 200 || res["user_id"] != login["user_id"] || cookie == "" {
		t.Fatalf("login: %d %v", status, res)
	}
	if got := amr(t, l, cookie); !slices.Equal(got, []any{"hwk"}) {
		t.Fatalf("amr: %v", got)
	}
	// フローは1回限り。
	status, st := l.mePost(t, "", "/v1/login/methods/testkey:begin", nil)
	if status != 200 {
		t.Fatal(status)
	}
	body := map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"key": "key-1"}}
	if status, _, _ := l.post(t, "", "/v1/login/methods/testkey:complete", body); status != 200 {
		t.Fatalf("first use: %d", status)
	}
	if status, _, _ := l.post(t, "", "/v1/login/methods/testkey:complete", body); status != 401 {
		t.Fatalf("flow reused: %d", status)
	}
	// 1要素目の方式は2要素目に使えない。
	if status, _ := l.mePost(t, cookie, "/v1/login/second-factor/testkey:begin", nil); status != 401 {
		t.Fatalf("second factor on a full session: %d", status)
	}

	// 無効化すると、その方式で作ったセッションは使えず、同じ鍵でログインできない。
	if status, res := l.mePost(t, full, "/v1/me/credentials/"+id+":revoke", nil); status != 204 {
		t.Fatalf("revoke: %d %v", status, res)
	}
	l.advance(l.e.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("session after revoke: %d", status)
	}
	if status, _, _ := l.keyLogin(t, "key-1"); status != 401 {
		t.Fatalf("login after revoke: %d", status)
	}
}

// TestMethodRestricted は制限つきのセッションで使える汎用のパスを確かめる。
func TestMethodRestricted(t *testing.T) {
	for _, c := range []struct {
		r    port.SessionRestriction
		path string
		want bool
	}{
		{port.RestrictionSecondFactor, "/v1/login/second-factor/hotp:begin", true},
		{port.RestrictionSecondFactor, "/v1/login/second-factor/hotp:complete", true},
		{port.RestrictionEnroll, "/v1/login/second-factor/hotp:complete", true},
		{port.RestrictionRecovery, "/v1/login/second-factor/hotp:complete", false},
		{port.RestrictionSecondFactor, "/v1/me/credentials/hotp:enroll-begin", false},
		{port.RestrictionEnroll, "/v1/me/credentials/hotp:enroll-begin", true},
		{port.RestrictionRecovery, "/v1/me/credentials/hotp:enroll-complete", true},
		{port.RestrictionEnroll, "/v1/me/credentials/crd_1:revoke", false},
		{port.RestrictionEnroll, "/v1/me/credentials/hotp/x:enroll-begin", false},
		{port.RestrictionSecondFactor, "/v1/login/second-factor/HOTP:begin", false},
		{port.RestrictionDeletion, "/v1/login/second-factor/hotp:begin", false},
	} {
		if got := restrictionAllows(c.r, "POST", c.path); got != c.want {
			t.Errorf("%s %s = %v", c.r, c.path, got)
		}
	}
	if restrictionAllows(port.RestrictionSecondFactor, "GET", "/v1/login/second-factor/hotp:begin") {
		t.Error("GET allowed")
	}
}

// 運営者の一覧・無効化と、アカウント統合で汎用の認証情報を扱う。
func TestHOTPAdminAndMerge(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.AccountMerge, feature.HOTP)
		c.Features = &names
		c.Security.Login.RateLimit.PerAccount, c.Security.Login.RateLimit.PerAccountTotal = 20, 20
	}, feature.Registered())
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)

	// 運営者の一覧に載り、crd_ の ID で無効化できる。
	res, pat := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)
	if status, out, _ := l.enrollHOTP(t, pat); status != 200 {
		t.Fatalf("enroll: %d %v", status, out)
	}
	var c struct {
		Credentials []struct{ ID, Method string } `json:"credentials"`
	}
	if status := l.adminGet(t, "/v1/admin/users/"+uid+"/credentials", sec, &c); status != 200 || len(c.Credentials) != 1 || c.Credentials[0].Method != "hotp" {
		t.Fatalf("admin credentials: %d %+v", status, c)
	}
	other, _ := l.login(t, "eve@example.com")
	if status, _ := l.admin(t, "/v1/admin/users/"+other["user_id"].(string)+"/credentials/"+c.Credentials[0].ID+":revoke", sec, nil); status != 404 {
		t.Fatalf("revoke via another user: %d", status)
	}
	path := "/v1/admin/users/" + uid + "/credentials/" + c.Credentials[0].ID + ":revoke"
	if status, out := l.admin(t, path, sec, nil); status != 204 {
		t.Fatalf("admin revoke: %d %v", status, out)
	}
	if status, _ := l.admin(t, path, sec, nil); status != 404 {
		t.Fatalf("admin revoke twice: %d", status)
	}
	if login, _ := l.login(t, "pat@example.com"); login["next"] != nil {
		t.Fatalf("login after admin revoke: %v", login)
	}
	// 一括の無効化は件数を返す。
	if status, out, _ := l.enrollHOTP(t, pat); status != 200 {
		t.Fatalf("enroll again: %d %v", status, out)
	}
	status, out := l.admin(t, "/v1/admin/users/"+uid+"/credentials:revoke-all", sec, nil)
	if status != 200 || out["credentials"] != 1.0 {
		t.Fatalf("revoke all: %d %v", status, out)
	}

	// 統合元の HOTP は統合先のものになり、統合先のログインで2要素目に使える。
	_, alice := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	_, bob := l.login(t, "bob@example.com")
	if status, out, _ := l.enrollHOTP(t, bob); status != 200 {
		t.Fatalf("bob enroll: %d %v", status, out)
	}
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": l.mergeToken(t, bob)}); code != 200 {
		t.Fatalf("merge: %d %v", code, out)
	}
	login, restricted := l.login(t, "alice@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"hotp"}) {
		t.Fatalf("alice login after merge: %v", login)
	}
	if status, res, _ := l.secondFactor(t, restricted, "hotp", map[string]any{"code": rfcCodes[2]}); status != 200 || res["user_id"] != aliceID {
		t.Fatalf("second factor with merged hotp: %d %v", status, res)
	}
}
