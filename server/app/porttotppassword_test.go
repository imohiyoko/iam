package app

import (
	"context"
	"encoding/base32"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/credential"
	pwm "github.com/imohiyoko/iam/authn/method/password"
	totpm "github.com/imohiyoko/iam/authn/method/totp"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// TOTP とパスワードを認証方式のポートに載せたこと（ADR 0101）を HTTP で確かめる。汎用のパスと方式専用のパスは同じ処理で動く。

func TestTOTPGenericPaths(t *testing.T) {
	l := newLoginEnv(t)
	_, full := l.login(t, "gen@example.com")
	status, st := l.mePost(t, full, "/v1/me/credentials/totp:enroll-begin", nil)
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	p := st["payload"].(map[string]any)
	if !strings.HasPrefix(p["uri"].(string), "otpauth://totp/") {
		t.Fatalf("payload: %v", p)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(p["secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	status, res := l.mePost(t, full, "/v1/me/credentials/totp:enroll-complete", map[string]any{"flow_id": st["flow_id"], "payload": map[string]any{"code": l.code(t, secret)}})
	if status != 200 {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	cid := res["credential"].(map[string]any)["id"].(string)
	// 方式専用の登録の開始は、汎用で登録した TOTP も数える（1人に1つ）。
	if status, res := l.mePost(t, full, "/v1/me/totp:start", nil); status != 409 || res["error"] != "totp_exists" {
		t.Fatalf("legacy start after generic enrollment: %d %v", status, res)
	}

	login, restricted := l.login(t, "gen@example.com")
	if login["next"] != "second_factor" || !slices.Equal(login["second_factor_methods"].([]any), []any{"totp"}) {
		t.Fatalf("login: %v", login)
	}
	l.advance(30 * time.Second)
	status, ch, _ := l.post(t, restricted, "/v1/login/second-factor/totp:begin", nil)
	if status != 200 {
		t.Fatalf("second factor begin: %d %v", status, ch)
	}
	if status, _, _ := l.post(t, restricted, "/v1/login/second-factor/totp:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"code": "abcdef"}}); status != 401 {
		t.Fatalf("wrong code: %d", status)
	}
	status, res, upgraded := l.post(t, restricted, "/v1/login/second-factor/totp:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"code": l.code(t, secret)}})
	if status != 200 || res["next"] != nil || upgraded == "" {
		t.Fatalf("second factor complete: %d %v", status, res)
	}
	// amr は方式専用のパスと同じ（ADR 0093 の AAL も変わらない）。
	if got := amr(t, l, upgraded); !slices.Equal(got, []any{"otp", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	// 同じ時間窓のコードは方式専用のパスでも通らない（使った窓は方式のデータにある）。
	_, again := l.login(t, "gen@example.com")
	if status, _, _ := l.post(t, again, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)}); status != 401 {
		t.Fatalf("reuse through the legacy path: %d", status)
	}
	// 汎用で登録した TOTP も方式専用のパスで無効化できる。
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/totp/"+cid+":revoke", nil, "Cookie", sessionCookie+"="+upgraded); w.Code != 204 {
		t.Fatalf("legacy revoke: %d %s", w.Code, w.Body)
	}
	if login, _ := l.login(t, "gen@example.com"); login["next"] != nil {
		t.Fatalf("login after revoke: %v", login)
	}
}

func TestPasswordGenericPaths(t *testing.T) {
	l := newPasswordEnv(t)
	_, cookie := l.login(t, "gp@example.com")
	_, other := l.login(t, "gp@example.com")
	const pw = "a long and memorable passphrase"
	if status, res := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-begin", map[string]any{"payload": map[string]any{"password": "short"}}); status != 400 || res["error"] != "password_too_short" {
		t.Fatalf("too short: %d %v", status, res)
	}
	status, st := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-begin", map[string]any{"payload": map[string]any{"password": pw}})
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	status, res := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-complete", map[string]any{"flow_id": st["flow_id"]})
	if status != 200 {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	cid := res["credential"].(map[string]any)["id"].(string)
	// 他のセッションは失効し、このセッションは残る（5.2。方式専用のパスと同じ）。
	if status, _ := l.me(t, other); status != 401 {
		t.Fatalf("other session after set: %d", status)
	}
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("current session after set: %d", status)
	}
	// 置き換えには今のパスワードが要る。
	if status, res := l.mePost(t, cookie, "/v1/me/credentials/password:enroll-begin", map[string]any{"payload": map[string]any{"password": "another long passphrase"}}); status != 409 || res["error"] != "current_password_mismatch" {
		t.Fatalf("change without current: %d %v", status, res)
	}

	login := func(email, password string) (int, map[string]any, string) {
		status, ch, _ := l.post(t, "", "/v1/login/methods/password:begin", nil)
		if status != 200 {
			t.Fatalf("login begin: %d %v", status, ch)
		}
		return l.post(t, "", "/v1/login/methods/password:complete", map[string]any{"flow_id": ch["flow_id"], "payload": map[string]any{"email": email, "password": password}})
	}
	status, res, pcookie := login("GP@example.com", pw)
	if status != 200 || pcookie == "" {
		t.Fatalf("generic login: %d %v", status, res)
	}
	if got := amr(t, l, pcookie); !slices.Equal(got, []any{"pwd"}) {
		t.Fatalf("amr: %v", got)
	}
	for _, c := range [][2]string{{"gp@example.com", "wrong but long enough"}, {"nobody@example.com", pw}} {
		if status, res, _ := login(c[0], c[1]); status != 401 || res["error"] != "authentication_failed" {
			t.Fatalf("login %v: %d %v", c, status, res)
		}
	}
	// 方式専用のパスでも同じパスワードで入れる。
	if status, _, _ := l.passwordLogin(t, "gp@example.com", pw); status != 200 {
		t.Fatalf("legacy login: %d", status)
	}
	// 汎用の無効化。パスワードを外すと、今のセッション以外は失効する。
	_, other = l.login(t, "gp@example.com")
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/credentials/"+cid+":revoke", nil, "Cookie", sessionCookie+"="+cookie); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if status, _ := l.me(t, other); status != 401 {
		t.Fatalf("other session after revoke: %d", status)
	}
	if status, _, _ := l.passwordLogin(t, "gp@example.com", pw); status != 401 {
		t.Fatalf("login after revoke: %d", status)
	}
}

// 方式専用の表に残っている TOTP とパスワードは、起動で authn_credentials へ移り、移した後もそのまま使える（ADR 0101）。
func TestStartupMigratesLegacyCredentials(t *testing.T) {
	l := newPasswordEnv(t)
	login, _ := l.login(t, "legacy@example.com")
	ctx := context.Background()
	const pw = "a long and memorable passphrase"
	secret := []byte("12345678901234567890")
	totpID := id.NewExternal(id.TOTP)
	crypter := pii.New(l.e.deps.KeyStore)
	if err := l.e.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, login["user_id"].(string))
		if err != nil {
			return err
		}
		ct, err := crypter.Encrypt(ctx, tx.DataKeys(), u.ID, secret, totpm.LegacySecretAAD)
		if err != nil {
			return err
		}
		now := l.e.deps.Clock.Now()
		if err := tx.TOTP().Create(ctx, port.TOTPCredential{ID: id.New(id.TOTP), PublicID: totpID, RealmID: u.RealmID, UserID: u.ID,
			SecretCiphertext: ct, LastUsedStep: totpm.Step(now), CreatedAt: now}); err != nil {
			return err
		}
		h, err := pwm.Hash(pwm.Normalize(pw), pwm.Params{Memory: 8, Time: 1, Threads: 1})
		if err != nil {
			return err
		}
		return tx.Passwords().Create(ctx, port.PasswordCredential{ID: id.New(id.Password), RealmID: u.RealmID, UserID: u.ID, Hash: h, CreatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	a, err := New(ctx, l.e.cfg, l.e.deps, feature.Registered())
	if err != nil {
		t.Fatal(err)
	}
	l.a = a
	if err := l.e.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if ts, _ := tx.TOTP().ListAll(ctx, 10); len(ts) != 0 {
			t.Errorf("legacy totp left: %d", len(ts))
		}
		ledger, err := tx.Features().List(ctx)
		if err != nil || !slices.ContainsFunc(ledger, func(r port.FeatureRecord) bool { return r.Feature == credential.MigrationTOTPPassword }) {
			t.Errorf("ledger: %+v, %v", ledger, err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, res, restricted := l.passwordLogin(t, "legacy@example.com", pw)
	if status != 200 || res["next"] != "second_factor" {
		t.Fatalf("password login after migration: %d %v", status, res)
	}
	// 移す前に使った窓は、移した後も使えない。
	if status, _, _ := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)}); status != 401 {
		t.Fatalf("reuse of the step used before the migration: %d", status)
	}
	l.advance(30 * time.Second)
	status, res, full := l.post(t, restricted, "/v1/login/second-factor:verify", map[string]string{"totp_code": l.code(t, secret)})
	if status != 200 || full == "" {
		t.Fatalf("totp after migration: %d %v", status, res)
	}
	if got := amr(t, l, full); !slices.Equal(got, []any{"pwd", "otp", "mfa"}) {
		t.Fatalf("amr: %v", got)
	}
	// 移した TOTP は移す前の公開 ID のまま、方式専用のパスで無効化できる。
	if w := l.do(t, l.a.PublicHandler(), "POST", "/v1/me/totp/"+totpID+":revoke", nil, "Cookie", sessionCookie+"="+full); w.Code != 204 {
		t.Fatalf("revoke migrated totp: %d %s", w.Code, w.Body)
	}
}
