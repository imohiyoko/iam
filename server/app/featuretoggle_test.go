package app

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// データがある状態でのフィーチャーの有効化・無効化（design.md 11.12、roadmap M6 の完了条件）。

// allFeaturesEnv はすべてのフィーチャーを設定で有効にした構成（空の DB なので台帳でも active になる）。
func allFeaturesEnv(t *testing.T) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		c.Realm.OrgDeletionGrace = 0
		names := []string{}
		for _, f := range feature.Registered() {
			names = append(names, f.Name)
		}
		c.Features = &names
		c.Security.Password.Argon2 = config.Argon2{MemoryKiB: 8, Iterations: 1, Parallelism: 1}
	}, feature.Registered())
}

// restart は同じ Storage で、設定のフィーチャーとバイナリを変えて起動し直す。
func (l *loginEnv) restart(t *testing.T, enabled []string, binary []feature.Feature) (*App, error) {
	t.Helper()
	cfg := l.e.cfg
	cfg.Features = &enabled
	a, err := New(context.Background(), cfg, l.e.deps, binary)
	if err == nil {
		l.a = a
	}
	return a, err
}

func without(fs []feature.Feature, names ...string) []feature.Feature {
	var out []feature.Feature
	for _, f := range fs {
		if !slices.Contains(names, f.Name) {
			out = append(out, f)
		}
	}
	return out
}

func names(fs []feature.Feature) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

func (l *loginEnv) ledgerState(t *testing.T, name string) port.FeatureState {
	t.Helper()
	var st port.FeatureState
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		rs, err := tx.Features().List(ctx)
		for _, r := range rs {
			if r.Feature == name {
				st = r.State
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// disableWithData は、データがある間は disabling に留まり、片付ければ台帳から消え、そのフィーチャーを含まないバイナリで起動できることを確かめる。
func disableWithData(t *testing.T, l *loginEnv, name string, remaining int) {
	t.Helper()
	ctx := context.Background()
	all := feature.Registered()
	// 台帳にある間は、含まないバイナリでは起動できない。
	if _, err := New(ctx, l.e.cfg, l.e.deps, without(all, name)); !errors.Is(err, feature.ErrLedgerMismatch) {
		t.Fatalf("%s: start without the feature while active: %v", name, err)
	}
	res, err := l.a.DisableFeature(ctx, name, false)
	if err != nil || res.Done || res.Remaining != remaining {
		t.Fatalf("%s: disable = %+v, %v", name, res, err)
	}
	if st := l.ledgerState(t, name); st != port.FeatureDisabling {
		t.Fatalf("%s: ledger = %q", name, st)
	}
	// disabling の間は、設定で有効でも動かさない（書き込まない）。
	if a, err := l.restart(t, names(all), all); err != nil || a.plan.IsActive(name) {
		t.Fatalf("%s: restart while disabling: active=%v, %v", name, err == nil && a.plan.IsActive(name), err)
	}
	res, err = l.a.DisableFeature(ctx, name, true)
	if err != nil || !res.Done || res.Purged != remaining || res.Remaining != 0 {
		t.Fatalf("%s: disable with purge = %+v, %v", name, res, err)
	}
	if st := l.ledgerState(t, name); st != "" {
		t.Fatalf("%s: ledger after disable = %q", name, st)
	}
	if _, err := l.restart(t, names(without(all, name)), without(all, name)); err != nil {
		t.Fatalf("%s: start without the feature after disable: %v", name, err)
	}
}

func TestDisablePasswordWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, cookie := l.login(t, "pat@example.com")
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": "a long and memorable passphrase"}); status != 204 {
		t.Fatalf("set: %d %v", status, res)
	}
	disableWithData(t, l, feature.Password, 1)
	// メールでのログインは続けられる。もう一度有効にすれば、パスワードを設定し直せる。
	_, cookie = l.login(t, "pat@example.com")
	all := feature.Registered()
	if _, err := l.restart(t, names(all), all); err != nil {
		t.Fatal(err)
	}
	if changed, err := l.a.EnableFeature(context.Background(), feature.Password); err != nil || !changed {
		t.Fatalf("enable again = %v, %v", changed, err)
	}
	if _, err := l.restart(t, names(all), all); err != nil || l.a.password == nil {
		t.Fatalf("restart after enable: %v", err)
	}
	if status, _, _ := l.passwordLogin(t, "pat@example.com", "a long and memorable passphrase"); status == 200 {
		t.Fatal("purged password still works")
	}
	if status, res := l.mePost(t, cookie, "/v1/me/password:set", map[string]string{"password": "another long passphrase here"}); status != 204 {
		t.Fatalf("set again: %d %v", status, res)
	}
}

func TestDisableQuotaWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	_, op := l.operator(t, "ops@example.com", role.RealmAdmin)
	for _, n := range []int{5, 2} {
		if status, out := l.admin(t, "/v1/admin/orgs/"+acme+"/quota/grants", op, map[string]any{"key": "members", "kind": "addon", "quantity": n}); status != 201 {
			t.Fatalf("grant: %d %v", status, out)
		}
	}
	disableWithData(t, l, feature.Quota, 2)
}

func TestDisableOrgLoginPolicyWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	if code, out := l.putSettings(t, owner, acme, map[string]any{"idle_timeout_seconds": 3600, "login_policy": map[string]any{"membership_email_domains": []string{"acme.example"}}}); code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}
	disableWithData(t, l, feature.OrgLoginPolicy, 1)
	// ポリシーだけを外し、ほかの設定は残す。
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		o, err := tx.Orgs().GetByPublicID(ctx, l.a.realm.ID, acme)
		if err != nil {
			return err
		}
		st, err := org.SettingsOf(o)
		if err != nil || st.LoginPolicy != nil || st.IdleTimeout == nil {
			t.Fatalf("settings after purge = %+v, %v", st, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDisableWarningsHasNoData(t *testing.T) {
	l := allFeaturesEnv(t)
	l.login(t, "pat@example.com")
	res, err := l.a.DisableFeature(context.Background(), feature.Warnings, false)
	if err != nil || !res.Done {
		t.Fatalf("disable = %+v, %v", res, err)
	}
	all := feature.Registered()
	if _, err := l.restart(t, names(without(all, feature.Warnings)), without(all, feature.Warnings)); err != nil {
		t.Fatal(err)
	}
	l.login(t, "pat@example.com")
}

// org は依存するフィーチャーを先に無効にし、共有 Org を運営者が削除してから無効にする。個人 Org は残し、再び有効にしたときに使う。
func TestDisableOrgWithData(t *testing.T) {
	l := allFeaturesEnv(t)
	ctx := context.Background()
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	personal := l.activeOrgPublic(t, owner)
	if _, err := l.a.DisableFeature(ctx, feature.Org, false); !errors.Is(err, ErrFeatureRequired) {
		t.Fatalf("disable org with dependents: %v", err)
	}
	for _, n := range []string{feature.Quota, feature.OrgLoginPolicy, feature.OrgManagedUsers} {
		if res, err := l.a.DisableFeature(ctx, n, false); err != nil || !res.Done {
			t.Fatalf("disable %s = %+v, %v", n, res, err)
		}
	}
	res, err := l.a.DisableFeature(ctx, feature.Org, false)
	if err != nil || res.Done || res.Remaining != 1 || res.Hint == "" {
		t.Fatalf("disable org = %+v, %v", res, err)
	}
	if _, err := l.a.DisableFeature(ctx, feature.Org, true); err == nil {
		t.Fatal("purged shared Orgs")
	}
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	if status, out := l.admin(t, "/v1/admin/orgs/"+acme+":delete", admin, map[string]bool{"immediate": true}); status != 200 {
		t.Fatalf("delete org: %d %v", status, out)
	}
	if res, err := l.a.DisableFeature(ctx, feature.Org, false); err != nil || !res.Done {
		t.Fatalf("disable org after deletion = %+v, %v", res, err)
	}
	rest := without(feature.Registered(), feature.Org, feature.Quota, feature.OrgLoginPolicy, feature.OrgManagedUsers)
	if _, err := l.restart(t, names(rest), rest); err != nil {
		t.Fatal(err)
	}
	if l.a.orgs != nil {
		t.Fatal("org runs after disable")
	}
	l.login(t, "boss@acme.example")
	l.login(t, "new@example.com")

	all := feature.Registered()
	if _, err := l.restart(t, names(all), all); err != nil {
		t.Fatal(err)
	}
	if changed, err := l.a.EnableFeature(ctx, feature.Org); err != nil || !changed {
		t.Fatalf("enable org again = %v, %v", changed, err)
	}
	if _, err := l.restart(t, names(all), all); err != nil {
		t.Fatal(err)
	}
	_, cookie := l.login(t, "boss@acme.example")
	if got := l.activeOrgPublic(t, cookie); got != personal {
		t.Fatalf("personal org after re-enable = %s, want %s", got, personal)
	}
	_, cookie = l.login(t, "new@example.com")
	if l.activeOrg(t, cookie) == "" {
		t.Fatal("no personal org for the user created while org was disabled")
	}
}
