package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

type myOrgRow struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	MembershipID string `json:"membership_id"`
	Active       bool   `json:"active"`
}

type myOrgs struct {
	Orgs []myOrgRow `json:"orgs"`
}

func (l *loginEnv) myOrgs(t *testing.T, cookie string) (int, myOrgs) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/orgs", nil, "Cookie", sessionCookie+"="+cookie)
	var out myOrgs
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// activeOrg はセッションの active な Org（内部 ID）を返す。
func (l *loginEnv) activeOrg(t *testing.T, cookie string) string {
	t.Helper()
	v, err := l.a.sessions.Validate(context.Background(), l.a.realm.ID, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return v.ActiveOrgID
}

func TestSignupCreatesPersonalOrgAndSessionEntersIt(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	_, cookie := l.login(t, "pat@example.com")
	code, got := l.myOrgs(t, cookie)
	if code != 200 || len(got.Orgs) != 1 {
		t.Fatalf("orgs = %d %+v", code, got)
	}
	o := got.Orgs[0]
	if o.Kind != "personal" || o.Role != "owner" || !o.Active || o.Name != "" {
		t.Fatalf("personal org = %+v", o)
	}
	active := l.activeOrg(t, cookie)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		po, err := tx.Orgs().GetByPublicID(ctx, l.a.realm.ID, o.ID)
		if err != nil {
			return err
		}
		if po.ID != active {
			t.Errorf("active org %s, want personal %s", active, po.ID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 2回目のログインでも個人 Org は1つのまま。
	_, again := l.login(t, "pat@example.com")
	if _, got := l.myOrgs(t, again); len(got.Orgs) != 1 {
		t.Fatalf("orgs after relogin = %+v", got)
	}
}

func TestCreateSharedOrg(t *testing.T) {
	l := newLoginEnvWith(t, nil, feature.Registered())
	_, cookie := l.login(t, "pat@example.com")
	code, body := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": "  Acme  "})
	if code != 201 || body["name"] != "Acme" || body["kind"] != "shared" || body["role"] != "owner" || body["active"] != false {
		t.Fatalf("create = %d %v", code, body)
	}
	for _, name := range []string{"", "   ", "a\nb", strings.Repeat("あ", 101)} {
		if code, body := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": name}); code != 400 || body["error"] != "invalid_org_name" {
			t.Errorf("name %q = %d %v", name, code, body)
		}
	}
	if _, got := l.myOrgs(t, cookie); len(got.Orgs) != 2 || !slices.ContainsFunc(got.Orgs, func(o myOrgRow) bool { return o.ID == body["id"] }) {
		t.Fatalf("orgs = %+v", got)
	}

	// 運営者は Org と Membership を見られる。
	_, opToken := l.operator(t, "ops@example.com", role.RealmSupport)
	var org struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if code := l.adminGet(t, "/v1/admin/orgs/"+body["id"].(string), opToken, &org); code != 200 || org.Kind != "shared" {
		t.Fatalf("admin get = %d %+v", code, org)
	}
	var ms struct {
		Memberships []struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
			Status string `json:"status"`
		} `json:"memberships"`
	}
	if code := l.adminGet(t, "/v1/admin/orgs/"+body["id"].(string)+"/memberships", opToken, &ms); code != 200 || len(ms.Memberships) != 1 ||
		ms.Memberships[0].UserID != l.userID(t, "pat@example.com") || ms.Memberships[0].Role != "owner" || ms.Memberships[0].Status != "active" {
		t.Fatalf("admin memberships = %d %+v", code, ms)
	}
	// support は作れない。
	if code, _ := l.admin(t, "/v1/admin/orgs", opToken, map[string]string{"name": "X", "owner_id": l.userID(t, "pat@example.com")}); code != 403 {
		t.Fatalf("support create = %d", code)
	}
}

func TestOrgCreationPolicy(t *testing.T) {
	t.Run("operators_only", func(t *testing.T) {
		l := newLoginEnvWith(t, func(c *config.Config) { c.Realm.OrgCreation = "operators_only" }, feature.Registered())
		_, cookie := l.login(t, "pat@example.com")
		if code, body := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": "Acme"}); code != 403 || body["error"] != "org_creation_not_allowed" {
			t.Fatalf("user create = %d %v", code, body)
		}
		_, opToken := l.operator(t, "ops@example.com", role.RealmAdmin)
		code, body := l.admin(t, "/v1/admin/orgs", opToken, map[string]string{"name": "Acme", "owner_id": l.userID(t, "pat@example.com")})
		if code != 201 || body["kind"] != "shared" {
			t.Fatalf("operator create = %d %v", code, body)
		}
		if code, _ := l.admin(t, "/v1/admin/orgs", opToken, map[string]string{"name": "Acme", "owner_id": "usr_nobody"}); code != 404 {
			t.Fatalf("unknown owner = %d", code)
		}
	})
	t.Run("invite_only", func(t *testing.T) {
		l := newLoginEnvWith(t, func(c *config.Config) { c.Realm.OrgCreation = "invite_only" }, feature.Registered())
		_, cookie := l.login(t, "pat@example.com")
		// 個人 Org だけでは作れない。
		if code, _ := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": "Acme"}); code != 403 {
			t.Fatalf("without shared membership = %d", code)
		}
		_, opToken := l.operator(t, "ops@example.com", role.RealmOwner)
		if code, _ := l.admin(t, "/v1/admin/orgs", opToken, map[string]string{"name": "Seed", "owner_id": l.userID(t, "pat@example.com")}); code != 201 {
			t.Fatalf("operator create = %d", code)
		}
		if code, _ := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": "Acme"}); code != 201 {
			t.Fatalf("with shared membership = %d", code)
		}
	})
}

func TestOrgOffHasNoOrgs(t *testing.T) {
	l := newLoginEnv(t)
	_, cookie := l.login(t, "pat@example.com")
	if code, _ := l.myOrgs(t, cookie); code != 404 {
		t.Fatalf("orgs with org off = %d", code)
	}
	if code, _ := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": "Acme"}); code != 404 {
		t.Fatalf("create with org off = %d", code)
	}
	if got := l.activeOrg(t, cookie); got != "" {
		t.Fatalf("active org with org off = %q", got)
	}
}

// 後から Org を有効にすると、既存のユーザーに個人 Org を作る（11.13）。
func TestEnableOrgPreparesPersonalOrgs(t *testing.T) {
	without := []feature.Feature{}
	for _, f := range feature.Registered() {
		if f.Name != feature.Org {
			without = append(without, f)
		}
	}
	l := newLoginEnvWith(t, nil, without)
	_, _ = l.login(t, "pat@example.com")
	_, _ = l.login(t, "sam@example.com")

	ctx := context.Background()
	a, err := New(ctx, l.e.cfg, l.e.deps, feature.Registered())
	if err != nil {
		t.Fatal(err)
	}
	if a.orgs != nil {
		t.Fatal("org runs before enable")
	}
	if changed, err := a.EnableFeature(ctx, feature.Org); err != nil || !changed {
		t.Fatalf("enable = %v, %v", changed, err)
	}
	if changed, err := a.EnableFeature(ctx, feature.Org); err != nil || changed {
		t.Fatalf("enable again = %v, %v", changed, err)
	}
	err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		us, err := tx.Users().List(ctx, a.realm.ID, "", 10)
		if err != nil {
			return err
		}
		if len(us) != 2 {
			t.Fatalf("users = %d", len(us))
		}
		for _, u := range us {
			if _, err := tx.Orgs().GetPersonal(ctx, a.realm.ID, u.ID); err != nil {
				t.Errorf("personal org of %s: %v", u.PublicID, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(ctx, l.e.cfg, l.e.deps, feature.Registered())
	if err != nil {
		t.Fatal(err)
	}
	if restarted.orgs == nil {
		t.Fatal("org does not run after enable")
	}
	l.a = restarted
	_, cookie := l.login(t, "pat@example.com")
	if l.activeOrg(t, cookie) == "" {
		t.Fatal("no active org after enable")
	}
}

func TestEnableFeatureRequiresConfig(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) { c.Features = &[]string{} }, feature.Registered())
	if _, err := l.a.EnableFeature(context.Background(), feature.Org); err == nil {
		t.Fatal("enabled a feature disabled in config")
	}
	if _, err := l.a.EnableFeature(context.Background(), "nope"); err == nil {
		t.Fatal("enabled an unknown feature")
	}
}
