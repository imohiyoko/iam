package app

import (
	"context"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウント統合（design.md 11.6、ADR 0082）を HTTP で確かめる。

func mergeEnv(t *testing.T, on bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = passkeyOrigin
		c.Passkey.Origins = []string{passkeyOrigin}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.AccountMerge)
		}
		c.Features = &names
	}, feature.Registered())
}

func (l *loginEnv) mergeToken(t *testing.T, cookie string) string {
	t.Helper()
	code, out := l.mePost(t, cookie, "/v1/me/merge-tokens", nil)
	if code != 201 || out["token"] == "" {
		t.Fatalf("merge token: %d %v", code, out)
	}
	return out["token"].(string)
}

func TestAccountMerge(t *testing.T) {
	l := mergeEnv(t, true)
	_, alice := l.login(t, "alice@example.com")
	aliceID := l.userID(t, "alice@example.com")
	acme := l.sharedOrg(t, alice, "Acme")
	l.join(t, alice, acme, "bob@example.com", "admin")
	bobID, _ := l.operator(t, "bob@example.com", role.RealmSupport)
	_, bob := l.login(t, "bob@example.com")
	bobs := l.sharedOrg(t, bob, "Bobs")
	key := passkeytest.New(passkeyOrigin)
	if code, out := l.registerPasskey(t, bob, key, "bob's key"); code != 200 {
		t.Fatalf("register passkey: %d %v", code, out)
	}
	if code, out := l.meDo(t, "PATCH", bob, "/v1/me/attributes", map[string]any{"attributes": map[string]any{}}); code != 404 {
		t.Fatalf("attributes off: %d %v", code, out)
	}

	// 同じアカウントへの統合はできない。トークンは1回限り。
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": l.mergeToken(t, alice)}); code != 400 || out["error"] != "same_user" {
		t.Fatalf("self merge: %d %v", code, out)
	}
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": "nope"}); code != 400 || out["error"] != "invalid_merge_token" {
		t.Fatalf("bad token: %d %v", code, out)
	}

	token := l.mergeToken(t, bob)
	code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": token})
	if code != 200 || out["merged_user_id"] != bobID || out["shared_org_id"] == nil || out["personal_org_id"] == nil {
		t.Fatalf("merge: %d %v", code, out)
	}
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": token}); code != 400 || out["error"] != "invalid_merge_token" {
		t.Fatalf("token reuse: %d %v", code, out)
	}

	// 統合元のセッションは失効し、統合元のメール・passkey は統合先のものになる。
	if code, _ := l.me(t, bob); code != 401 {
		t.Fatalf("bob's session after merge: %d", code)
	}
	if got := l.userID(t, "bob@example.com"); got != aliceID {
		t.Fatalf("bob's email belongs to %s, want %s", got, aliceID)
	}
	if res, _ := l.login(t, "bob@example.com"); res["user_id"] != aliceID {
		t.Fatalf("login with bob's email: %v", res)
	}
	code, res, viaKey := l.passkeyLogin(t, key)
	if code != 200 || res["user_id"] != aliceID {
		t.Fatalf("login with bob's passkey: %d %v", code, res)
	}

	// Membership：Acme では役割の高い方（owner）を残し、Bobs を引き継ぐ。統合元の個人 Org は残し、中身は新しい Org に移す。
	_, orgs := l.myOrgs(t, viaKey)
	roles := map[string]string{}
	for _, o := range orgs.Orgs {
		roles[o.ID] = o.Kind + "/" + o.Role
	}
	shared := out["shared_org_id"].(string)
	if roles[acme] != "shared/owner" || roles[bobs] != "shared/owner" || roles[shared] != "shared/owner" || len(orgs.Orgs) != 4 ||
		roles[out["personal_org_id"].(string)] != "" {
		t.Fatalf("orgs after merge = %v", roles)
	}

	// ロールの付与は統合先に移る。統合元は merged。
	aliceInternal := l.internalUserID(t, aliceID)
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		if u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, bobID); err != nil || u.Status != port.UserMerged ||
			u.MergedInto != aliceInternal {
			t.Errorf("merged user = %+v, %v", u, err)
		}
		bs, err := tx.RoleBindings().ListByPrincipal(ctx, l.a.realm.ID, port.PrincipalUser, aliceInternal)
		if err != nil || len(bs) != 1 || bs[0].Role != role.RealmSupport {
			t.Errorf("bindings of alice = %+v, %v", bs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	if types["user.merged"] != 1 {
		t.Fatalf("audit: %v", types)
	}
}

func TestAccountMergeGuards(t *testing.T) {
	l := mergeEnv(t, false)
	_, alice := l.login(t, "alice@example.com")
	if code, _ := l.mePost(t, alice, "/v1/me/merge-tokens", nil); code != 404 {
		t.Fatalf("feature off: %d", code)
	}
	l = mergeEnv(t, true)
	_, alice = l.login(t, "alice@example.com")
	_, bob := l.login(t, "bob@example.com")
	token := l.mergeToken(t, bob)
	// 直近の本人確認が要る。
	l.advance(20 * time.Minute)
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": token}); code != 401 || out["error"] != "reauthentication_required" {
		t.Fatalf("stale session: %d %v", code, out)
	}
	_, alice = l.login(t, "alice@example.com")
	// トークンは 10 分で切れる。
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": token}); code != 400 || out["error"] != "invalid_merge_token" {
		t.Fatalf("expired token: %d %v", code, out)
	}
	// 削除の予定があれば統合しない。
	_, bob = l.login(t, "bob@example.com")
	token = l.mergeToken(t, bob)
	if code, out := l.mePost(t, alice, "/v1/me/account:delete", nil); code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	_, alice = l.login(t, "alice@example.com")
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": token}); code == 200 {
		t.Fatalf("merge into an account pending deletion: %d %v", code, out)
	}
}
