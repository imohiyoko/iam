package app

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 本人の Personal Access Token（ADR 0109）を HTTP で確かめる。

// newPATEnv は既定のフィーチャーに、on なら personal_access_tokens を足した環境。
func newPATEnv(t *testing.T, on bool, edit func(*config.Config)) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.PersonalAccessTokens)
		}
		c.Features = &names
		if edit != nil {
			edit(c)
		}
	}, feature.Registered())
}

// bearerDo は公開 API を Bearer で呼ぶ。
func (l *loginEnv) bearerDo(t *testing.T, method, bearer, path string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), method, path, body, "Authorization", "Bearer "+bearer)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// createPAT は Bearer のセッションで PAT を作り、トークンと ID を返す。
func (l *loginEnv) createPAT(t *testing.T, bearer string, body map[string]any) (token, tokenID string) {
	t.Helper()
	code, out := l.bearerDo(t, "POST", bearer, "/v1/me/personal-access-tokens", body)
	if code != 201 {
		t.Fatalf("create PAT: %d %v", code, out)
	}
	p, _ := out["personal_access_token"].(map[string]any)
	return out["token"].(string), p["id"].(string)
}

func TestPersonalAccessTokens(t *testing.T) {
	l := newPATEnv(t, true, nil)
	ownerID, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})

	token, tokenID := l.createPAT(t, owner, map[string]any{"name": "ci", "scopes": []string{"users:read", "authz:check"}})
	if !strings.HasPrefix(token, pat.Prefix) || len(token) != pat.TokenLength {
		t.Fatalf("token = %q", token)
	}
	code, list := l.bearerDo(t, "GET", owner, "/v1/me/personal-access-tokens", nil)
	items, _ := list["personal_access_tokens"].([]any)
	if code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != tokenID || strings.Contains(fmt.Sprint(list), token) {
		t.Fatalf("list: %d %v", code, list)
	}

	// 管理 API：スコープの内（users:read）は通り、本人が持っていてもスコープの外（credentials:revoke）は 403。
	if code, out := l.adminDo(t, "GET", token, "/v1/admin/users", nil); code != 200 {
		t.Fatalf("users with PAT: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", token, "/v1/admin/users/"+ownerID+"/personal-access-tokens", nil); code != 403 {
		t.Fatalf("out of scope: %d", code)
	}
	// 運営者のセッションは max_auth_age を過ぎれば使えないが、PAT はトークンの期限まで使える。
	l.advance(time.Hour)
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/users", nil); code != 401 || out["error"] != "reauthentication_required" {
		t.Fatalf("stale session: %d %v", code, out)
	}
	if code, _ := l.adminDo(t, "GET", token, "/v1/admin/users", nil); code != 200 {
		t.Fatalf("PAT after max_auth_age: %d", code)
	}
	// 公開 API では使えない（PAT で PAT を作れない）。
	if code, _ := l.bearerDo(t, "POST", token, "/v1/me/personal-access-tokens", map[string]any{"name": "x", "scopes": []string{"users:read"}}); code != 401 {
		t.Fatalf("public API with PAT: %d", code)
	}
	// 作るには直近の認証が要る。
	if code, out := l.bearerDo(t, "POST", owner, "/v1/me/personal-access-tokens", map[string]any{"name": "x", "scopes": []string{"users:read"}}); code != 401 || out["error"] != "reauthentication_required" {
		t.Fatalf("create with a stale session: %d %v", code, out)
	}
	_, owner = l.operator(t, "root@example.com", role.RealmOwner)

	// イントロスペクション：連携先に結び付かない。
	in := p.introspect(t, token)
	if in["active"] != true || in["token_type"] != pat.TokenType || in["sub"] != ownerID || in["scope"] != "authz:check users:read" ||
		in["client_id"] != nil || in["aud"] != nil || in["iss"] != testIssuer || !slices.Equal(anyStrings(in["amr"]), []string{"pat"}) {
		t.Fatalf("introspection: %v", in)
	}
	// 判定の API：access_token の PAT はスコープで絞った文脈になる（本人は credentials:revoke を持つ）。
	check := func(action string, accessToken string) bool {
		body := map[string]any{"principal_id": ownerID, "action": action}
		if accessToken != "" {
			body["access_token"] = accessToken
		}
		code, out := l.adminDo(t, "POST", owner, "/v1/admin/authz:check", body)
		if code != 200 {
			t.Fatalf("check: %d %v", code, out)
		}
		return out["allowed"] == true
	}
	if !check(role.PermUsersRead, token) || check(role.PermCredentialsRevoke, token) || !check(role.PermCredentialsRevoke, "") {
		t.Fatal("check with PAT context")
	}
	// PAT で判定の API を呼ぶ（authz:check はスコープの内）。
	if code, out := l.adminDo(t, "POST", token, "/v1/admin/authz:check", map[string]any{"principal_id": ownerID, "action": role.PermUsersRead}); code != 200 || out["allowed"] != true {
		t.Fatalf("check by PAT: %d %v", code, out)
	}
	// 最後に使った時刻が付く。
	_, list = l.bearerDo(t, "GET", owner, "/v1/me/personal-access-tokens", nil)
	if items = list["personal_access_tokens"].([]any); items[0].(map[string]any)["last_used_at"] == nil {
		t.Fatalf("last_used_at: %v", list)
	}

	// 取り消せば次の要求から使えない。
	if code, _ := l.bearerDo(t, "POST", owner, "/v1/me/personal-access-tokens/"+tokenID+":revoke", nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := l.bearerDo(t, "POST", owner, "/v1/me/personal-access-tokens/"+tokenID+":revoke", nil); code != 204 {
		t.Fatalf("revoke again: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", token, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("revoked PAT: %d", code)
	}
	if in := p.introspect(t, token); in["active"] != false || len(in) != 1 {
		t.Fatalf("introspection after revoke: %v", in)
	}
	if check(role.PermUsersRead, token) == false {
		// 使えないトークンは文脈なし（条件の無い付与はそのまま）。
		t.Fatal("check with revoked PAT should fall back to no context")
	}
	created, revoked := l.auditOf(t, pat.EventCreated), l.auditOf(t, pat.EventRevoked)
	if len(created) != 1 || created[0].Details["token_id"] != tokenID || len(revoked) != 1 || revoked[0].Details["reason"] != pat.ReasonUser {
		t.Fatalf("audit: %+v %+v", created, revoked)
	}
	if strings.Contains(l.e.out.String(), token[len(pat.Prefix)+27:]) {
		t.Fatal("the secret leaked to the event sink")
	}
}

// 運営者の一覧・取り消し・ポリシー、侵害時の一括の取り消し。
func TestPersonalAccessTokenAdmin(t *testing.T) {
	l := newPATEnv(t, true, func(c *config.Config) { c.PersonalAccessTokens.MaxLifetime = config.Duration(90 * 24 * time.Hour) })
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	annID, ann := l.operator(t, "ann@example.com", role.RealmSupport)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)

	// ポリシー：owner だけ。ホスト先の上限を超えられない。
	if code, _ := l.adminDo(t, "GET", admin, "/v1/admin/personal-access-token-policy", nil); code != 403 {
		t.Fatalf("policy by admin: %d", code)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/personal-access-token-policy",
		map[string]any{"max_lifetime_seconds": 91 * 86400, "allowed_scopes": []string{}, "require_expiry": false}); code != 400 || out["error"] != "invalid_policy" {
		t.Fatalf("beyond host max: %d %v", code, out)
	}
	code, pol := l.adminDo(t, "PUT", owner, "/v1/admin/personal-access-token-policy",
		map[string]any{"max_lifetime_seconds": 3600, "allowed_scopes": []string{"users:*", "docs:read"}, "require_expiry": true})
	if code != 200 || pol["effective_max_lifetime_seconds"] != float64(3600) || pol["host_max_lifetime_seconds"] != float64(90*86400) || pol["updated_at"] == nil {
		t.Fatalf("put policy: %d %v", code, pol)
	}
	if code, my := l.bearerDo(t, "GET", ann, "/v1/me/personal-access-token-policy", nil); code != 200 || my["max_lifetime_seconds"] != float64(3600) ||
		!slices.Equal(anyStrings(my["allowed_scopes"]), []string{"docs:read", "users:*"}) {
		t.Fatalf("my policy: %d %v", code, my)
	}
	if code, out := l.bearerDo(t, "POST", ann, "/v1/me/personal-access-tokens", map[string]any{"name": "x", "scopes": []string{"credentials:revoke"}}); code != 400 || out["error"] != "scope_not_allowed" {
		t.Fatalf("scope not allowed: %d %v", code, out)
	}
	if code, out := l.bearerDo(t, "POST", ann, "/v1/me/personal-access-tokens", map[string]any{"name": "x", "scopes": []string{"bad"}}); code != 400 || out["error"] != "invalid_scope" {
		t.Fatalf("invalid scope: %d %v", code, out)
	}
	tok, tokID := l.createPAT(t, ann, map[string]any{"name": "laptop", "scopes": []string{"users:read"}})
	tok2, _ := l.createPAT(t, ann, map[string]any{"name": "ci", "scopes": []string{"users:read"}})
	if code, _ := l.adminDo(t, "GET", tok, "/v1/admin/users", nil); code != 200 {
		t.Fatalf("support PAT: %d", code)
	}

	// 一覧と取り消しは credentials:revoke（support は持たない）。取り消しは対象より強いこと。
	if code, _ := l.adminDo(t, "GET", ann, "/v1/admin/users/"+annID+"/personal-access-tokens", nil); code != 403 {
		t.Fatalf("list by support: %d", code)
	}
	code, list := l.adminDo(t, "GET", admin, "/v1/admin/users/"+annID+"/personal-access-tokens", nil)
	if items, _ := list["personal_access_tokens"].([]any); code != 200 || len(items) != 2 || items[0].(map[string]any)["expires_at"] == nil {
		t.Fatalf("list by admin: %d %v", code, list)
	}
	if code, _ := l.adminDo(t, "POST", admin, "/v1/admin/users/"+annID+"/personal-access-tokens/pat_nope:revoke", nil); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}
	if code, _ := l.adminDo(t, "POST", admin, "/v1/admin/users/"+annID+"/personal-access-tokens/"+tokID+":revoke", nil); code != 204 {
		t.Fatalf("revoke by admin: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", tok, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("revoked by admin: %d", code)
	}
	if ev := l.auditOf(t, pat.EventRevoked); len(ev) != 1 || ev[0].Details["reason"] != pat.ReasonOperator || ev[0].Actor.Type != "user" {
		t.Fatalf("operator revoke audit: %+v", ev)
	}
	// 侵害時の初動は PAT も取り消す。
	code, res := l.adminDo(t, "POST", admin, "/v1/admin/users/"+annID+"/credentials:revoke-all", nil)
	if code != 200 || res["personal_access_tokens"] != float64(1) {
		t.Fatalf("revoke-all: %d %v", code, res)
	}
	if code, _ := l.adminDo(t, "GET", tok2, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("after revoke-all: %d", code)
	}

	// ポリシーの寿命の上限は既存のトークンにも効く。
	_, owner = l.operator(t, "root@example.com", role.RealmOwner)
	tok3, _ := l.createPAT(t, owner, map[string]any{"name": "short", "scopes": []string{"users:read"}})
	l.advance(time.Hour)
	if code, _ := l.adminDo(t, "GET", tok3, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("beyond realm max lifetime: %d", code)
	}
	if ev := l.auditOf(t, pat.EventPolicyUpdated); len(ev) != 1 || ev[0].Details["require_expiry"] != true {
		t.Fatalf("policy audit: %+v", ev)
	}

	// 無効化で片付ける（トークンとポリシー）。
	enabled := slices.DeleteFunc(slices.Clone(*l.e.cfg.Features), func(s string) bool { return s == feature.PersonalAccessTokens })
	a, err := l.restart(t, enabled, feature.Registered())
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := l.adminDo(t, "GET", tok3, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("PAT with the feature off: %d", code)
	}
	if res, err := a.DisableFeature(context.Background(), feature.PersonalAccessTokens, false); err != nil || res.Done || res.Remaining != 4 {
		t.Fatalf("disable without purge: %+v %v", res, err)
	}
	if res, err := a.DisableFeature(context.Background(), feature.PersonalAccessTokens, true); err != nil || !res.Done || res.Purged != 4 {
		t.Fatalf("disable with purge: %+v %v", res, err)
	}
}

// フィーチャーがオフなら API は 404、PAT の形のトークンはどこでも通らない。
func TestPersonalAccessTokensOff(t *testing.T) {
	l := newPATEnv(t, false, nil)
	ownerID, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/me/personal-access-tokens"}, {"POST", "/v1/me/personal-access-tokens"}, {"GET", "/v1/me/personal-access-token-policy"},
		{"POST", "/v1/me/personal-access-tokens/pat_x:revoke"},
	} {
		if code, _ := l.bearerDo(t, c.method, owner, c.path, map[string]any{"name": "x", "scopes": []string{"users:read"}}); code != 404 {
			t.Errorf("%s %s: %d", c.method, c.path, code)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/admin/users/" + ownerID + "/personal-access-tokens"}, {"GET", "/v1/admin/personal-access-token-policy"},
		{"POST", "/v1/admin/users/" + ownerID + "/personal-access-tokens/pat_x:revoke"},
	} {
		if code, _ := l.adminDo(t, c.method, owner, c.path, nil); code != 404 {
			t.Errorf("%s %s: %d", c.method, c.path, code)
		}
	}
	// 正しい形の PAT（他の環境で作ったもの）も受け付けない。
	fake := pat.Prefix + strings.Repeat("0", 26) + "_" + strings.Repeat("a", 49)
	if code, _ := l.adminDo(t, "GET", fake, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("PAT-shaped token: %d", code)
	}
	if in := p.introspect(t, fake); in["active"] != false {
		t.Fatalf("introspection: %v", in)
	}
}

// 消したユーザーの PAT は使えない（統合は authn/merge のテストで確かめる）。
func TestPersonalAccessTokenErase(t *testing.T) {
	l := newPATEnv(t, true, nil)
	annID, ann := l.operator(t, "ann@example.com", role.RealmSupport)
	tok, _ := l.createPAT(t, ann, map[string]any{"name": "x", "scopes": []string{"users:read"}})
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, annID)
		if err != nil {
			return err
		}
		return tx.Users().Erase(ctx, l.a.realm.ID, u.ID, l.a.deps.Clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := l.adminDo(t, "GET", tok, "/v1/admin/users", nil); code != 401 {
		t.Fatalf("erased user's PAT: %d", code)
	}
}

// 統合元の PAT は取り消され、統合先の権限で使えない。
func TestPersonalAccessTokenMerge(t *testing.T) {
	l := newPATEnv(t, true, func(c *config.Config) { *c.Features = append(*c.Features, feature.AccountMerge) })
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "client_secret"})
	_, alice := l.login(t, "alice@example.com")
	_, bob := l.login(t, "bob@example.com")
	tok, _ := l.createPAT(t, bob, map[string]any{"name": "x", "scopes": []string{"users:read"}})
	if in := p.introspect(t, tok); in["active"] != true {
		t.Fatalf("before merge: %v", in)
	}
	if code, out := l.mePost(t, alice, "/v1/me/merges", map[string]string{"token": l.mergeToken(t, bob)}); code != 200 {
		t.Fatalf("merge: %d %v", code, out)
	}
	if in := p.introspect(t, tok); in["active"] != false {
		t.Fatalf("after merge: %v", in)
	}
	if ev := l.auditOf(t, "user.merged"); len(ev) != 1 || ev[0].Details["personal_access_tokens_revoked"] != float64(1) {
		t.Fatalf("merge audit: %+v", ev)
	}
}

func anyStrings(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
