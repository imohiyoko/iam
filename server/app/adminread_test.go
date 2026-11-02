package app

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/port"
)

// 管理 API の一覧・取得・検索と運営者によるメールの操作（ADR 0097）を HTTP で確かめる。

func (l *loginEnv) adminGetJSON(t *testing.T, bearer, path string) (int, map[string]any) {
	t.Helper()
	return l.adminDo(t, "GET", bearer, path, nil)
}

func ids(t *testing.T, out map[string]any, key string) []string {
	t.Helper()
	list, _ := out[key].([]any)
	var res []string
	for _, x := range list {
		res = append(res, x.(map[string]any)["id"].(string))
	}
	slices.Sort(res)
	return res
}

func sortedIDs(v ...string) []string {
	slices.Sort(v)
	return v
}

func (l *loginEnv) auditOf(t *testing.T, typ string) []audit.Event {
	t.Helper()
	var out []audit.Event
	for _, e := range l.auditTypes(t) {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestAdminListAndGetUsers(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	ownerID, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	_, billing := l.operator(t, "billing@example.com", role.RealmBilling)
	_, boss := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, boss, "Acme")
	l.join(t, boss, acme, "ann@acme.example", "member")
	ann, bossID := l.userID(t, "ann@acme.example"), l.userID(t, "boss@acme.example")

	if code, _ := l.adminGetJSON(t, billing, "/v1/admin/users"); code != 403 {
		t.Fatalf("billing lists users: %d", code)
	}
	if code, _ := l.adminGetJSON(t, "", "/v1/admin/users"); code != 401 {
		t.Fatalf("anonymous lists users: %d", code)
	}
	code, out := l.adminGetJSON(t, support, "/v1/admin/users")
	if code != 200 || len(out["users"].([]any)) != 5 || out["next_cursor"] != nil {
		t.Fatalf("support lists users: %d %v", code, out)
	}
	if b, _ := json.Marshal(out); strings.Contains(string(b), "@") {
		t.Fatalf("list exposes email addresses: %s", b)
	}

	// メールは完全一致（小文字化だけの正規化）。部分一致はしない。
	search := func(q string) []string {
		t.Helper()
		code, out := l.adminGetJSON(t, support, "/v1/admin/users?"+q)
		if code != 200 {
			t.Fatalf("search %s: %d %v", q, code, out)
		}
		return ids(t, out, "users")
	}
	if got := search("email=" + url.QueryEscape("ANN@Acme.Example")); !slices.Equal(got, []string{ann}) {
		t.Fatalf("email search = %v", got)
	}
	if got := search("email=" + url.QueryEscape("nobody@acme.example")); len(got) != 0 {
		t.Fatalf("unknown email = %v", got)
	}
	if code, out := l.adminGetJSON(t, support, "/v1/admin/users?email=acme.example"); code != 400 || out["error"] != "invalid_email" {
		t.Fatalf("partial email: %d %v", code, out)
	}
	if got := search("org_id=" + acme); !slices.Equal(got, sortedIDs(ann, bossID)) {
		t.Fatalf("org search = %v", got)
	}
	if got := search("org_id=org_missing"); len(got) != 0 {
		t.Fatalf("missing org = %v", got)
	}
	if got := search("email=" + url.QueryEscape("ann@acme.example") + "&org_id=" + acme + "&status=active"); !slices.Equal(got, []string{ann}) {
		t.Fatalf("combined search = %v", got)
	}
	future := url.QueryEscape(l.a.deps.Clock.Now().Add(time.Hour).Format(time.RFC3339))
	if got := search("created_from=" + future); len(got) != 0 {
		t.Fatalf("created_from in the future = %v", got)
	}
	if got := search("created_before=" + future); len(got) != 5 {
		t.Fatalf("created_before in the future = %v", got)
	}
	for _, q := range []string{"limit=0", "limit=201", "connection=google", "subject=x", "status=unknown"} {
		if code, _ := l.adminGetJSON(t, support, "/v1/admin/users?"+q); code != 400 {
			t.Fatalf("bad query %s: %d", q, code)
		}
	}

	// 公開 ID の順に、next_cursor で続きを取る。
	var paged []string
	after := ""
	for range 10 {
		code, out := l.adminGetJSON(t, support, "/v1/admin/users?limit=2&after="+after)
		if code != 200 {
			t.Fatalf("page: %d %v", code, out)
		}
		for _, u := range out["users"].([]any) {
			paged = append(paged, u.(map[string]any)["id"].(string))
		}
		next, _ := out["next_cursor"].(string)
		if next == "" {
			break
		}
		after = next
	}
	if len(paged) != 5 || !slices.IsSorted(paged) {
		t.Fatalf("paging = %v", paged)
	}

	// 停止中は status=suspended で引け、一覧と詳細の suspended が真。
	if code, out := l.admin(t, "/v1/admin/users/"+ann+"/suspensions", owner, map[string]any{"category": "tos_violation", "reason": "spam"}); code != 201 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	if got := search("status=suspended"); !slices.Equal(got, []string{ann}) {
		t.Fatalf("suspended = %v", got)
	}
	if got := search("status=active"); slices.Contains(got, ann) || len(got) != 4 {
		t.Fatalf("active = %v", got)
	}

	// 詳細。アドレスは include_pii と pii:read のときだけ。
	code, out = l.adminGetJSON(t, support, "/v1/admin/users/"+ann)
	if code != 200 || out["suspended"] != true || out["status"] != "active" || len(out["suspensions"].([]any)) != 1 {
		t.Fatalf("support gets user: %d %v", code, out)
	}
	emails := out["emails"].([]any)
	if len(emails) != 1 || emails[0].(map[string]any)["email"] != nil || emails[0].(map[string]any)["verified"] != true {
		t.Fatalf("emails without pii = %v", emails)
	}
	if ms := out["memberships"].([]any); len(ms) != 2 { // 個人 Org と Acme
		t.Fatalf("memberships = %v", ms)
	}
	if _, ok := out["credentials"].(map[string]any); !ok {
		t.Fatalf("credentials = %v", out["credentials"])
	}
	if code, out := l.adminGetJSON(t, support, "/v1/admin/users/"+ann+"?include_pii=true"); code != 403 || out["error"] != "permission_denied" {
		t.Fatalf("support reveals pii: %d %v", code, out)
	}
	if n := len(l.auditOf(t, "user.pii_read")); n != 0 {
		t.Fatalf("pii_read without reveal = %d", n)
	}
	code, out = l.adminGetJSON(t, owner, "/v1/admin/users/"+ann+"?include_pii=true")
	if code != 200 || out["emails"].([]any)[0].(map[string]any)["email"] != "ann@acme.example" {
		t.Fatalf("owner reveals pii: %d %v", code, out)
	}
	reads := l.auditOf(t, "user.pii_read")
	if len(reads) != 1 || reads[0].Actor.ID != ownerID || reads[0].Details["user_id"] != ann {
		t.Fatalf("pii_read audit = %+v", reads)
	}
	if code, _ := l.adminGetJSON(t, support, "/v1/admin/users/usr_missing"); code != 404 {
		t.Fatalf("missing user: %d", code)
	}
	code, out = l.adminGetJSON(t, support, "/v1/admin/users/"+ann+"/memberships")
	if code != 200 || len(out["memberships"].([]any)) != 2 {
		t.Fatalf("memberships: %d %v", code, out)
	}
}

func TestAdminUsersWithoutOrg(t *testing.T) {
	l := newLoginEnvWith(t, nil, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	id, _ := l.operator(t, "someone@example.com", role.RealmSupport)
	code, out := l.adminGetJSON(t, owner, "/v1/admin/users/"+id)
	if code != 200 || out["memberships"] != nil {
		t.Fatalf("user without org: %d %v", code, out)
	}
	if code, out := l.adminGetJSON(t, owner, "/v1/admin/users/"+id+"/memberships"); code != 404 || out["error"] != "org_disabled" {
		t.Fatalf("memberships without org: %d %v", code, out)
	}
	if code, out := l.adminGetJSON(t, owner, "/v1/admin/orgs"); code != 404 || out["error"] != "org_disabled" {
		t.Fatalf("orgs without org: %d %v", code, out)
	}
}

func TestAdminSessionsListAndRevokeAll(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	_, security := l.operator(t, "security@example.com", role.RealmSecurity)
	_, billing := l.operator(t, "billing@example.com", role.RealmBilling)
	_, c1 := l.login(t, "ann@example.com")
	_, c2 := l.login(t, "ann@example.com")
	ann := l.userID(t, "ann@example.com")

	code, out := l.adminGetJSON(t, support, "/v1/admin/users/"+ann+"/sessions")
	if code != 200 || len(out["sessions"].([]any)) != 2 {
		t.Fatalf("sessions: %d %v", code, out)
	}
	s0 := out["sessions"].([]any)[0].(map[string]any)
	if s0["ip"] != nil || s0["user_agent"] != nil || s0["active_org_id"] == nil {
		t.Fatalf("session view = %v", s0)
	}
	if code, _ := l.adminGetJSON(t, billing, "/v1/admin/users/"+ann+"/sessions"); code != 403 {
		t.Fatalf("billing lists sessions: %d", code)
	}
	// support は読めるが失効できない。
	if code, _ := l.admin(t, "/v1/admin/users/"+ann+"/sessions:revoke-all", support, nil); code != 403 {
		t.Fatalf("support revokes: %d", code)
	}
	code, out = l.admin(t, "/v1/admin/users/"+ann+"/sessions:revoke-all", security, nil)
	if code != 200 || out["sessions"] != float64(2) {
		t.Fatalf("revoke-all: %d %v", code, out)
	}
	for _, c := range []string{c1, c2} {
		if code, _ := l.me(t, c); code != 401 {
			t.Fatalf("revoked session still works: %d", code)
		}
	}
	// 認証情報（メール）は残り、もう一度ログインできる。
	if _, c3 := l.login(t, "ann@example.com"); c3 == "" {
		t.Fatal("cannot log in again")
	}
	if code, out := l.adminGetJSON(t, support, "/v1/admin/users/"+ann); code != 200 || len(out["emails"].([]any)) != 1 {
		t.Fatalf("emails after revoke-all: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/users/"+ann+"/sessions:revoke-all", security, nil); code != 200 || out["sessions"] != float64(1) {
		t.Fatalf("second revoke-all: %d %v", code, out)
	}
	if code, _ := l.admin(t, "/v1/admin/users/usr_missing/sessions:revoke-all", security, nil); code != 404 {
		t.Fatalf("missing user: %d", code)
	}
	if n := len(l.auditOf(t, "session.revoked")); n < 2 {
		t.Fatalf("session.revoked audit = %d", n)
	}
}

func TestAdminReverseLookups(t *testing.T) {
	l := serviceAccountsEnv(t)
	ownerID, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	_, billing := l.operator(t, "billing@example.com", role.RealmBilling)
	_, _ = l.login(t, "ann@example.com")
	ann := l.userID(t, "ann@example.com")

	code, out := l.admin(t, "/v1/admin/groups", owner, map[string]any{"name": "auditors"})
	if code != 201 {
		t.Fatalf("group: %d %v", code, out)
	}
	gid := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/groups/"+gid+"/members", owner, map[string]any{"principal_type": "user", "principal_id": ann}); code != 204 {
		t.Fatalf("member: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmSupport, "principal_type": "group", "principal_id": gid}); code != 201 {
		t.Fatalf("bind group: %d %v", code, out)
	}

	code, out = l.adminGetJSON(t, support, "/v1/admin/users/"+ownerID+"/role-bindings")
	if code != 200 || len(out["bindings"].([]any)) != 1 || out["bindings"].([]any)[0].(map[string]any)["role"] != role.RealmOwner {
		t.Fatalf("owner bindings: %d %v", code, out)
	}
	code, out = l.adminGetJSON(t, support, "/v1/admin/users/"+ann+"/role-bindings")
	if code != 200 || len(out["bindings"].([]any)) != 1 {
		t.Fatalf("ann bindings: %d %v", code, out)
	}
	if b := out["bindings"].([]any)[0].(map[string]any); b["via_group_id"] != gid || b["principal_type"] != "group" || b["role"] != role.RealmSupport {
		t.Fatalf("group binding = %v", b)
	}
	code, out = l.adminGetJSON(t, support, "/v1/admin/users/"+ann+"/groups")
	if code != 200 || len(out["groups"].([]any)) != 1 || out["groups"].([]any)[0].(map[string]any)["direct"] != true {
		t.Fatalf("ann groups: %d %v", code, out)
	}
	for _, p := range []string{"/role-bindings", "/groups"} {
		if code, _ := l.adminGetJSON(t, billing, "/v1/admin/users/"+ann+p); code != 403 {
			t.Fatalf("billing %s: %d", p, code)
		}
		if code, _ := l.adminGetJSON(t, support, "/v1/admin/users/usr_missing"+p); code != 404 {
			t.Fatalf("missing user %s: %d", p, code)
		}
	}

	// サービスアカウントも同じ。
	code, out = l.admin(t, "/v1/admin/service-accounts", owner, map[string]any{"name": "billing-sync"})
	if code != 201 {
		t.Fatalf("service account: %d %v", code, out)
	}
	sa := out["id"].(string)
	if code, out := l.admin(t, "/v1/admin/role-bindings", owner, map[string]any{"role": role.RealmBilling, "principal_type": "service_account", "principal_id": sa}); code != 201 {
		t.Fatalf("bind sa: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/groups/"+gid+"/members", owner, map[string]any{"principal_type": "service_account", "principal_id": sa}); code != 204 {
		t.Fatalf("sa member: %d %v", code, out)
	}
	code, out = l.adminGetJSON(t, support, "/v1/admin/service-accounts/"+sa+"/role-bindings")
	if code != 200 || len(out["bindings"].([]any)) != 2 {
		t.Fatalf("sa bindings: %d %v", code, out)
	}
	code, out = l.adminGetJSON(t, support, "/v1/admin/service-accounts/"+sa+"/groups")
	if code != 200 || !slices.Equal(ids(t, out, "groups"), []string{gid}) {
		t.Fatalf("sa groups: %d %v", code, out)
	}
	if code, _ := l.adminGetJSON(t, support, "/v1/admin/service-accounts/sva_missing/role-bindings"); code != 404 {
		t.Fatalf("missing sa: %d", code)
	}
}

func TestAdminListOrgs(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	_, billing := l.operator(t, "billing@example.com", role.RealmBilling)
	_, boss := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, boss, "Acme")
	labs := l.sharedOrg(t, boss, "Acme Labs")
	beta := l.sharedOrg(t, boss, "beta")

	list := func(q string) []string {
		t.Helper()
		code, out := l.adminGetJSON(t, support, "/v1/admin/orgs?"+q)
		if code != 200 {
			t.Fatalf("orgs %s: %d %v", q, code, out)
		}
		return ids(t, out, "orgs")
	}
	if code, _ := l.adminGetJSON(t, billing, "/v1/admin/orgs"); code != 403 {
		t.Fatalf("billing lists orgs: %d", code)
	}
	if got := list("kind=shared"); !slices.Equal(got, sortedIDs(acme, labs, beta)) {
		t.Fatalf("shared = %v", got)
	}
	if got := list("kind=personal"); len(got) != 4 { // 運営者3人と boss
		t.Fatalf("personal = %v", got)
	}
	if got := list("name_prefix=Acme"); !slices.Equal(got, sortedIDs(acme, labs)) {
		t.Fatalf("prefix = %v", got)
	}
	if got := list("name_prefix=acme"); len(got) != 0 { // 大文字と小文字を区別する
		t.Fatalf("prefix lower = %v", got)
	}
	if code, out := l.admin(t, "/v1/admin/orgs/"+beta+"/suspensions", owner, map[string]any{"category": "billing", "reason": "unpaid"}); code != 201 {
		t.Fatalf("suspend org: %d %v", code, out)
	}
	if got := list("status=suspended"); !slices.Equal(got, []string{beta}) {
		t.Fatalf("suspended = %v", got)
	}
	if got := list("status=active&kind=shared"); !slices.Equal(got, sortedIDs(acme, labs)) {
		t.Fatalf("active = %v", got)
	}
	if got := list("parent_id=org_missing"); len(got) != 0 {
		t.Fatalf("missing parent = %v", got)
	}
	code, out := l.adminGetJSON(t, support, "/v1/admin/orgs?kind=shared&limit=2")
	next, _ := out["next_cursor"].(string)
	if code != 200 || len(out["orgs"].([]any)) != 2 || next == "" {
		t.Fatalf("page 1: %d %v", code, out)
	}
	if got := list("kind=shared&after=" + next); len(got) != 1 {
		t.Fatalf("page 2 = %v", got)
	}
	if code, _ := l.adminGetJSON(t, support, "/v1/admin/orgs?limit=500"); code != 400 {
		t.Fatalf("bad limit: %d", code)
	}
	if code, _ := l.adminGetJSON(t, support, "/v1/admin/orgs?status=archived"); code != 400 {
		t.Fatalf("bad status: %d", code)
	}
}

func TestAdminConnectionsAPI(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, security := l.operator(t, "security@example.com", role.RealmSecurity)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, billing := l.operator(t, "billing@example.com", role.RealmBilling)
	p := newFakeIdP(t, l, owner)
	if code, res, _ := p.login(t, l, "sub-1", "fia@example.com", true, ""); code != 200 {
		t.Fatalf("oauth login: %d %v", code, res)
	}
	fia := l.userID(t, "fia@example.com")

	if code, _ := l.adminGetJSON(t, billing, "/v1/admin/connections"); code != 403 {
		t.Fatalf("billing lists connections: %d", code)
	}
	w := l.do(t, l.a.AdminHandler(), "GET", "/v1/admin/connections", nil, "Authorization", "Bearer "+security)
	if w.Code != 200 || strings.Contains(w.Body.String(), "csecret") || strings.Contains(w.Body.String(), "client_secret") {
		t.Fatalf("list connections: %d %s", w.Code, w.Body)
	}
	var list struct {
		Connections []map[string]any `json:"connections"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Connections) != 1 || list.Connections[0]["slug"] != "fake" || list.Connections[0]["active_identities"] != float64(1) ||
		list.Connections[0]["client_id"] != "cid" {
		t.Fatalf("connections = %v", list.Connections)
	}
	cid := list.Connections[0]["id"].(string)
	if code, out := l.adminGetJSON(t, security, "/v1/admin/connections/"+cid); code != 200 || out["issuer"] != "https://fake.example" {
		t.Fatalf("get connection: %d %v", code, out)
	}
	if code, _ := l.adminGetJSON(t, security, "/v1/admin/connections/con_missing"); code != 404 {
		t.Fatalf("missing connection: %d", code)
	}

	// 外部 ID で引く。
	code, out := l.adminGetJSON(t, security, "/v1/admin/users?connection=fake&subject=sub-1")
	if code != 200 || !slices.Equal(ids(t, out, "users"), []string{fia}) {
		t.Fatalf("identity search: %d %v", code, out)
	}
	if code, out := l.adminGetJSON(t, security, "/v1/admin/users?connection=fake&subject=sub-2"); code != 200 || len(out["users"].([]any)) != 0 {
		t.Fatalf("unknown subject: %d %v", code, out)
	}

	// 変更は connections:manage（realm:owner）だけ。シークレットは監査ログにも出さない。
	upd := map[string]any{"client_id": "cid2", "client_secret": "new-very-secret", "redirect_uris": []string{"https://app.example/cb", "https://app.example/cb2"}}
	if code, _ := l.adminDo(t, "PUT", admin, "/v1/admin/connections/"+cid, upd); code != 403 {
		t.Fatalf("admin updates connection: %d", code)
	}
	code, out = l.adminDo(t, "PUT", owner, "/v1/admin/connections/"+cid, upd)
	if code != 200 || out["client_id"] != "cid2" || len(out["redirect_uris"].([]any)) != 2 || out["client_secret"] != nil {
		t.Fatalf("update connection: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/connections/"+cid, map[string]any{"client_id": "cid2", "redirect_uris": []string{"not a url"}}); code != 400 || out["error"] != "invalid_connection" {
		t.Fatalf("bad redirect: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/connections/"+cid, map[string]any{"client_id": "cid2", "client_secret": "", "redirect_uris": []string{"https://app.example/cb"}}); code != 400 || out["error"] != "invalid_connection" {
		t.Fatalf("empty secret: %d %v", code, out)
	}
	updated := l.auditOf(t, "connection.updated")
	if len(updated) != 1 {
		t.Fatalf("connection.updated = %+v", updated)
	}
	for _, e := range l.auditTypes(t) {
		if b, _ := json.Marshal(e); strings.Contains(string(b), "new-very-secret") {
			t.Fatalf("secret in audit: %s", b)
		}
	}

	// 使っている外部 ID があれば、既定では消さない。
	if code, out := l.admin(t, "/v1/admin/connections/"+cid+":delete", owner, nil); code != 409 || out["error"] != "connection_in_use" {
		t.Fatalf("delete in use: %d %v", code, out)
	}
	code, out = l.admin(t, "/v1/admin/connections/"+cid+":delete", owner, map[string]any{"revoke_identities": true})
	if code != 200 || out["identities_revoked"] != float64(1) {
		t.Fatalf("delete with revoke: %d %v", code, out)
	}
	if code, _ := l.adminGetJSON(t, security, "/v1/admin/connections/"+cid); code != 404 {
		t.Fatalf("deleted connection: %d", code)
	}
	if code, out := l.adminGetJSON(t, security, "/v1/admin/users/"+fia); code != 200 || len(out["credentials"].(map[string]any)["identities"].([]any)) != 0 {
		t.Fatalf("identity after delete: %d %v", code, out)
	}
	if n := len(l.auditOf(t, "connection.deleted")); n != 1 {
		t.Fatalf("connection.deleted = %d", n)
	}
}

func TestAdminSigningKeysList(t *testing.T) {
	l := newLoginEnvWith(t, nil, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, security := l.operator(t, "security@example.com", role.RealmSecurity)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	if code, _ := l.admin(t, "/v1/admin/signing-keys:rotate", owner, map[string]any{"alg": "ES256"}); code != 200 {
		t.Fatalf("rotate: %d", code)
	}
	if code, _ := l.adminGetJSON(t, support, "/v1/admin/signing-keys"); code != 403 {
		t.Fatalf("support lists keys: %d", code)
	}
	w := l.do(t, l.a.AdminHandler(), "GET", "/v1/admin/signing-keys", nil, "Authorization", "Bearer "+security)
	if w.Code != 200 || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "public") {
		t.Fatalf("list keys: %d %s", w.Code, w.Body)
	}
	states := func(bearer string) map[string]int {
		t.Helper()
		code, out := l.adminGetJSON(t, bearer, "/v1/admin/signing-keys")
		if code != 200 {
			t.Fatalf("list keys: %d %v", code, out)
		}
		m := map[string]int{}
		for _, k := range out["keys"].([]any) {
			k := k.(map[string]any)
			m[k["alg"].(string)+"/"+k["state"].(string)]++
			if (k["state"] == "active") != (k["published_until"] == nil) {
				t.Fatalf("published_until = %v", k)
			}
		}
		return m
	}
	if got := states(security); got["ES256/active"] != 1 || got["ES256/retired"] != 1 || got["ML-DSA-65/active"] != 1 {
		t.Fatalf("states = %v", got)
	}
	l.advance(l.e.cfg.OIDC.RetiredKeyTTL.D() + time.Second)
	_, security = l.operator(t, "security2@example.com", role.RealmSecurity)
	if got := states(security); got["ES256/expired"] != 1 || got["ES256/active"] != 1 {
		t.Fatalf("states after ttl = %v", got)
	}
}

func TestAdminUserEmails(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	ownerID, _ := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	_, _ = l.login(t, "ann@example.com")
	ann := l.userID(t, "ann@example.com")
	base := "/v1/admin/users/" + ann + "/emails"

	if code, _ := l.admin(t, base, support, map[string]any{"email": "ann2@example.com"}); code != 403 {
		t.Fatalf("support adds email: %d", code)
	}
	code, out := l.admin(t, base, admin, map[string]any{"email": "Ann2@Example.com"})
	if code != 201 || out["verified_via"] != "admin" || out["primary"] != false || out["verified"] != true || out["email"] != nil {
		t.Fatalf("add email: %d %v", code, out)
	}
	added := out["id"].(string)
	if code, out := l.admin(t, base, admin, map[string]any{"email": "ann2@example.com"}); code != 409 || out["error"] != "email_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	if code, out := l.admin(t, base, admin, map[string]any{"email": "not an email"}); code != 400 || out["error"] != "invalid_email" {
		t.Fatalf("invalid: %d %v", code, out)
	}
	// 上位のロールの運営者のメールは変えられない（なりすましと同じ判定）。
	if code, out := l.admin(t, "/v1/admin/users/"+ownerID+"/emails", admin, map[string]any{"email": "takeover@example.com"}); code != 403 {
		t.Fatalf("admin adds email to owner: %d %v", code, out)
	}
	if code, _ := l.admin(t, "/v1/admin/users/usr_missing/emails", admin, map[string]any{"email": "x@example.com"}); code != 404 {
		t.Fatalf("missing user: %d", code)
	}

	code, out = l.adminGetJSON(t, admin, "/v1/admin/users/"+ann)
	if code != 200 || len(out["emails"].([]any)) != 2 {
		t.Fatalf("emails: %d %v", code, out)
	}
	var original string
	for _, e := range out["emails"].([]any) {
		if e := e.(map[string]any); e["primary"] == true {
			original = e["id"].(string)
		}
	}
	// primary は消せない。primary を移してから消す。
	if code, out := l.admin(t, base+"/"+original+":remove", admin, nil); code != 409 || out["error"] != "primary_email" {
		t.Fatalf("remove primary: %d %v", code, out)
	}
	if code, out := l.admin(t, base+"/"+added+":make-primary", admin, nil); code != 204 {
		t.Fatalf("make primary: %d %v", code, out)
	}
	if code, out := l.admin(t, base+"/"+original+":remove", admin, nil); code != 204 {
		t.Fatalf("remove: %d %v", code, out)
	}
	if code, out := l.admin(t, base+"/"+added+":remove", admin, nil); code != 409 || out["error"] != "primary_email" {
		t.Fatalf("remove last: %d %v", code, out)
	}
	if code, _ := l.admin(t, base+"/eml_missing:make-primary", admin, nil); code != 404 {
		t.Fatalf("missing email: %d", code)
	}
	for _, typ := range []string{"email.added", "email.primary_changed", "email.removed"} {
		es := l.auditOf(t, typ)
		if len(es) != 1 || es[0].Details["user_id"] != ann || es[0].Actor.Type != "user" || es[0].Actor.ID == ann {
			t.Fatalf("audit %s = %+v", typ, es)
		}
	}

	// realm が admin の経路を受け入れなければ足せない。
	saved := l.a.accounts.VerifiedVia
	l.a.accounts.VerifiedVia = []port.VerifiedVia{port.VerifiedViaCode}
	t.Cleanup(func() { l.a.accounts.VerifiedVia = saved })
	if code, out := l.admin(t, base, admin, map[string]any{"email": "ann3@example.com"}); code != 400 || out["error"] != "verification_method_disabled" {
		t.Fatalf("admin via disabled: %d %v", code, out)
	}
}

func TestAdminReadStaysInRealm(t *testing.T) {
	l := multiRealmEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	acme, _ := l.newRealm(t, owner, map[string]any{"slug": "acme"})
	inAcme, _ := acme.login(t, "alice@example.com")
	alice := inAcme["user_id"].(string)
	_, _ = l.login(t, "alice@example.com")

	// 既定の realm の運営者からは、別の realm のユーザーは見えない。
	if code, _ := l.adminGetJSON(t, owner, "/v1/admin/users/"+alice); code != 404 {
		t.Fatalf("other realm user: %d", code)
	}
	code, out := l.adminGetJSON(t, owner, "/v1/admin/users?email="+url.QueryEscape("alice@example.com"))
	if code != 200 || len(out["users"].([]any)) != 1 || ids(t, out, "users")[0] == alice {
		t.Fatalf("email search across realms: %d %v", code, out)
	}
	if code, _ := l.adminGetJSON(t, owner, "/v1/admin/users/"+alice+"/sessions"); code != 404 {
		t.Fatalf("other realm sessions: %d", code)
	}
	if code, _ := l.admin(t, "/v1/admin/users/"+alice+"/sessions:revoke-all", owner, nil); code != 404 {
		t.Fatalf("other realm revoke-all: %d", code)
	}
	// 既定の realm のトークンは別の realm の管理 API で使えない。
	if w := acme.do(t, true, "GET", "/v1/admin/users", nil, "Authorization", "Bearer "+owner); w.Code != 401 {
		t.Fatalf("default token in acme admin: %d", w.Code)
	}
}
