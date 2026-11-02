package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/authn/method/ldap/ldaptest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// LDAP / Active Directory（ADR 0102）。ディレクトリは同じプロセスの偽物（127.0.0.1）。テストの構成は Dev なので、
// Org 専用の connection からも手元のアドレスに届く。

const (
	ldapSvcDN  = "cn=svc,dc=corp,dc=example"
	ldapSvcPW  = "svc-secret"
	ldapPeople = "ou=people,dc=corp,dc=example"
)

func newLDAPEnv(t *testing.T, extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "sso", "admin", "invitation"}
		c.Server.PublicURL = "https://iam.example"
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, extra...)
		c.Features = &names
	}, feature.Registered())
}

func newDirectory(t *testing.T) *ldaptest.Server {
	t.Helper()
	srv := ldaptest.New(t, ldaptest.LDAPS)
	srv.Add(ldapSvcDN, map[string][]string{"cn": {"svc"}, "userPassword": {ldapSvcPW}})
	return srv
}

func addPerson(srv *ldaptest.Server, uid, uuid, email, pw string) {
	srv.Add("uid="+uid+","+ldapPeople, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {uid}, "entryUUID": {uuid},
		"mail": {email}, "userPassword": {pw}})
}

func ldapBody(srv *ldaptest.Server) map[string]any {
	return map[string]any{"url": srv.URL, "ca_pem": srv.CAPEM, "bind_dn": ldapSvcDN, "bind_password": ldapSvcPW, "user_base_dn": ldapPeople}
}

func (l *loginEnv) ldapLogin(t *testing.T, conn, user, pw string) (int, map[string]any, string) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/ldap/"+conn+":login", map[string]string{"username": user, "password": pw})
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, sessionOf(w)
}

func TestLDAPDisabled(t *testing.T) {
	l := newLDAPEnv(t, feature.OrgManagedUsers)
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	srv := newDirectory(t)
	body := ldapBody(srv)
	body["slug"] = "corp"
	if code, out := l.admin(t, "/v1/admin/connections:ldap", owner, body); code != 404 || out["error"] != "ldap_disabled" {
		t.Fatalf("admin create: %d %v", code, out)
	}
	if code, _, _ := l.ldapLogin(t, "corp", "alice", "pw"); code != 404 {
		t.Fatalf("login: %d", code)
	}
	if code, out := l.admin(t, "/v1/admin/connections/x:sync", owner, nil); code != 404 || out["error"] != "ldap_disabled" {
		t.Fatalf("sync: %d %v", code, out)
	}
	_, me := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, me, "Acme")
	if code, _ := l.mePost(t, me, "/v1/me/orgs/"+acme+"/connections:ldap", body); code != 404 {
		t.Fatalf("org add: %d", code)
	}
}

func TestLDAPRealmConnection(t *testing.T) {
	l := newLDAPEnv(t, feature.LDAP)
	_, owner := l.operator(t, "owner@example.com", role.RealmOwner)
	srv := newDirectory(t)
	addPerson(srv, "alice", "11111111-1111-1111-1111-111111111111", "alice@corp.example", "alice-pw")

	body := ldapBody(srv)
	body["slug"], body["trust_email"] = "corp", true
	code, out := l.admin(t, "/v1/admin/connections:ldap", owner, body)
	if code != 201 || out["type"] != "ldap" {
		t.Fatalf("create: %d %v", code, out)
	}
	connID := out["id"].(string)
	info := out["ldap"].(map[string]any)
	if info["url"] != srv.URL || info["ca_configured"] != true || info["login_attribute"] != "uid" || info["id_attribute"] != "entryUUID" {
		t.Fatalf("info: %v", info)
	}
	// 秘密は返さない。
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), ldapSvcPW) || strings.Contains(string(raw), "bind_password") {
		t.Fatalf("bind password leaked: %s", raw)
	}
	if code, out := l.admin(t, "/v1/admin/connections:ldap", owner, body); code != 409 || out["error"] != "slug_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	// 平文の接続、壊れた絞り込みは 400。
	bad := ldapBody(srv)
	bad["slug"], bad["url"] = "plain", "http://127.0.0.1:389"
	if code, out := l.admin(t, "/v1/admin/connections:ldap", owner, bad); code != 400 || out["error"] != "invalid_connection" {
		t.Fatalf("bad url: %d %v", code, out)
	}
	bad["url"], bad["user_filter"] = srv.URL, "(objectClass=person"
	if code, _ := l.admin(t, "/v1/admin/connections:ldap", owner, bad); code != 400 {
		t.Fatalf("bad filter: %d", code)
	}

	// ホスト型の画面の一覧には出さない（パスワードを受ける画面は無い）。
	if w := l.do(t, l.a.PublicHandler(), "GET", "/login", nil); strings.Contains(w.Body.String(), `data-connection="corp"`) {
		t.Fatalf("ldap on hosted login: %s", w.Body)
	}

	// 登録とログイン。
	code, res, alice := l.ldapLogin(t, "corp", "alice", "alice-pw")
	if code != 200 || alice == "" || res["created"] != true {
		t.Fatalf("signup: %d %v", code, res)
	}
	if code, res, _ := l.ldapLogin(t, "corp", "alice", "alice-pw"); code != 200 || res["created"] == true {
		t.Fatalf("login: %d %v", code, res)
	}
	if code, out, _ := l.ldapLogin(t, "corp", "alice", "wrong"); code != 401 || out["error"] != "authentication_failed" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	if code, _, _ := l.ldapLogin(t, "corp", "alice", ""); code != 401 {
		t.Fatalf("empty password: %d", code)
	}
	if code, _, _ := l.ldapLogin(t, "corp", "*", "alice-pw"); code != 401 {
		t.Fatalf("wildcard: %d", code)
	}
	if code, _, _ := l.ldapLogin(t, "nope", "alice", "alice-pw"); code != 404 {
		t.Fatalf("unknown connection: %d", code)
	}

	// サービスアカウントのパスワードを変えると届かなくなり（503）、直すと戻る。
	if code, out := l.admin(t, "/v1/admin/connections/"+connID+":update-ldap", owner, map[string]any{"bind_password": "wrong"}); code != 200 {
		t.Fatalf("update: %d %v", code, out)
	}
	if code, out, _ := l.ldapLogin(t, "corp", "alice", "alice-pw"); code != 503 || out["error"] != "directory_unavailable" {
		t.Fatalf("broken service account: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/connections/"+connID+":sync", owner, nil); code != 503 {
		t.Fatalf("sync broken: %d %v", code, out)
	}
	if code, _ := l.admin(t, "/v1/admin/connections/"+connID+":update-ldap", owner, map[string]any{"bind_password": ldapSvcPW,
		"sync": map[string]any{"enabled": true, "provision": true}}); code != 200 {
		t.Fatalf("update back: %d", code)
	}

	// 同期：新しい人を作り、消えた人を止める。
	addPerson(srv, "bob", "22222222-2222-2222-2222-222222222222", "bob@corp.example", "bob-pw")
	code, out = l.admin(t, "/v1/admin/connections/"+connID+":sync", owner, nil)
	if code != 200 || out["entries"] != 2.0 || out["provisioned"] != 1.0 || out["complete"] != true {
		t.Fatalf("sync: %d %v", code, out)
	}
	srv.Remove("uid=alice," + ldapPeople)
	code, out = l.admin(t, "/v1/admin/connections/"+connID+":sync", owner, nil)
	if code != 200 || out["suspended"] != 1.0 {
		t.Fatalf("sync missing: %d %v", code, out)
	}
	if l.sessionAlive(t, alice) {
		t.Fatal("session of a suspended user is alive")
	}
	if len(l.auditOf(t, "ldap.sync.completed")) == 0 {
		t.Fatal("no sync audit event")
	}
	// LDAP 以外の connection には同期は無い。
	if code, _ := l.admin(t, "/v1/admin/connections/missing:sync", owner, nil); code != 404 {
		t.Fatalf("sync unknown: %d", code)
	}
}

func TestLDAPOrgConnection(t *testing.T) {
	l := newLDAPEnv(t, feature.OrgManagedUsers, feature.LDAP)
	dns := &fakeDNS{txt: map[string][]string{}}
	l.a.orgs.Resolver = dns
	srv := newDirectory(t)
	addPerson(srv, "sam", "33333333-3333-3333-3333-333333333333", "sam@acme.example", "sam-pw")
	addPerson(srv, "eve", "44444444-4444-4444-4444-444444444444", "eve@other.example", "eve-pw")

	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	base := "/v1/me/orgs/" + acme + "/connections"

	body := ldapBody(srv)
	code, out := l.mePost(t, owner, base+":ldap", body)
	if code != 201 || out["type"] != "ldap" || out["ldap"].(map[string]any)["url"] != srv.URL ||
		out["ldap"].(map[string]any)["sync"].(map[string]any)["interval_seconds"] != 3600.0 {
		t.Fatalf("add: %d %v", code, out)
	}
	conn := out["id"].(string)

	w := l.do(t, l.a.PublicHandler(), "POST", "/v1/login/sso:discover", map[string]string{"email": "x@acme.example"})
	var disc struct {
		Entries []struct{ Connection, Type string } `json:"entries"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &disc)
	if len(disc.Entries) != 1 || disc.Entries[0].Connection != conn || disc.Entries[0].Type != "ldap" {
		t.Fatalf("discover: %s", w.Body)
	}

	code, _, sam := l.ldapLogin(t, conn, "sam", "sam-pw")
	if code != 200 {
		t.Fatalf("signup: %d", code)
	}
	if e := l.myOrgEntry(t, sam, acme); e["managed"] != true || e["active"] != true {
		t.Fatalf("not managed: %v", e)
	}
	if code, out, _ := l.ldapLogin(t, conn, "eve", "eve-pw"); code != 400 || out["error"] != "email_domain_not_verified" {
		t.Fatalf("outside domain: %d %v", code, out)
	}
	// 個人ユーザーは連携できない。
	if code, out := l.mePost(t, owner, "/v1/me/identities/ldap/"+conn+":link", map[string]string{"username": "sam", "password": "sam-pw"}); code != 409 ||
		out["error"] != "not_managed_by_org" {
		t.Fatalf("link by personal user: %d %v", code, out)
	}

	if code, out := l.mePost(t, owner, base+"/"+conn+":delete", nil); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _, _ := l.ldapLogin(t, conn, "sam", "sam-pw"); code != 404 {
		t.Fatalf("login after delete: %d", code)
	}
}
