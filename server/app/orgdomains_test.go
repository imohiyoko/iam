package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
)

// Org のドメインの所有証明（design.md 11.3、ADR 0075）を HTTP で確かめる。

type fakeDNS struct {
	mu   sync.Mutex
	txt  map[string][]string
	fail bool
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("servfail")
	}
	v, ok := f.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, nil
}

func (f *fakeDNS) set(name string, v ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[name] = v
}

func newDomainEnv(t *testing.T, on bool) (*loginEnv, *fakeDNS) {
	t.Helper()
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Realm.VerifiedVia = []string{"code", "oauth_provider", "admin", "invitation"}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.OrgManagedUsers)
		}
		c.Features = &names
	}, feature.Registered())
	dns := &fakeDNS{txt: map[string][]string{}}
	if l.a.orgs != nil {
		l.a.orgs.Resolver = dns
	}
	return l, dns
}

func TestOrgDomainsFeatureOff(t *testing.T) {
	l, _ := newDomainEnv(t, false)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	if code, out := l.meDo(t, "GET", owner, "/v1/me/orgs/"+acme+"/domains", nil); code != 404 {
		t.Fatalf("domains without feature: %d %v", code, out)
	}
}

func TestOrgDomainsAPI(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	base := "/v1/me/orgs/" + acme + "/domains"

	code, out := l.mePost(t, owner, base, map[string]string{"domain": " Acme.Example. "})
	if code != 201 || out["domain"] != "acme.example" || out["status"] != "pending" || out["txt_name"] != "_iam-challenge.acme.example" {
		t.Fatalf("add: %d %v", code, out)
	}
	dom, value := out["id"].(string), out["txt_value"].(string)
	if code, out := l.mePost(t, owner, base, map[string]string{"domain": "acme.example"}); code != 409 || out["error"] != "domain_exists" {
		t.Fatalf("add again: %d %v", code, out)
	}
	for _, bad := range []string{"localhost", "-a.example", "a..example", "192.168.0.1", "例え.jp"} {
		if code, out := l.mePost(t, owner, base, map[string]string{"domain": bad}); code != 400 || out["error"] != "invalid_domain" {
			t.Fatalf("add %q: %d %v", bad, code, out)
		}
	}

	// TXT が無ければ 409。確かめた時刻は残る。
	if code, out := l.mePost(t, owner, base+"/"+dom+":verify", nil); code != 409 || out["error"] != "domain_not_verified" {
		t.Fatalf("verify without TXT: %d %v", code, out)
	}
	if code, out := l.meDo(t, "GET", owner, base, nil); code != 200 || out["domains"].([]any)[0].(map[string]any)["checked_at"] == nil {
		t.Fatalf("list after failed verify: %d %v", code, out)
	}
	dns.fail = true
	if code, out := l.mePost(t, owner, base+"/"+dom+":verify", nil); code != 503 || out["error"] != "dns_unavailable" {
		t.Fatalf("verify with DNS failure: %d %v", code, out)
	}
	dns.fail = false
	dns.set("_iam-challenge.acme.example", "v=spf1 -all", value)
	if code, out := l.mePost(t, owner, base+"/"+dom+":verify", nil); code != 200 || out["status"] != "verified" || out["verified_at"] == nil {
		t.Fatalf("verify: %d %v", code, out)
	}

	// 別の Org は、証明済みのドメインを登録できない。
	_, other := l.login(t, "eve@evil.example")
	evil := l.sharedOrg(t, other, "Evil")
	if code, out := l.mePost(t, other, "/v1/me/orgs/"+evil+"/domains", map[string]string{"domain": "acme.example"}); code != 409 || out["error"] != "domain_taken" {
		t.Fatalf("add taken: %d %v", code, out)
	}
	// 他の Org のドメインは見えない。
	if code, out := l.mePost(t, other, "/v1/me/orgs/"+evil+"/domains/"+dom+":verify", nil); code != 404 {
		t.Fatalf("verify another org's domain: %d %v", code, out)
	}

	// メンバー（owner でない）は扱えない。
	_, pat := l.login(t, "pat@acme.example")
	if code, body := l.invite(t, owner, acme, "pat@acme.example", "admin"); code != 201 {
		t.Fatalf("invite: %d %v", code, body)
	}
	_, token := l.claimToken(t)
	if code, body := l.accept(t, pat, token); code != 200 {
		t.Fatalf("accept: %d %v", code, body)
	}
	if code, out := l.meDo(t, "GET", pat, base, nil); code != 403 {
		t.Fatalf("list as admin: %d %v", code, out)
	}

	// 消すと、別の Org が登録して証明できる。
	if code, out := l.mePost(t, owner, base+"/"+dom+":delete", nil); code != 204 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, base+"/"+dom+":delete", nil); code != 404 {
		t.Fatalf("delete again: %d %v", code, out)
	}
	code, out = l.mePost(t, other, "/v1/me/orgs/"+evil+"/domains", map[string]string{"domain": "acme.example"})
	if code != 201 {
		t.Fatalf("add after delete: %d %v", code, out)
	}
	dns.set("_iam-challenge.acme.example", out["txt_value"].(string))
	if code, out := l.mePost(t, other, "/v1/me/orgs/"+evil+"/domains/"+out["id"].(string)+":verify", nil); code != 200 {
		t.Fatalf("verify by other: %d %v", code, out)
	}

	var types []string
	for _, e := range l.auditTypes(t) {
		if e.OrgID == acme {
			types = append(types, e.Type)
		}
	}
	want := map[string]bool{"org.domain.added": false, "org.domain.verified": false, "org.domain.removed": false}
	for _, ty := range types {
		if _, ok := want[ty]; ok {
			want[ty] = true
		}
	}
	for ty, seen := range want {
		if !seen {
			t.Errorf("audit %s missing: %v", ty, types)
		}
	}
}

// verifiedDomain は Org に domain を登録して証明する。
func (l *loginEnv) verifiedDomain(t *testing.T, dns *fakeDNS, cookie, orgID, domain string) {
	t.Helper()
	base := "/v1/me/orgs/" + orgID + "/domains"
	code, out := l.mePost(t, cookie, base, map[string]string{"domain": domain})
	if code != 201 {
		t.Fatalf("add domain: %d %v", code, out)
	}
	dns.set(out["txt_name"].(string), out["txt_value"].(string))
	if code, out := l.mePost(t, cookie, base+"/"+out["id"].(string)+":verify", nil); code != 200 {
		t.Fatalf("verify domain: %d %v", code, out)
	}
}

// myOrgEntry は本人の Org の一覧から orgID の行を返す。
func (l *loginEnv) myOrgEntry(t *testing.T, cookie, orgID string) map[string]any {
	t.Helper()
	code, out := l.meDo(t, "GET", cookie, "/v1/me/orgs", nil)
	if code != 200 {
		t.Fatalf("my orgs: %d %v", code, out)
	}
	for _, o := range out["orgs"].([]any) {
		if m := o.(map[string]any); m["id"] == orgID {
			return m
		}
	}
	t.Fatalf("org %s not in %v", orgID, out)
	return nil
}

// joinOrg は email を Org に招待し、受け入れさせる。
func (l *loginEnv) joinOrg(t *testing.T, owner, orgID, email string) string {
	t.Helper()
	_, cookie := l.login(t, email)
	if code, body := l.invite(t, owner, orgID, email, "member"); code != 201 {
		t.Fatalf("invite %s: %d %v", email, code, body)
	}
	_, token := l.claimToken(t)
	if code, body := l.accept(t, cookie, token); code != 200 {
		t.Fatalf("accept %s: %d %v", email, code, body)
	}
	return cookie
}

func TestManagedUsers(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	pat := l.joinOrg(t, owner, acme, "pat@acme.example")
	sam := l.joinOrg(t, owner, acme, "sam@other.example")
	patMember := l.myOrgEntry(t, pat, acme)["membership_id"].(string)
	samMember := l.myOrgEntry(t, sam, acme)["membership_id"].(string)
	member := func(id string) string { return "/v1/me/orgs/" + acme + "/members/" + id }

	if code, out := l.mePost(t, sam, "/v1/me/orgs/"+acme+":accept-management", nil); code != 409 || out["error"] != "no_management_request" {
		t.Fatalf("accept without request: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, member(samMember)+":request-management", nil); code != 409 || out["error"] != "email_domain_not_verified" {
		t.Fatalf("request for unverified domain: %d %v", code, out)
	}
	if code, out := l.mePost(t, sam, member(patMember)+":request-management", nil); code != 403 {
		t.Fatalf("request by member: %d %v", code, out)
	}

	// 求めて、断られる。
	if code, out := l.mePost(t, owner, member(patMember)+":request-management", nil); code != 204 {
		t.Fatalf("request: %d %v", code, out)
	}
	if e := l.myOrgEntry(t, pat, acme); e["management_requested"] != true || e["managed"] != nil {
		t.Fatalf("my org after request: %v", e)
	}
	if code, out := l.mePost(t, pat, "/v1/me/orgs/"+acme+":decline-management", nil); code != 204 {
		t.Fatalf("decline: %d %v", code, out)
	}
	if e := l.myOrgEntry(t, pat, acme); e["management_requested"] != nil {
		t.Fatalf("my org after decline: %v", e)
	}

	// 求めて、受け入れられる。
	if code, out := l.mePost(t, owner, member(patMember)+":request-management", nil); code != 204 {
		t.Fatalf("request again: %d %v", code, out)
	}
	if code, out := l.mePost(t, pat, "/v1/me/orgs/"+acme+":accept-management", nil); code != 204 {
		t.Fatalf("accept: %d %v", code, out)
	}
	if e := l.myOrgEntry(t, pat, acme); e["managed"] != true || e["management_requested"] != nil {
		t.Fatalf("my org after accept: %v", e)
	}
	code, out := l.meDo(t, "GET", owner, "/v1/me/orgs/"+acme+"/members", nil)
	managed := 0
	for _, m := range out["members"].([]any) {
		if m.(map[string]any)["managed"] == true {
			managed++
		}
	}
	if code != 200 || managed != 1 {
		t.Fatalf("members: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, member(patMember)+":request-management", nil); code != 409 || out["error"] != "already_managed" {
		t.Fatalf("request for managed: %d %v", code, out)
	}

	// 管理ユーザーは抜けられず、自分でアカウントを消せない。
	if code, out := l.mePost(t, pat, "/v1/me/orgs/"+acme+":leave", nil); code != 409 || out["error"] != "managed_user" {
		t.Fatalf("leave as managed: %d %v", code, out)
	}
	if code, out := l.mePost(t, pat, "/v1/me/account:delete", nil); code != 409 || out["error"] != "managed_user" {
		t.Fatalf("delete account as managed: %d %v", code, out)
	}

	// Org が手放すと個人ユーザーに戻り、抜けられる。
	if code, out := l.mePost(t, owner, member(patMember)+":release-management", nil); code != 204 {
		t.Fatalf("release: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, member(patMember)+":release-management", nil); code != 409 || out["error"] != "not_managed" {
		t.Fatalf("release again: %d %v", code, out)
	}
	if e := l.myOrgEntry(t, pat, acme); e["managed"] != nil {
		t.Fatalf("my org after release: %v", e)
	}

	// 除名でも個人ユーザーに戻る。
	if code, out := l.mePost(t, owner, member(patMember)+":request-management", nil); code != 204 {
		t.Fatalf("request third: %d %v", code, out)
	}
	if code, out := l.mePost(t, pat, "/v1/me/orgs/"+acme+":accept-management", nil); code != 204 {
		t.Fatalf("accept again: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, member(patMember)+":remove", nil); code != 204 {
		t.Fatalf("remove: %d %v", code, out)
	}
	if code, out := l.mePost(t, pat, "/v1/me/account:delete", nil); code != 200 {
		t.Fatalf("delete account after removal: %d %v", code, out)
	}

	seen := map[string]bool{}
	for _, e := range l.auditTypes(t) {
		if e.OrgID == acme {
			seen[e.Type] = true
		}
	}
	for _, ty := range []string{"org.management.requested", "org.management.declined", "user.managed", "user.management_released"} {
		if !seen[ty] {
			t.Errorf("audit %s missing", ty)
		}
	}
}
