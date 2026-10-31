package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
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

func newDomainEnv(t *testing.T, on bool, extra ...string) (*loginEnv, *fakeDNS) {
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
		names = append(names, extra...)
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

// 証明済みのドメインは定期的に確かめ直し、TXT が猶予の間ずっと無ければ証明を外す（ADR 0085）。
func TestOrgDomainRecheck(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	rc := l.a.domainRecheck
	if rc == nil {
		t.Fatal("rechecker is off")
	}
	every, grace := l.e.cfg.OrgDomains.Recheck.D(), l.e.cfg.OrgDomains.Grace.D()
	sweep := func(want org.Rechecked) {
		t.Helper()
		if n, err := rc.Sweep(context.Background()); err != nil || n != want {
			t.Fatalf("sweep = %+v, %v; want %+v", n, err, want)
		}
	}
	verified := func() bool {
		t.Helper()
		err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
			_, err := tx.OrgDomains().GetVerified(ctx, l.a.realm.ID, "acme.example")
			return err
		})
		if err != nil && !errors.Is(err, errs.NotFound) {
			t.Fatal(err)
		}
		return err == nil
	}

	// 間隔の前は確かめない。TXT があれば証明のまま。
	sweep(org.Rechecked{})
	l.advance(every)
	sweep(org.Rechecked{Checked: 1})
	sweep(org.Rechecked{})

	// TXT が無くなっても、猶予の間は証明のまま。DNS の障害は猶予に数えない。
	dns.mu.Lock()
	delete(dns.txt, "_iam-challenge.acme.example")
	dns.mu.Unlock()
	l.advance(every)
	sweep(org.Rechecked{Checked: 1})
	dns.fail = true
	l.advance(every)
	sweep(org.Rechecked{Failed: 1})
	dns.fail = false
	if !verified() {
		t.Fatal("unverified within grace")
	}
	// 猶予を過ぎても無ければ証明を外す。外れたドメインは確かめ直さない。
	l.advance(grace)
	sweep(org.Rechecked{Checked: 1, Unverified: 1})
	if verified() {
		t.Fatal("still verified after grace")
	}
	l.advance(every)
	sweep(org.Rechecked{})

	var types []string
	for _, e := range l.auditTypes(t) {
		if e.OrgID == acme && strings.HasPrefix(e.Type, "org.domain.") {
			types = append(types, e.Type)
		}
	}
	if want := []string{"org.domain.added", "org.domain.verified", "org.domain.missing", "org.domain.unverified"}; !slices.Equal(types, want) {
		t.Fatalf("audit = %v; want %v", types, want)
	}
}

// TXT が無くなった後に猶予より長く DNS が障害でも、障害の間は猶予に数えない。
func TestOrgDomainRecheckOutage(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	rc, every, grace := l.a.domainRecheck, l.e.cfg.OrgDomains.Recheck.D(), l.e.cfg.OrgDomains.Grace.D()
	sweep := func(want org.Rechecked) {
		t.Helper()
		if n, err := rc.Sweep(context.Background()); err != nil || n != want {
			t.Fatalf("sweep = %+v, %v; want %+v", n, err, want)
		}
	}
	dns.mu.Lock()
	delete(dns.txt, "_iam-challenge.acme.example")
	dns.mu.Unlock()
	l.advance(every)
	sweep(org.Rechecked{Checked: 1})
	dns.fail = true
	l.advance(grace + every)
	sweep(org.Rechecked{Failed: 1})
	dns.fail = false
	l.advance(every)
	sweep(org.Rechecked{Checked: 1})
	l.advance(grace - every)
	sweep(org.Rechecked{Checked: 1, Unverified: 1})
}

// TXT が戻れば猶予は消え、また見つからなくなったときに猶予を数え直す。
func TestOrgDomainRecheckRecovers(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	rc, every, grace := l.a.domainRecheck, l.e.cfg.OrgDomains.Recheck.D(), l.e.cfg.OrgDomains.Grace.D()
	value := dns.txt["_iam-challenge.acme.example"]
	for range 2 {
		dns.mu.Lock()
		delete(dns.txt, "_iam-challenge.acme.example")
		dns.mu.Unlock()
		l.advance(every)
		if n, err := rc.Sweep(context.Background()); err != nil || n.Unverified != 0 {
			t.Fatalf("missing: %+v, %v", n, err)
		}
		l.advance(grace - time.Minute)
		dns.set("_iam-challenge.acme.example", value...)
		if n, err := rc.Sweep(context.Background()); err != nil || n != (org.Rechecked{Checked: 1}) {
			t.Fatalf("back: %+v, %v", n, err)
		}
	}
	// owner が置き直して確かめれば、次の確かめ直しを待たずに猶予が消える。
	dns.mu.Lock()
	delete(dns.txt, "_iam-challenge.acme.example")
	dns.mu.Unlock()
	l.advance(every)
	if n, err := rc.Sweep(context.Background()); err != nil || n != (org.Rechecked{Checked: 1}) {
		t.Fatalf("missing again: %+v, %v", n, err)
	}
	l.advance(grace - time.Hour)
	dns.set("_iam-challenge.acme.example", value...)
	_, owner = l.login(t, "boss@acme.example")
	code, out := l.meDo(t, "GET", owner, "/v1/me/orgs/"+acme+"/domains", nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	dom := out["domains"].([]any)[0].(map[string]any)["id"].(string)
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/domains/"+dom+":verify", nil); code != 200 || out["status"] != "verified" {
		t.Fatalf("verify again: %d %v", code, out)
	}
	dns.mu.Lock()
	delete(dns.txt, "_iam-challenge.acme.example")
	dns.mu.Unlock()
	l.advance(2 * time.Hour)
	if n, err := rc.Sweep(context.Background()); err != nil || n != (org.Rechecked{}) {
		t.Fatalf("checked again too soon: %+v, %v", n, err)
	}
	l.advance(every)
	// 猶予は数え直しなので、まだ外れない。
	if n, err := rc.Sweep(context.Background()); err != nil || n != (org.Rechecked{Checked: 1}) {
		t.Fatalf("after reverify: %+v, %v", n, err)
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
	// 受け入れには直近の本人確認が要る。
	l.advance(l.e.cfg.Security.Session.MaxAuthAge.Default.D() + time.Minute)
	if code, out := l.mePost(t, pat, "/v1/me/orgs/"+acme+":accept-management", nil); code != 401 || out["error"] != "reauthentication_required" {
		t.Fatalf("accept without recent auth: %d %v", code, out)
	}
	_, pat = l.login(t, "pat@acme.example")
	_, owner = l.login(t, "boss@acme.example")
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

func TestManagedUsersPowers(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")

	// 管理ユーザーとして招けるのは、証明済みドメインのアドレスだけ。
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/invitations", map[string]any{"email": "x@other.example", "role": "member", "managed": true}); code != 409 || out["error"] != "email_domain_not_verified" {
		t.Fatalf("managed invite outside domain: %d %v", code, out)
	}
	// 新しく登録した人は、受け入れでそのまま管理ユーザーになる。
	code, out := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/invitations", map[string]any{"email": "new@acme.example", "role": "member", "managed": true})
	if code != 201 || out["managed"] != true {
		t.Fatalf("managed invite: %d %v", code, out)
	}
	_, token := l.claimToken(t)
	if code, out := l.accept(t, "", token); code != 200 {
		t.Fatalf("accept as new user: %d %v", code, out)
	}
	_, newbie := l.login(t, "new@acme.example")
	if e := l.myOrgEntry(t, newbie, acme); e["managed"] != true {
		t.Fatalf("new user not managed: %v", e)
	}
	// 既存のユーザーには、管理を求める（本人の同意を待つ）。
	_, old := l.login(t, "old@acme.example")
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/invitations", map[string]any{"email": "old@acme.example", "role": "member", "managed": true}); code != 201 {
		t.Fatalf("managed invite existing: %d %v", code, out)
	}
	_, token = l.claimToken(t)
	if code, out := l.accept(t, old, token); code != 200 {
		t.Fatalf("accept as existing user: %d %v", code, out)
	}
	if e := l.myOrgEntry(t, old, acme); e["managed"] != nil || e["management_requested"] != true {
		t.Fatalf("existing user after managed invite: %v", e)
	}

	// 管理する Org のメンバーを停止すると、ログインそのものができない。
	newbieMember := l.myOrgEntry(t, newbie, acme)["membership_id"].(string)
	member := func(id string) string { return "/v1/me/orgs/" + acme + "/members/" + id }
	if code, out := l.mePost(t, owner, member(newbieMember)+"/suspensions", map[string]string{"reason": "left the company"}); code != 201 {
		t.Fatalf("suspend membership: %d %v", code, out)
	}
	if w := l.loginVerify(t, "new@acme.example"); w.Code != 403 {
		t.Fatalf("managed user logged in while suspended: %d %s", w.Code, w.Body.String())
	}
	// 管理していないユーザーは、停止された Org の外（個人 Org）でログインできる。
	oldMember := l.myOrgEntry(t, old, acme)["membership_id"].(string)
	if code, out := l.mePost(t, owner, member(oldMember)+"/suspensions", map[string]string{"reason": "left the company"}); code != 201 {
		t.Fatalf("suspend old: %d %v", code, out)
	}
	if w := l.loginVerify(t, "old@acme.example"); w.Code != 200 {
		t.Fatalf("personal user login: %d %s", w.Code, w.Body.String())
	}

	// Org の owner は管理ユーザーのアカウントを消せる。管理していない人は消せない。
	if code, out := l.mePost(t, owner, member(oldMember)+":delete-account", nil); code != 409 || out["error"] != "not_managed" {
		t.Fatalf("delete unmanaged: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, member(newbieMember)+":delete-account", nil); code != 200 {
		t.Fatalf("delete managed: %d %v", code, out)
	}
	if code, out := l.meDo(t, "GET", newbie, "/v1/me/orgs", nil); code != 401 {
		t.Fatalf("session of deleted managed user: %d %v", code, out)
	}
}

// passkey 必須の Org の管理ユーザーで passkey が無い人は、ログインできないのではなく passkey の登録だけができるセッションになる。
func TestManagedUserPasskeyEnrollment(t *testing.T) {
	l, dns := newDomainEnv(t, true, feature.OrgLoginPolicy)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.verifiedDomain(t, dns, owner, acme, "acme.example")
	if code, out := l.putSettings(t, owner, acme, map[string]any{"login_policy": map[string]any{"require_passkey": true}}); code != 200 {
		t.Fatalf("put passkey: %d %v", code, out)
	}
	if code, out := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/invitations", map[string]any{"email": "new@acme.example", "role": "member", "managed": true}); code != 201 {
		t.Fatalf("managed invite: %d %v", code, out)
	}
	// 招待からの登録（メールのコード）は、参加を済ませて登録だけのセッションになる。
	_, token := l.claimToken(t)
	code, out := l.accept(t, "", token)
	if code != 200 {
		t.Fatalf("accept as new user: %d %v", code, out)
	}
	if login, _ := out["login"].(map[string]any); login == nil || login["next"] != "enroll" {
		t.Fatalf("accept login: %v", out)
	}
	// メールのコードでのログインも、登録だけのセッションになる。
	w := l.loginVerify(t, "new@acme.example")
	var res map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res["next"] != "enroll" {
		t.Fatalf("managed login without passkey: %d %s", w.Code, w.Body.String())
	}
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c.Value
		}
	}
	if code, out := l.meDo(t, "GET", cookie, "/v1/me/orgs", nil); code != 401 {
		t.Fatalf("enroll session used the api: %d %v", code, out)
	}
	if code, out := l.meDo(t, "GET", cookie, "/v1/me/methods", nil); code != 200 {
		t.Fatalf("enroll session methods: %d %v", code, out)
	}
}

// 運営者は管理 API（orgs:update）で扱え、Org を消すとドメインも消える。
func TestOrgDomainsAdminAPI(t *testing.T) {
	l, dns := newDomainEnv(t, true)
	_, root := l.operator(t, "root@example.com", role.RealmOwner)
	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	base := "/v1/admin/orgs/" + acme + "/domains"

	if code, out := l.adminDo(t, "GET", support, base, nil); code != 403 {
		t.Fatalf("list as support: %d %v", code, out)
	}
	code, out := l.admin(t, base, root, map[string]string{"domain": "acme.example"})
	if code != 201 || out["status"] != "pending" {
		t.Fatalf("add: %d %v", code, out)
	}
	dom, value := out["id"].(string), out["txt_value"].(string)
	if code, out := l.admin(t, base, root, map[string]string{"domain": "acme.example"}); code != 409 || out["error"] != "domain_exists" {
		t.Fatalf("add again: %d %v", code, out)
	}
	if code, out := l.admin(t, base+"/"+dom+":verify", root, nil); code != 409 || out["error"] != "domain_not_verified" {
		t.Fatalf("verify without TXT: %d %v", code, out)
	}
	dns.fail = true
	if code, out := l.admin(t, base+"/"+dom+":verify", root, nil); code != 503 || out["error"] != "dns_unavailable" {
		t.Fatalf("verify with DNS failure: %d %v", code, out)
	}
	dns.fail = false
	dns.set("_iam-challenge.acme.example", value)
	if code, out := l.admin(t, base+"/"+dom+":verify", root, nil); code != 200 || out["status"] != "verified" {
		t.Fatalf("verify: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", root, base, nil); code != 200 || len(out["domains"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	// owner の公開 API からも同じものが見える。
	if code, out := l.meDo(t, "GET", owner, "/v1/me/orgs/"+acme+"/domains", nil); code != 200 ||
		out["domains"].([]any)[0].(map[string]any)["status"] != "verified" {
		t.Fatalf("list as owner: %d %v", code, out)
	}

	// Org を消すと証明済みのドメインも消え、別の Org が登録できる。
	if code, out := l.admin(t, "/v1/admin/orgs/"+acme+":delete", root, map[string]any{"immediate": true}); code != 200 {
		t.Fatalf("delete org: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", root, base, nil); code != 404 {
		t.Fatalf("list of a deleted org: %d %v", code, out)
	}
	_, other := l.login(t, "eve@evil.example")
	evil := l.sharedOrg(t, other, "Evil")
	if code, out := l.admin(t, "/v1/admin/orgs/"+evil+"/domains", root, map[string]string{"domain": "acme.example"}); code != 201 {
		t.Fatalf("add after the owner org is deleted: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/orgs/"+evil+"/domains/"+dom+":delete", root, nil); code != 404 {
		t.Fatalf("delete another org's domain: %d %v", code, out)
	}
}

func TestOrgDomainsAdminFeatureOff(t *testing.T) {
	l, _ := newDomainEnv(t, false)
	_, root := l.operator(t, "root@example.com", role.RealmOwner)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	if code, out := l.adminDo(t, "GET", root, "/v1/admin/orgs/"+acme+"/domains", nil); code != 404 || out["error"] != "org_managed_users_disabled" {
		t.Fatalf("admin domains without feature: %d %v", code, out)
	}
}
