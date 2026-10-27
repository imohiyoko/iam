package app

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
)

// Org と Membership の停止と有効期間（design.md 4.7、4.8、ADR 0058）を HTTP で確かめる。

func unavailableOf(got myOrgs, orgID string) []string {
	for _, o := range got.Orgs {
		if o.ID == orgID {
			return o.Unavailable
		}
	}
	return nil
}

func reasonsOf(body map[string]any) string {
	rs, _ := body["reasons"].([]any)
	var out []string
	for _, r := range rs {
		out = append(out, r.(string))
	}
	return strings.Join(out, ",")
}

// membershipOf は Org の管理者から見た、email のメンバーの Membership の公開 ID を返す。
func (l *loginEnv) membershipOf(t *testing.T, cookie, orgID, userID string) string {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/orgs/"+orgID+"/members", nil, "Cookie", sessionCookie+"="+cookie)
	var out struct {
		Members []struct {
			MembershipID string `json:"membership_id"`
			UserID       string `json:"user_id"`
		} `json:"members"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatalf("members: %d %s", w.Code, w.Body)
	}
	for _, m := range out.Members {
		if m.UserID == userID {
			return m.MembershipID
		}
	}
	t.Fatalf("no member %s", userID)
	return ""
}

func (l *loginEnv) mePatch(t *testing.T, cookie, path string, body any) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "PATCH", path, body, "Cookie", sessionCookie+"="+cookie)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// join は email のユーザーを owner の Org に role で招待し、受け入れさせて、そのアドレスでログインし直したセッションを返す。
func (l *loginEnv) join(t *testing.T, owner, orgID, email, role string) string {
	t.Helper()
	_, cookie := l.login(t, email)
	if code, body := l.invite(t, owner, orgID, email, role); code != 201 {
		t.Fatalf("invite %s: %d %v", email, code, body)
	}
	_, token := l.claimToken(t)
	if code, body := l.accept(t, cookie, token); code != 200 {
		t.Fatalf("accept %s: %d %v", email, code, body)
	}
	return cookie
}

func TestOperatorSuspendsOrg(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "pat@acme.example", "member")
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	l.advance(time.Second)
	_, pat := l.login(t, "pat@acme.example")
	if l.activeOrgPublic(t, pat) != acme {
		t.Fatal("pat should enter acme")
	}

	status, sp := l.admin(t, "/v1/admin/orgs/"+acme+"/suspensions", admin, map[string]string{"category": "tos_violation", "reason": "fraud ring"})
	if status != 201 || sp["target_type"] != "org" || sp["target_id"] != acme || sp["user_id"] != nil {
		t.Fatalf("suspend org: %d %v", status, sp)
	}
	// 停止中の Org の操作は理由つきで拒む。reason は見せない。
	code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/invitations", map[string]string{"email": "x@acme.example", "role": "member"})
	if code != 403 || reasonsOf(body) != "suspended.tos_violation" || strings.Contains(body["error"].(string), "fraud") {
		t.Fatalf("invite while suspended: %d %v", code, body)
	}
	// セッションは失効しない。検証の結果は遅くとも validity_max_delay の後に Org を使えないと示す。
	if code, _ := l.me(t, pat); code != 200 {
		t.Fatalf("session while org suspended: %d", code)
	}
	l.advance(l.a.cfg.Security.Session.ValidityMaxDelay.D() + time.Second)
	if v, err := l.a.sessions.Validate(t.Context(), l.a.realm.ID, pat); err != nil || !slices.Equal(v.OrgUnavailable, []string{"suspended.tos_violation"}) {
		t.Fatalf("validated = %+v, %v", v.OrgUnavailable, err)
	}
	if _, got := l.myOrgs(t, pat); !slices.Equal(unavailableOf(got, acme), []string{"suspended.tos_violation"}) {
		t.Fatalf("my orgs = %+v", got)
	}
	// ログインでは候補から外れ、個人 Org に入る。切り替えは理由つきで拒む。
	res, again := l.login(t, "pat@acme.example")
	if res["org_id"] == acme {
		t.Fatalf("login entered suspended org: %v", res)
	}
	if code, body, _ := l.post(t, again, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "suspended.tos_violation" {
		t.Fatalf("switch into suspended org: %d %v", code, body)
	}
	// 個人 Org は止められない。
	personal := l.activeOrgPublic(t, again)
	if status, out := l.admin(t, "/v1/admin/orgs/"+personal+"/suspensions", admin, map[string]string{"category": "tos_violation", "reason": "x"}); status != 409 || out["error"] != "personal_org" {
		t.Fatalf("suspend personal org: %d %v", status, out)
	}

	// 解除すれば戻る（ユーザーの停止と違い、停止をまたいだセッションも使える）。
	if status, out := l.admin(t, "/v1/admin/suspensions/"+sp["id"].(string)+":lift", admin, map[string]string{"reason": "cleared"}); status != 200 || out["lifted_at"] == nil {
		t.Fatalf("lift: %d %v", status, out)
	}
	if code, body, _ := l.post(t, again, "/v1/me/orgs/"+acme+":switch", nil); code != 200 {
		t.Fatalf("switch after lift: %d %v", code, body)
	}
	if code, _ := l.invite(t, owner, acme, "x@acme.example", "member"); code != 201 {
		t.Fatalf("invite after lift: %d", code)
	}
	var list struct {
		Suspensions []map[string]any `json:"suspensions"`
	}
	if status := l.adminGet(t, "/v1/admin/orgs/"+acme+"/suspensions", admin, &list); status != 200 || len(list.Suspensions) != 1 || list.Suspensions[0]["active"] != false {
		t.Fatalf("list: %d %v", status, list)
	}
	types := map[string]bool{}
	for _, e := range l.auditTypes(t) {
		types[e.Type] = true
	}
	if !types["org.suspended"] || !types["org.suspension_lifted"] {
		t.Fatalf("audit = %v", types)
	}
}

func TestOperatorOrgValidity(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	until := l.a.deps.Clock.Now().Add(10 * time.Minute)
	if status, _ := l.adminPatch(t, "/v1/admin/orgs/"+acme, support, map[string]any{"valid_until": until}); status != 403 {
		t.Fatalf("support patch = %d", status)
	}
	if status, out := l.adminPatch(t, "/v1/admin/orgs/"+acme, admin, map[string]any{"valid_from": until, "valid_until": until}); status != 400 || out["error"] != "invalid_period" {
		t.Fatalf("bad period = %d %v", status, out)
	}
	status, out := l.adminPatch(t, "/v1/admin/orgs/"+acme, admin, map[string]any{"valid_until": until})
	if status != 200 || out["valid_until"] == nil {
		t.Fatalf("patch = %d %v", status, out)
	}
	if code, _ := l.invite(t, owner, acme, "x@acme.example", "member"); code != 201 {
		t.Fatalf("invite in validity: %d", code)
	}
	// 境界の時刻ちょうどから使えない（判定は時刻から。scheduled_events の処理を待たない）。
	l.advance(10 * time.Minute)
	if code, body := l.invite(t, owner, acme, "y@acme.example", "member"); code != 403 || reasonsOf(body) != "outside_validity" {
		t.Fatalf("invite after validity: %d %v", code, body)
	}
	if status, _ := l.adminPatch(t, "/v1/admin/orgs/"+acme, admin, map[string]any{"valid_until": nil}); status != 200 {
		t.Fatalf("clear = %d", status)
	}
	if code, _ := l.invite(t, owner, acme, "y@acme.example", "member"); code != 201 {
		t.Fatalf("invite after clear: %d", code)
	}
}

func TestOrgAdminSuspendsMember(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	ownerID := l.userID(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	mgr := l.join(t, owner, acme, "mgr@acme.example", "admin")
	pat := l.join(t, owner, acme, "pat@acme.example", "member")
	sam := l.join(t, owner, acme, "sam@acme.example", "member")
	patM := l.membershipOf(t, owner, acme, l.userID(t, "pat@acme.example"))
	path := "/v1/me/orgs/" + acme + "/members/" + patM + "/suspensions"

	// 権限：member はできない。自分と、admin から owner は対象にできない。
	if code, body := l.mePost(t, sam, path, map[string]string{"reason": "x"}); code != 403 || body["error"] != "permission_denied" {
		t.Fatalf("member suspends: %d %v", code, body)
	}
	ownerPath := "/v1/me/orgs/" + acme + "/members/" + l.membershipOf(t, owner, acme, ownerID) + "/suspensions"
	if code, body := l.mePost(t, mgr, ownerPath, map[string]string{"reason": "x"}); code != 403 || body["error"] != "permission_denied" {
		t.Fatalf("admin suspends owner: %d %v", code, body)
	}
	if code, body := l.mePost(t, owner, ownerPath, map[string]string{"reason": "x"}); code != 403 || body["error"] != "self_target" {
		t.Fatalf("owner suspends self: %d %v", code, body)
	}

	code, sp := l.mePost(t, mgr, path, map[string]string{"reason": "left the project"})
	if code != 201 || sp["category"] != "customer_request" || sp["active"] != true || sp["membership_id"] != patM {
		t.Fatalf("suspend member: %d %v", code, sp)
	}
	// 停止された本人はこの Org にだけ入れない。
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "suspended.customer_request" {
		t.Fatalf("switch: %d %v", code, body)
	}
	if _, got := l.myOrgs(t, pat); !slices.Equal(unavailableOf(got, acme), []string{"suspended.customer_request"}) {
		t.Fatalf("my orgs = %+v", got)
	}
	if code, _ := l.me(t, pat); code != 200 {
		t.Fatalf("session = %d", code)
	}

	// 運営者による停止は Org の管理者には見えず、解除もできない。
	_, operator := l.operator(t, "admin@example.com", role.RealmAdmin)
	status, tos := l.admin(t, "/v1/admin/memberships/"+patM+"/suspensions", operator, map[string]string{"category": "tos_violation", "reason": "x"})
	if status != 201 || tos["target_type"] != "membership" || tos["user_id"] != l.userID(t, "pat@acme.example") {
		t.Fatalf("operator suspends membership: %d %v", status, tos)
	}
	w := l.do(t, l.a.PublicHandler(), "GET", path, nil, "Cookie", sessionCookie+"="+mgr)
	var list struct {
		Suspensions []map[string]any `json:"suspensions"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Suspensions) != 1 || list.Suspensions[0]["id"] != sp["id"] {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if code, _ := l.mePost(t, mgr, "/v1/me/orgs/"+acme+"/suspensions/"+tos["id"].(string)+":lift", map[string]string{"reason": "x"}); code != 404 {
		t.Fatalf("lift operator suspension: %d", code)
	}
	// 解除しても、運営者の停止は残る。
	if code, out := l.mePost(t, mgr, "/v1/me/orgs/"+acme+"/suspensions/"+sp["id"].(string)+":lift", map[string]string{"reason": "back"}); code != 200 || out["active"] != false {
		t.Fatalf("lift: %d %v", code, out)
	}
	if _, got := l.myOrgs(t, pat); !slices.Equal(unavailableOf(got, acme), []string{"suspended.tos_violation"}) {
		t.Fatalf("my orgs after lift = %+v", got)
	}
	// 本人は自分の停止を解除できない（Org の管理者でも）。
	mgrM := l.membershipOf(t, owner, acme, l.userID(t, "mgr@acme.example"))
	_, own := l.mePost(t, owner, "/v1/me/orgs/"+acme+"/members/"+mgrM+"/suspensions", map[string]string{"reason": "x"})
	if code, body := l.mePost(t, mgr, "/v1/me/orgs/"+acme+"/suspensions/"+own["id"].(string)+":lift", map[string]string{"reason": "x"}); code != 403 {
		t.Fatalf("self lift: %d %v", code, body)
	}
}

func TestOrgAdminMemberValidity(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	pat := l.join(t, owner, acme, "pat@acme.example", "member")
	patM := l.membershipOf(t, owner, acme, l.userID(t, "pat@acme.example"))
	until := l.a.deps.Clock.Now().Add(10 * time.Minute)
	code, out := l.mePatch(t, owner, "/v1/me/orgs/"+acme+"/members/"+patM, map[string]any{"valid_until": until})
	if code != 200 || out["valid_until"] == nil {
		t.Fatalf("patch: %d %v", code, out)
	}
	code, _, pat = l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil)
	if code != 200 {
		t.Fatalf("switch in validity: %d", code)
	}
	l.advance(10 * time.Minute)
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "outside_validity" {
		t.Fatalf("switch after validity: %d %v", code, body)
	}
	// 運営者も変えられる。
	_, operator := l.operator(t, "admin@example.com", role.RealmAdmin)
	if status, out := l.adminPatch(t, "/v1/admin/memberships/"+patM, operator, map[string]any{}); status != 200 || out["valid_until"] != nil {
		t.Fatalf("operator clear: %d %v", status, out)
	}
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 200 {
		t.Fatalf("switch after clear: %d %v", code, body)
	}
}

// activeOrgPublic はセッションの active な Org の公開 ID を返す。
func (l *loginEnv) activeOrgPublic(t *testing.T, cookie string) string {
	t.Helper()
	_, got := l.myOrgs(t, cookie)
	for _, o := range got.Orgs {
		if o.Active {
			return o.ID
		}
	}
	t.Fatal("no active org")
	return ""
}
