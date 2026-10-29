package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

func newOrgEnv(t *testing.T, via ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		if len(via) > 0 {
			c.Realm.VerifiedVia = via
		}
	}, feature.Registered())
}

// claimToken は最後の通知のトークンを取り出す。
func (l *loginEnv) claimToken(t *testing.T) (to, token string) {
	t.Helper()
	if _, err := l.a.notifier.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := l.notes.last(t)
	w := l.do(t, l.a.AdminHandler(), "POST", "/v1/admin/notifications/"+n.ID+":claim", nil, "Authorization", "Bearer "+l.apiKey)
	var sec struct{ To, Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &sec) != nil || sec.Token == "" {
		t.Fatalf("claim: %d %s", w.Code, w.Body)
	}
	return sec.To, sec.Token
}

func (l *loginEnv) sharedOrg(t *testing.T, cookie, name string) string {
	t.Helper()
	code, body := l.mePost(t, cookie, "/v1/me/orgs", map[string]string{"name": name})
	if code != 201 {
		t.Fatalf("create org: %d %v", code, body)
	}
	return body["id"].(string)
}

func (l *loginEnv) invite(t *testing.T, cookie, orgID, email, role string) (int, map[string]any) {
	t.Helper()
	return l.mePost(t, cookie, "/v1/me/orgs/"+orgID+"/invitations", map[string]string{"email": email, "role": role})
}

func (l *loginEnv) accept(t *testing.T, cookie, token string) (int, map[string]any) {
	t.Helper()
	if cookie == "" {
		w := l.do(t, l.a.PublicHandler(), "POST", "/v1/invitations:accept", map[string]string{"token": token})
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	return l.mePost(t, cookie, "/v1/invitations:accept", map[string]string{"token": token})
}

type orgMember struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}

type orgMembers struct {
	Members []orgMember `json:"members"`
}

func (l *loginEnv) members(t *testing.T, cookie, orgID string) (int, orgMembers) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/orgs/"+orgID+"/members", nil, "Cookie", sessionCookie+"="+cookie)
	var out orgMembers
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// 招待したアドレスが Membership に結び付き、Org の管理者にはそれだけが見える（4.4、roadmap M3）。
func TestInvitationBindsInvitedEmail(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "pat@example.com")
	orgID := l.sharedOrg(t, owner, "Acme")
	_, sam := l.login(t, "sam@home.example")

	code, body := l.invite(t, owner, orgID, "Sam@Work.example", "member")
	if code != 201 || body["email"] != "sam@work.example" || body["status"] != "pending" {
		t.Fatalf("invite = %d %v", code, body)
	}
	to, token := l.claimToken(t)
	if to != "sam@work.example" {
		t.Fatalf("invitation sent to %q", to)
	}
	code, body = l.accept(t, sam, token)
	if code != 200 || body["login"] != nil {
		t.Fatalf("accept = %d %v", code, body)
	}
	got := body["org"].(map[string]any)
	if got["id"] != orgID || got["role"] != "member" || got["email_id"] == nil {
		t.Fatalf("accepted org = %v", got)
	}
	// 使い直せない。受け入れた招待のアドレスの鍵は消す（crypto-shredding）。
	if code, body := l.accept(t, sam, token); code != 404 || body["error"] != "invalid_invitation" {
		t.Fatalf("accept again = %d %v", code, body)
	}
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		o, err := tx.Orgs().GetByPublicID(ctx, l.a.realm.ID, orgID)
		if err != nil {
			return err
		}
		invs, err := tx.Invitations().ListByOrg(ctx, l.a.realm.ID, o.ID)
		if err != nil || len(invs) != 1 {
			t.Fatalf("invitations = %+v, %v", invs, err)
		}
		if _, err := tx.DataKeys().Get(ctx, invs[0].ID); !errors.Is(err, errs.NotFound) {
			t.Fatalf("invitation data key after accept: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	_, ms := l.members(t, owner, orgID)
	if len(ms.Members) != 2 {
		t.Fatalf("members = %+v", ms)
	}
	for _, m := range ms.Members {
		if m.UserID == l.userID(t, "sam@home.example") && m.Email != "sam@work.example" {
			t.Fatalf("org admin sees %q, want only the bound email", m.Email)
		}
		if m.Email == "sam@home.example" {
			t.Fatal("org admin sees an email not bound to the membership")
		}
	}
	// メンバーは一覧を見られない（招待・除名の権限が無い）。
	if code, _ := l.members(t, sam, orgID); code != 403 {
		t.Fatalf("member lists members = %d", code)
	}

	// 結び付いたメールは消せない。primary に結び付け直せば消せる。
	workID := got["email_id"].(string)
	if code, body := l.mePost(t, sam, "/v1/me/emails/"+workID+":remove", nil); code != 409 || body["error"] != "email_bound_to_membership" {
		t.Fatalf("remove bound email = %d %v", code, body)
	}
	if code, body := l.mePost(t, sam, "/v1/me/orgs/"+orgID+":bind-email", map[string]any{}); code != 200 || body["email_id"] != nil {
		t.Fatalf("rebind to primary = %d %v", code, body)
	}
	if _, ms := l.members(t, owner, orgID); !slices.ContainsFunc(ms.Members, func(m orgMember) bool { return m.Email == "sam@home.example" }) {
		t.Fatalf("after rebind members = %+v", ms)
	}
	if code, _ := l.mePost(t, sam, "/v1/me/emails/"+workID+":remove", nil); code != 204 {
		t.Fatalf("remove after rebind = %d", code)
	}
	// index_only に切り替えた直後（掃除前で暗号文が残っている）も、アドレスは見せない（9.6）。
	l.a.accounts.IndexOnly = true
	if _, ms := l.members(t, owner, orgID); slices.ContainsFunc(ms.Members, func(m orgMember) bool { return m.Email != "" }) {
		t.Fatalf("index_only members = %+v", ms)
	}
}

func TestInvitationRegistersNewUser(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "pat@example.com")
	orgID := l.sharedOrg(t, owner, "Acme")
	if code, _ := l.invite(t, owner, orgID, "new@example.com", "admin"); code != 201 {
		t.Fatalf("invite = %d", code)
	}
	_, token := l.claimToken(t)
	code, body := l.accept(t, "", token)
	if code != 200 || body["login"] == nil {
		t.Fatalf("accept = %d %v", code, body)
	}
	login := body["login"].(map[string]any)
	if login["created"] != true || body["org"].(map[string]any)["active"] != true || body["org"].(map[string]any)["role"] != "admin" {
		t.Fatalf("registered = %v", body)
	}
	_, cookie := l.login(t, "new@example.com")
	if _, got := l.myOrgs(t, cookie); len(got.Orgs) != 2 {
		t.Fatalf("new user's orgs = %+v", got)
	}
}

// realm が招待をメールの確認とみなさなければ、本人が先にアドレスを確認する。
func TestInvitationRequiresVerifiedEmailByDefault(t *testing.T) {
	l := newOrgEnv(t)
	_, owner := l.login(t, "pat@example.com")
	orgID := l.sharedOrg(t, owner, "Acme")
	_, sam := l.login(t, "sam@example.com")

	l.invite(t, owner, orgID, "new@example.com", "member")
	_, token := l.claimToken(t)
	if code, body := l.accept(t, "", token); code != 409 || body["error"] != "email_verification_required" {
		t.Fatalf("anonymous accept = %d %v", code, body)
	}
	if code, body := l.accept(t, sam, token); code != 409 || body["error"] != "email_verification_required" {
		t.Fatalf("accept without the email = %d %v", code, body)
	}
	// 本人のアドレスへの招待はそのまま受け入れられる。ログインしていなければログインを求める。
	l.invite(t, owner, orgID, "sam@example.com", "member")
	_, token = l.claimToken(t)
	if code, body := l.accept(t, "", token); code != 409 || body["error"] != "login_required" {
		t.Fatalf("anonymous accept of existing user = %d %v", code, body)
	}
	_, other := l.login(t, "other@example.com")
	if code, body := l.accept(t, other, token); code != 409 || body["error"] != "email_exists" {
		t.Fatalf("accept by another user = %d %v", code, body)
	}
	if code, body := l.accept(t, sam, token); code != 200 {
		t.Fatalf("accept own email = %d %v", code, body)
	}
	// 既にメンバーなら招待できない。
	if code, body := l.invite(t, owner, orgID, "sam@example.com", "member"); code != 409 || body["error"] != "already_member" {
		t.Fatalf("invite member = %d %v", code, body)
	}
}

func TestInvitationPermissions(t *testing.T) {
	l := newOrgEnv(t)
	_, owner := l.login(t, "pat@example.com")
	orgID := l.sharedOrg(t, owner, "Acme")
	_, admin := l.login(t, "ada@example.com")
	_, member := l.login(t, "mem@example.com")
	for email, r := range map[string]string{"ada@example.com": "admin", "mem@example.com": "member"} {
		l.invite(t, owner, orgID, email, r)
		_, token := l.claimToken(t)
		c := admin
		if r == "member" {
			c = member
		}
		if code, body := l.accept(t, c, token); code != 200 {
			t.Fatalf("accept %s = %d %v", email, code, body)
		}
	}
	if code, body := l.invite(t, member, orgID, "x@example.com", "member"); code != 403 || body["error"] != "permission_denied" {
		t.Fatalf("member invites = %d %v", code, body)
	}
	if code, _ := l.invite(t, admin, orgID, "x@example.com", "owner"); code != 403 {
		t.Fatalf("admin invites owner = %d", code)
	}
	if code, _ := l.invite(t, admin, orgID, "x@example.com", "member"); code != 201 {
		t.Fatalf("admin invites member = %d", code)
	}
	if code, body := l.invite(t, admin, orgID, "x@example.com", "boss"); code != 400 {
		t.Fatalf("unknown role = %d %v", code, body)
	}
	// 所属していない Org は見えない。
	_, outsider := l.login(t, "out@example.com")
	if code, _ := l.invite(t, outsider, orgID, "y@example.com", "member"); code != 404 {
		t.Fatalf("outsider invites = %d", code)
	}
	// 個人 Org には招待できない。
	_, mine := l.myOrgs(t, owner)
	var personal string
	for _, o := range mine.Orgs {
		if o.Kind == "personal" {
			personal = o.ID
		}
	}
	if code, body := l.invite(t, owner, personal, "y@example.com", "member"); code != 409 || body["error"] != "personal_org" {
		t.Fatalf("invite to personal org = %d %v", code, body)
	}

	// 取り消した招待は受け入れられず、アドレスも返さない。
	_, body := l.invite(t, owner, orgID, "z@example.com", "member")
	_, token := l.claimToken(t)
	invID := body["id"].(string)
	if code, _ := l.mePost(t, admin, "/v1/me/orgs/"+orgID+"/invitations/"+invID+":revoke", nil); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	if code, _ := l.mePost(t, admin, "/v1/me/orgs/"+orgID+"/invitations/"+invID+":revoke", nil); code != 404 {
		t.Fatalf("revoke again = %d", code)
	}
	_, z := l.login(t, "z@example.com")
	if code, _ := l.accept(t, z, token); code != 404 {
		t.Fatalf("accept revoked = %d", code)
	}
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/orgs/"+orgID+"/invitations", nil, "Cookie", sessionCookie+"="+owner)
	var invs struct {
		Invitations []struct {
			ID     string  `json:"id"`
			Email  *string `json:"email"`
			Status string  `json:"status"`
		} `json:"invitations"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &invs) != nil {
		t.Fatalf("list = %d %s", w.Code, w.Body)
	}
	for _, i := range invs.Invitations {
		if i.Status != "pending" && i.Email != nil {
			t.Fatalf("closed invitation shows its address: %+v", i)
		}
		if i.ID == invID && i.Status != "revoked" {
			t.Fatalf("revoked invitation = %+v", i)
		}
	}
}
