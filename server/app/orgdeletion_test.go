package app

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// Org の削除と、期限の過ぎた招待の後始末（design.md 4.10）を HTTP で確かめる。

func (l *loginEnv) invitationKey(t *testing.T, publicID string) (port.Invitation, error) {
	t.Helper()
	var inv port.Invitation
	var keyErr error
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		if inv, err = tx.Invitations().GetByPublicID(ctx, l.a.realm.ID, publicID); err != nil {
			return err
		}
		_, keyErr = tx.DataKeys().Get(ctx, inv.ID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return inv, keyErr
}

func TestOrgDeletion(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	pat := l.join(t, owner, acme, "pat@acme.example", "member")
	code, inv := l.invite(t, owner, acme, "later@acme.example", "member")
	if code != 201 {
		t.Fatalf("invite: %d", code)
	}

	if code, body := l.mePost(t, pat, "/v1/me/orgs/"+acme+":delete", nil); code != 403 || body["error"] != "permission_denied" {
		t.Fatalf("member deletes: %d %v", code, body)
	}
	code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+":delete", nil)
	if code != 200 || body["deleted"] != false || body["deletes_at"] == nil {
		t.Fatalf("delete: %d %v", code, body)
	}
	if code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+":delete", nil); code != 409 || body["error"] != "deletion_scheduled" {
		t.Fatalf("delete twice: %d %v", code, body)
	}
	// 猶予期間の間はメンバーが入れない。
	if _, got := l.myOrgs(t, pat); !slices.Equal(unavailableOf(got, acme), []string{org.CodeDeletionScheduled}) {
		t.Fatalf("my orgs = %+v", got)
	}
	if code, body, _ := l.post(t, pat, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != org.CodeDeletionScheduled {
		t.Fatalf("switch: %d %v", code, body)
	}
	// 取り消せる。
	if code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+":cancel-deletion", nil); code != 204 {
		t.Fatalf("cancel: %d %v", code, body)
	}
	if code, body := l.mePost(t, owner, "/v1/me/orgs/"+acme+":cancel-deletion", nil); code != 409 || body["error"] != "deletion_not_scheduled" {
		t.Fatalf("cancel twice: %d %v", code, body)
	}
	if _, got := l.myOrgs(t, pat); unavailableOf(got, acme) != nil {
		t.Fatalf("my orgs after cancel = %+v", got)
	}
	// 取り消した予定は発火しない。
	l.advance(31 * 24 * time.Hour)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, owner = l.login(t, "boss@acme.example")
	if code, _ := l.mePost(t, owner, "/v1/me/orgs/"+acme+":delete", nil); code != 200 {
		t.Fatalf("delete again: %d", code)
	}
	l.advance(31 * 24 * time.Hour)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	// 削除した：全員の Membership が終わり、行は墓標として残る。
	_, pat = l.login(t, "pat@acme.example")
	if _, got := l.myOrgs(t, pat); len(got.Orgs) != 1 || got.Orgs[0].Kind != "personal" {
		t.Fatalf("pat orgs after deletion = %+v", got)
	}
	_, owner = l.login(t, "boss@acme.example")
	if code, _ := l.mePost(t, owner, "/v1/me/orgs/"+acme+":cancel-deletion", nil); code != 404 {
		t.Fatalf("cancel after deletion: %d", code)
	}
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	var view map[string]any
	if status := l.adminGet(t, "/v1/admin/orgs/"+acme, admin, &view); status != 200 || view["deleted_at"] == nil {
		t.Fatalf("admin view: %d %v", status, view)
	}
	// 招待は pending のまま残らず、アドレスの鍵も消えている（ここでは期限の後始末が先に来る）。
	if got, err := l.invitationKey(t, inv["id"].(string)); got.Status == port.InvitationPending || !errors.Is(err, errs.NotFound) {
		t.Fatalf("invitation after deletion = %v, key %v", got.Status, err)
	}
	types := map[string]bool{}
	for _, e := range l.auditTypes(t) {
		types[e.Type] = true
	}
	if !types["org.deletion_scheduled"] || !types["org.deletion_cancelled"] || !types[org.EventOrgDeleted] {
		t.Fatalf("audit = %v", types)
	}
}

func TestOperatorDeletesOrg(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	if status, _ := l.admin(t, "/v1/admin/orgs/"+acme+":delete", support, map[string]bool{"immediate": true}); status != 403 {
		t.Fatalf("support deletes: %d", status)
	}
	personal := l.activeOrgPublic(t, owner)
	if status, out := l.admin(t, "/v1/admin/orgs/"+personal+":delete", admin, nil); status != 409 || out["error"] != "personal_org" {
		t.Fatalf("delete personal: %d %v", status, out)
	}
	_, inv := l.invite(t, owner, acme, "x@acme.example", "member")
	status, out := l.admin(t, "/v1/admin/orgs/"+acme+":delete", admin, map[string]bool{"immediate": true})
	if status != 200 || out["deleted_at"] == nil {
		t.Fatalf("immediate delete: %d %v", status, out)
	}
	// pending の招待は取り消し、アドレスの鍵を消す。
	if got, err := l.invitationKey(t, inv["id"].(string)); got.Status != port.InvitationRevoked || !errors.Is(err, errs.NotFound) {
		t.Fatalf("invitation after deletion = %v, key %v", got.Status, err)
	}
	if _, got := l.myOrgs(t, owner); len(got.Orgs) != 1 {
		t.Fatalf("owner orgs = %+v", got)
	}
	if status, _ := l.admin(t, "/v1/admin/orgs/"+acme+":delete", admin, nil); status != 404 {
		t.Fatalf("delete twice: %d", status)
	}
}

func TestInvitationExpiryShredsKey(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	_, inv := l.invite(t, owner, acme, "x@acme.example", "member")
	_, token := l.claimToken(t)
	if _, err := l.invitationKey(t, inv["id"].(string)); err != nil {
		t.Fatalf("key before expiry: %v", err)
	}
	l.advance(org.DefaultInvitationTTL + time.Second)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := l.invitationKey(t, inv["id"].(string))
	if got.Status != port.InvitationExpired || !errors.Is(err, errs.NotFound) {
		t.Fatalf("after expiry = %v, key %v", got.Status, err)
	}
	if code, _ := l.accept(t, "", token); code != 404 {
		t.Fatalf("accept expired: %d", code)
	}
	_, owner = l.login(t, "boss@acme.example")
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me/orgs/"+acme+"/invitations", nil, "Cookie", sessionCookie+"="+owner)
	var list struct {
		Invitations []map[string]any `json:"invitations"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Invitations) != 1 || list.Invitations[0]["status"] != "expired" || list.Invitations[0]["email"] != nil {
		t.Fatalf("invitations: %d %s", w.Code, w.Body)
	}
}
