package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// アカウントの削除（design.md 4.10）を HTTP で確かめる。

// storedUser は公開 ID のユーザーと、データ鍵が残っているかを返す。
func (l *loginEnv) storedUser(t *testing.T, publicID string) (port.User, bool) {
	t.Helper()
	var u port.User
	var hasKey bool
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		if u, err = tx.Users().GetByPublicID(ctx, l.a.realm.ID, publicID); err != nil {
			return err
		}
		_, err = tx.DataKeys().Get(ctx, u.ID)
		hasKey = err == nil
		if errors.Is(err, errs.NotFound) {
			err = nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u, hasKey
}

func TestAccountDeletion(t *testing.T) {
	l := newOrgEnv(t, "code", "oauth_provider", "admin", "invitation")
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	l.join(t, owner, acme, "sam@acme.example", "member")
	samID := l.userID(t, "sam@acme.example")

	// 共有 Org の最後のオーナーの間はできない。
	if code, body := l.mePost(t, owner, "/v1/me/account:delete", nil); code != 409 || body["error"] != "last_owner" {
		t.Fatalf("last owner delete: %d %v", code, body)
	}
	// 直近の本人確認が要る。
	l.advance(16 * time.Minute)
	_, sam := l.login(t, "sam@acme.example")
	l.advance(16 * time.Minute)
	if code, body := l.mePost(t, sam, "/v1/me/account:delete", nil); code != 401 || body["error"] != "reauthentication_required" {
		t.Fatalf("stale delete: %d %v", code, body)
	}
	_, sam = l.login(t, "sam@acme.example")
	code, body := l.mePost(t, sam, "/v1/me/account:delete", nil)
	if code != 200 || body["deleted"] != false || body["deletes_at"] == nil {
		t.Fatalf("delete: %d %v", code, body)
	}
	// 既存のセッションは使えない。ログインしても取り消しだけができる。
	if code, _ := l.me(t, sam); code != 401 {
		t.Fatalf("session after delete: %d", code)
	}
	res, pending := l.login(t, "sam@acme.example")
	if res["next"] != "cancel_deletion" {
		t.Fatalf("login while pending = %v", res)
	}
	if code, _ := l.me(t, pending); code != 403 && code != 401 {
		t.Fatalf("restricted session used: %d", code)
	}
	code, body, cancelled := l.post(t, pending, "/v1/me/account:cancel-deletion", nil)
	if code != 200 || body["next"] != nil || cancelled == "" {
		t.Fatalf("cancel: %d %v", code, body)
	}
	if code, _ := l.me(t, cancelled); code != 200 {
		t.Fatalf("session after cancel: %d", code)
	}
	if code, body := l.mePost(t, cancelled, "/v1/me/account:delete", nil); code != 200 {
		t.Fatalf("delete again: %d %v", code, body)
	}

	// 保留の間は猶予が終わっても消さない。
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, ownerOp := l.operator(t, "root@example.com", role.RealmOwner)
	if status, _ := l.admin(t, "/v1/admin/users/"+samID+":legal-hold", admin, map[string]bool{"hold": true}); status != 403 {
		t.Fatalf("admin legal hold: %d", status)
	}
	if status, out := l.admin(t, "/v1/admin/users/"+samID+":legal-hold", ownerOp, map[string]bool{"hold": true}); status != 200 || out["legal_hold"] != true {
		t.Fatalf("legal hold: %d %v", status, out)
	}
	l.advance(31 * 24 * time.Hour)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if u, hasKey := l.storedUser(t, samID); u.Status != port.UserActive || !hasKey {
		t.Fatalf("held user = %+v, key %v", u, hasKey)
	}
	// 保留を解くと次の回に消す。
	_, ownerOp = l.operator(t, "root2@example.com", role.RealmOwner)
	if status, _ := l.admin(t, "/v1/admin/users/"+samID+":legal-hold", ownerOp, map[string]bool{"hold": false}); status != 200 {
		t.Fatalf("release hold: %d", status)
	}
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, hasKey := l.storedUser(t, samID)
	if u.Status != port.UserDeleted || hasKey {
		t.Fatalf("deleted user = %+v, key %v", u, hasKey)
	}
	types := map[string]int{}
	for _, e := range l.auditTypes(t) {
		types[e.Type]++
	}
	if types["user.deletion_scheduled"] != 2 || types["user.deletion_cancelled"] != 1 || types["user.deletion_held"] != 1 || types["user.deleted"] != 1 {
		t.Fatalf("audit = %v", types)
	}
	// 所属は終わり、メールのインデックスも消えて、同じアドレスで新しいユーザーとして登録できる。
	_, owner = l.login(t, "boss@acme.example")
	if _, got := l.members(t, owner, acme); len(got.Members) != 1 {
		t.Fatalf("members after deletion = %+v", got)
	}
	if res, _ := l.login(t, "sam@acme.example"); res["user_id"] == samID || res["created"] != true {
		t.Fatalf("re-register = %v", res)
	}
}

func TestOperatorDeletesUserImmediately(t *testing.T) {
	l := newLoginEnvWith(t, nil, nil)
	_, cookie := l.login(t, "pat@example.com")
	uid := l.userID(t, "pat@example.com")
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+":delete", support, map[string]bool{"immediate": true}); status != 403 {
		t.Fatalf("support delete: %d", status)
	}
	status, out := l.admin(t, "/v1/admin/users/"+uid+":delete", admin, map[string]bool{"immediate": true})
	if status != 200 || out["status"] != "deleted" {
		t.Fatalf("immediate delete: %d %v", status, out)
	}
	if code, _ := l.me(t, cookie); code != 401 {
		t.Fatalf("session after delete: %d", code)
	}
	if u, hasKey := l.storedUser(t, uid); u.Status != port.UserDeleted || hasKey {
		t.Fatalf("user = %+v, key %v", u, hasKey)
	}
	if status, _ := l.admin(t, "/v1/admin/users/"+uid+":delete", admin, nil); status != 404 {
		t.Fatalf("delete twice: %d", status)
	}
}

// realm の最後の realm:owner は削除できない。猶予の間に最後になったら、猶予が終わっても消さない（ADR 0064）。
func TestLastRealmOwnerDeletion(t *testing.T) {
	l := newLoginEnvWith(t, nil, nil)
	rootID, _ := l.operator(t, "root@example.com", role.RealmOwner)
	_, admin := l.operator(t, "admin@example.com", role.RealmAdmin)
	for _, body := range []any{map[string]bool{"immediate": true}, nil} {
		if status, out := l.admin(t, "/v1/admin/users/"+rootID+":delete", admin, body); status != 409 || out["error"] != "last_owner" {
			t.Fatalf("delete last owner %v: %d %v", body, status, out)
		}
	}
	root2ID, _ := l.operator(t, "root2@example.com", role.RealmOwner)
	if status, out := l.admin(t, "/v1/admin/users/"+rootID+":delete", admin, nil); status != 200 {
		t.Fatalf("schedule owner deletion: %d %v", status, out)
	}
	// 削除の予約中の owner は数えない：root2 が最後の使える owner になる。
	if status, out := l.admin(t, "/v1/admin/users/"+root2ID+":delete", admin, map[string]bool{"immediate": true}); status != 409 || out["error"] != "last_owner" {
		t.Fatalf("delete the last available owner: %d %v", status, out)
	}
	// 猶予の間に別の owner の付与が消えると、root が最後の owner になる。
	if err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, root2ID)
		if err != nil {
			return err
		}
		bs, err := tx.RoleBindings().ListByPrincipal(ctx, l.a.realm.ID, port.PrincipalUser, u.ID)
		if err != nil {
			return err
		}
		for _, b := range bs {
			if err := tx.RoleBindings().Delete(ctx, l.a.realm.ID, b.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l.advance(31 * 24 * time.Hour)
	if _, err := l.a.scheduler.Fire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if u, hasKey := l.storedUser(t, rootID); u.Status != port.UserActive || !hasKey {
		t.Fatalf("last owner purged: %+v, key %v", u, hasKey)
	}
	held := false
	for _, e := range l.auditTypes(t) {
		if e.Type == "user.deletion_held" && e.Details["reason"] == "last_owner" {
			held = true
		}
	}
	if !held {
		t.Fatal("no user.deletion_held for the last owner")
	}
}
