package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/imohiyoko/iam/shared/port"
)

// GET /v1/me は本人の公開 ID、primary のメール、active な Org、このセッションを返し、内部 ID を出さない（ADR 0045）。
func TestGetMe(t *testing.T) {
	l := newOrgEnv(t)
	if w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me", nil); w.Code != 401 {
		t.Fatalf("no session: %d %s", w.Code, w.Body)
	}
	_, cookie := l.login(t, "mia@example.com")
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me", nil, "Cookie", sessionCookie+"="+cookie)
	if w.Code != 200 {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	var me struct {
		ID           string `json:"id"`
		PrimaryEmail struct {
			Email   string `json:"email"`
			Primary bool   `json:"primary"`
		} `json:"primary_email"`
		ActiveOrg *struct {
			ID          string   `json:"id"`
			Unavailable []string `json:"unavailable"`
		} `json:"active_org"`
		Session struct {
			ID          string   `json:"id"`
			AuthMethods []string `json:"auth_methods"`
		} `json:"session"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.PrimaryEmail.Email != "mia@example.com" || !me.PrimaryEmail.Primary || len(me.Session.AuthMethods) == 0 {
		t.Fatalf("me: %s", w.Body)
	}
	if me.ActiveOrg == nil || me.ActiveOrg.Unavailable == nil || len(me.ActiveOrg.Unavailable) != 0 {
		t.Fatalf("active org: %s", w.Body)
	}
	if _, list := l.me(t, cookie); len(list) != 1 || list[0]["id"] != me.Session.ID || list[0]["current"] != true {
		t.Fatalf("session %q, list %v", me.Session.ID, list)
	}
	u, _ := l.storedUser(t, me.ID)
	var orgID string
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		o, err := tx.Orgs().GetByPublicID(ctx, l.a.realm.ID, me.ActiveOrg.ID)
		orgID = o.ID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, internal := range []string{u.ID, orgID} {
		if strings.Contains(w.Body.String(), internal) {
			t.Fatalf("internal ID %q in %s", internal, w.Body)
		}
	}
}
