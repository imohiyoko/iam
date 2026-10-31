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
			Kind        string   `json:"kind"`
			Role        string   `json:"role"`
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
	if me.ActiveOrg == nil || me.ActiveOrg.Kind != "personal" || me.ActiveOrg.Role != "owner" || me.ActiveOrg.Unavailable == nil || len(me.ActiveOrg.Unavailable) != 0 {
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

// active な Org の Group は、直接の所属と入れ子で受け継ぐものを名前の順に返し、ほかの Org の Group は出さない（design.md 11.5）。
func TestGetMeGroups(t *testing.T) {
	l := nestedGroupsEnv(t, true)
	_, owner := l.login(t, "boss@acme.example")
	acme := l.sharedOrg(t, owner, "Acme")
	other := l.sharedOrg(t, owner, "Other")
	l.join(t, owner, acme, "sam@acme.example", "member")
	l.join(t, owner, other, "sam@acme.example", "member")
	_, sam := l.login(t, "sam@acme.example")
	samID := l.userID(t, "sam@acme.example")
	group := func(org, name string) string {
		t.Helper()
		code, body := l.meDo(t, "POST", owner, "/v1/me/orgs/"+org+"/groups", map[string]any{"name": name})
		if code != 201 {
			t.Fatalf("create group %s: %d %v", name, code, body)
		}
		return body["id"].(string)
	}
	add := func(org, parent, typ, child string) {
		t.Helper()
		code, body := l.meDo(t, "POST", owner, "/v1/me/orgs/"+org+"/groups/"+parent+"/members", map[string]any{"principal_type": typ, "principal_id": child})
		if code != 204 {
			t.Fatalf("add %s to %s: %d %v", child, parent, code, body)
		}
	}
	eng, all := group(acme, "Engineering"), group(acme, "All staff")
	group(acme, "Sales")
	add(acme, eng, "user", samID)
	add(acme, all, "group", eng)
	add(other, group(other, "Elsewhere"), "user", samID)
	code, _, sam := l.post(t, sam, "/v1/me/orgs/"+acme+":switch", nil)
	if code != 200 {
		t.Fatalf("switch: %d", code)
	}
	w := l.do(t, l.a.PublicHandler(), "GET", "/v1/me", nil, "Cookie", sessionCookie+"="+sam)
	var me struct {
		ActiveOrg struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Name   string `json:"name"`
			Role   string `json:"role"`
			Groups []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Direct bool   `json:"direct"`
			} `json:"groups"`
		} `json:"active_org"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &me); w.Code != 200 || err != nil {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	o := me.ActiveOrg
	if o.ID != acme || o.Kind != "shared" || o.Name != "Acme" || o.Role != "member" || len(o.Groups) != 2 {
		t.Fatalf("active org: %s", w.Body)
	}
	if g := o.Groups[0]; g.ID != all || g.Name != "All staff" || g.Direct {
		t.Fatalf("inherited group: %+v", g)
	}
	if g := o.Groups[1]; g.ID != eng || g.Name != "Engineering" || !g.Direct {
		t.Fatalf("direct group: %+v", g)
	}
}
