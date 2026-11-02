package app

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/authn/method/passkey/passkeytest"
)

// passkey を認証方式のポートに載せたこと（ADR 0106）を HTTP で確かめる。汎用のパスと方式専用のパスは同じ処理で動く。

func TestPasskeyGenericPaths(t *testing.T) {
	l := newPasskeyEnv(t)
	first, cookie := l.login(t, "gpk@example.com")
	a := passkeytest.New(passkeyOrigin)
	status, st := l.mePost(t, cookie, "/v1/me/credentials/passkey:enroll-begin", nil)
	if status != 200 {
		t.Fatalf("enroll-begin: %d %v", status, st)
	}
	opts, err := json.Marshal(st["payload"])
	if err != nil {
		t.Fatal(err)
	}
	cred, err := a.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	status, res := l.mePost(t, cookie, "/v1/me/credentials/passkey:enroll-complete", map[string]any{"flow_id": st["flow_id"],
		"payload": map[string]any{"credential": json.RawMessage(cred), "name": "Key"}})
	if status != 200 {
		t.Fatalf("enroll-complete: %d %v", status, res)
	}
	cid := res["credential"].(map[string]any)["id"].(string)
	// 汎用で登録したものも方式専用の一覧に出る。
	if m := l.passkeys(t, cookie); len(m.Passkeys) != 1 || m.Passkeys[0].ID != cid || m.Passkeys[0].Name != "Key" {
		t.Fatalf("methods: %+v", m)
	}

	status, ch, _ := l.post(t, "", "/v1/login/methods/passkey:begin", nil)
	if status != 200 {
		t.Fatalf("login begin: %d %v", status, ch)
	}
	opts, err = json.Marshal(ch["payload"])
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := a.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	status, login, pcookie := l.post(t, "", "/v1/login/methods/passkey:complete", map[string]any{"flow_id": ch["flow_id"],
		"payload": map[string]any{"credential": json.RawMessage(assertion)}})
	if status != 200 || login["user_id"] != first["user_id"] || pcookie == "" {
		t.Fatalf("generic login: %d %v", status, login)
	}
	if got := amr(t, l, pcookie); !slices.Equal(got, []any{"hwk", "user"}) {
		t.Fatalf("amr: %v", got)
	}
	// 同じチャレンジはもう使えない（一度きり）。
	if status, _, _ := l.post(t, "", "/v1/login/methods/passkey:complete", map[string]any{"flow_id": ch["flow_id"],
		"payload": map[string]any{"credential": json.RawMessage(assertion)}}); status == 200 {
		t.Fatal("replayed challenge accepted")
	}
	// 方式専用のパスでもログインでき、方式専用のパスで無効化すると汎用のパスでも入れない。
	if status, _, _ := l.passkeyLogin(t, a); status != 200 {
		t.Fatalf("legacy login: %d", status)
	}
	if status, _ := l.mePost(t, cookie, "/v1/me/passkeys/"+cid+":revoke", nil); status != 204 {
		t.Fatalf("revoke: %d", status)
	}
	if status, res, _ := l.passkeyLogin(t, a); status != 401 || res["error"] != "authentication_failed" {
		t.Fatalf("login after revoke: %d %v", status, res)
	}
}
