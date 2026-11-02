package app

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/authn/credential"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
	"github.com/imohiyoko/iam/authn/method/passkey/passkeytest"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
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

// 方式専用の表に残っている passkey と無効化した credential ID は、起動で authn_credentials と退役した検索キーへ移り、
// 移した後もそのまま使える（ADR 0106）。
func TestStartupMigratesLegacyPasskeys(t *testing.T) {
	// 認証器の公開鍵を得るため、別の環境で登録しておく。
	src := newPasskeyEnv(t)
	sfirst, scookie := src.login(t, "src@example.com")
	a, gone := passkeytest.New(passkeyOrigin), passkeytest.New(passkeyOrigin)
	var datas []passkeym.Data
	for _, x := range []*passkeytest.Authenticator{a, gone} {
		if status, res := src.registerPasskey(t, scookie, x, "Legacy"); status != 200 {
			t.Fatalf("register: %d %v", status, res)
		}
	}
	ctx := context.Background()
	if err := src.e.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, src.a.realm.ID, sfirst["user_id"].(string))
		if err != nil {
			return err
		}
		cs, err := tx.Credentials().ListByUser(ctx, src.a.realm.ID, u.ID, passkeym.Name)
		if err != nil {
			return err
		}
		for _, c := range cs {
			_, d, err := passkeym.Read(ctx, tx, pii.New(src.e.deps.KeyStore), c)
			if err != nil {
				return err
			}
			datas = append(datas, d)
		}
		return nil
	}); err != nil || len(datas) != 2 {
		t.Fatalf("source passkeys: %d, %v", len(datas), err)
	}

	l := newPasskeyEnv(t)
	login, cookie := l.login(t, "legacy@example.com")
	pid := id.NewExternal(id.Passkey)
	if err := l.e.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, err := tx.Users().GetByPublicID(ctx, l.a.realm.ID, login["user_id"].(string))
		if err != nil {
			return err
		}
		now := l.e.deps.Clock.Now()
		for i, d := range datas {
			p := port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: u.RealmID, UserID: u.ID,
				CredentialID: d.CredentialID, PublicKey: d.PublicKey, Alg: d.Alg, SignCount: d.SignCount, Flags: d.Flags, AAGUID: d.AAGUID,
				Transports: d.Transports, Name: "Legacy", CreatedAt: now}
			if i == 0 {
				p.PublicID = pid // ハンドルは空（持ち主の公開 ID。移す前の登録と同じ）
			} else {
				p.UserHandle = []byte("old-handle")
			}
			if err := tx.Passkeys().Create(ctx, p); err != nil {
				return err
			}
			if i == 1 {
				if err := tx.Passkeys().Revoke(ctx, u.RealmID, p.ID, now, "revoked_by_user"); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// 認証器のハンドルは、移す前と同じ持ち主の公開 ID。
	matches := func(x *passkeytest.Authenticator) bool {
		for _, d := range datas[:1] {
			if string(d.CredentialID) == string(x.CredentialID) {
				return true
			}
		}
		return false
	}
	if !matches(a) {
		a, gone = gone, a
	}
	a.UserHandle = []byte(login["user_id"].(string))

	app, err := New(ctx, l.e.cfg, l.e.deps, feature.Registered())
	if err != nil {
		t.Fatal(err)
	}
	l.a = app
	if err := l.e.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if ps, _ := tx.Passkeys().ListAll(ctx, 10); len(ps) != 0 {
			t.Errorf("legacy passkeys left: %d", len(ps))
		}
		ledger, err := tx.Features().List(ctx)
		if err != nil || !slices.ContainsFunc(ledger, func(r port.FeatureRecord) bool { return r.Feature == credential.MigrationPasskeys }) {
			t.Errorf("ledger: %+v, %v", ledger, err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, res, pcookie := l.passkeyLogin(t, a)
	if status != 200 || res["user_id"] != login["user_id"] || pcookie == "" {
		t.Fatalf("login with migrated passkey: %d %v", status, res)
	}
	// 移した passkey は移す前の公開 ID のまま一覧に出て、名前を変えられる。
	if m := l.passkeys(t, cookie); len(m.Passkeys) != 1 || m.Passkeys[0].ID != pid {
		t.Fatalf("methods: %+v", m)
	}
	if status, res := l.mePost(t, cookie, "/v1/me/passkeys/"+pid+":rename", map[string]string{"name": "Renamed"}); status != 200 || res["name"] != "Renamed" {
		t.Fatalf("rename: %d %v", status, res)
	}
	// 移す前に無効化した credential ID は、移した後も再登録できない（4.6）。
	if status, res := l.registerPasskey(t, cookie, gone, ""); status != 409 || res["error"] != "passkey_revoked" {
		t.Fatalf("re-register revoked: %d %v", status, res)
	}
}
