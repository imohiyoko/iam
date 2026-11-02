package storagetest

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func newPasskey(realmID, userID, credentialID string) port.Passkey {
	return port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: realmID, UserID: userID,
		CredentialID: []byte(credentialID), PublicKey: []byte("cose-key"), Alg: -7, SignCount: 0, Flags: 0x1d,
		AAGUID: make([]byte, 16), Transports: []string{"internal", "hybrid"}, Name: "Passkey", CreatedAt: T0,
		AttestationFormat: "packed", Attested: true}
}

// testLegacyPasskeys は、authn_credentials への移行（ADR 0106）で使う、方式専用の passkey の表の列挙と削除を確かめる。
func testLegacyPasskeys(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r1, r2, u := id.New(id.Realm), id.New(id.Realm), id.New(id.User)
	p := newPasskey(r1, u, "cred-1")
	p.UserHandle, p.PreferredOrgID = []byte("handle"), id.New(id.Org)
	bare := newPasskey(r2, u, "cred-2")
	// attestation を確かめていない行（ADR 0096 の前に登録したもの）。
	bare.AAGUID, bare.Transports, bare.AttestationFormat, bare.Attested = nil, nil, "", false
	at := T0.Add(time.Hour)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Passkeys()
		for _, x := range []port.Passkey{p, bare} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if err := conflict("same credential id", repo.Create(ctx, newPasskey(r1, id.New(id.User), "cred-1"))); err != nil {
			return err
		}
		dup := newPasskey(r1, u, "cred-x")
		dup.PublicID = p.PublicID
		if err := conflict("same public id", repo.Create(ctx, dup)); err != nil {
			return err
		}
		all, err := repo.ListAll(ctx, 10)
		if err != nil || len(all) != 2 {
			return fmt.Errorf("passkeys.ListAll = %+v, %v", all, err)
		}
		want := map[string]port.Passkey{p.ID: p, bare.ID: bare}
		for _, x := range all {
			w := want[x.ID]
			if w.ID == bare.ID {
				w.AAGUID, w.Transports = x.AAGUID, x.Transports
				if len(x.AAGUID) != 0 || len(x.Transports) != 0 {
					return fmt.Errorf("bare passkey = %+v", x)
				}
			}
			if !reflect.DeepEqual(x, w) {
				return fmt.Errorf("passkeys.ListAll %s = %+v, want %+v", x.ID, x, w)
			}
		}
		if all[0].ID > all[1].ID {
			return fmt.Errorf("passkeys.ListAll is not in id order")
		}
		if first, err := repo.ListAll(ctx, 1); err != nil || len(first) != 1 || first[0].ID != all[0].ID {
			return fmt.Errorf("passkeys.ListAll(1) = %+v, %v", first, err)
		}
		// 無効化は credential ID を無効化済みに残す。2度目は何もしない。別の realm・無いものは NotFound。
		if err := repo.Revoke(ctx, r1, p.ID, at, "revoked_by_user"); err != nil {
			return err
		}
		if err := repo.Revoke(ctx, r1, p.ID, at.Add(time.Hour), "again"); err != nil {
			return err
		}
		for name, err := range map[string]error{
			"revoke in another realm": repo.Revoke(ctx, r2, p.ID, at, "x"),
			"revoke missing":          repo.Revoke(ctx, r1, id.New(id.Passkey), at, "x"),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		all, err = repo.ListAll(ctx, 10)
		if err != nil {
			return err
		}
		for _, x := range all {
			if x.ID == p.ID && (x.RevokedAt == nil || !x.RevokedAt.Equal(at) || x.RevokeReason != "revoked_by_user") {
				return fmt.Errorf("revoked passkey = %+v", x)
			}
		}
		rv, err := repo.ListRevoked(ctx, 10)
		if err != nil || len(rv) != 1 || rv[0].RealmID != r1 || !bytes.Equal(rv[0].CredentialID, p.CredentialID) || !rv[0].RevokedAt.Equal(at) {
			return fmt.Errorf("passkeys.ListRevoked = %+v, %v", rv, err)
		}
		// 消す：別の realm の ID では消さない。無いものは何もしない。
		for _, err := range []error{repo.Delete(ctx, r2, p.ID), repo.Delete(ctx, r1, id.New(id.Passkey)), repo.Delete(ctx, r1, p.ID),
			repo.DeleteRevoked(ctx, r2, p.CredentialID), repo.DeleteRevoked(ctx, r1, []byte("none"))} {
			if err != nil {
				return err
			}
		}
		if left, err := repo.ListAll(ctx, 10); err != nil || len(left) != 1 || left[0].ID != bare.ID {
			return fmt.Errorf("passkeys after delete = %+v, %v", left, err)
		}
		if rv, err := repo.ListRevoked(ctx, 10); err != nil || len(rv) != 1 {
			return fmt.Errorf("revoked after delete in another realm = %+v, %v", rv, err)
		}
		if err := repo.DeleteRevoked(ctx, r1, p.CredentialID); err != nil {
			return err
		}
		if rv, err := repo.ListRevoked(ctx, 10); err != nil || len(rv) != 0 {
			return fmt.Errorf("revoked after delete = %+v, %v", rv, err)
		}
		return nil
	})
}

// testRetiredLookups は、退役した検索キー（ADR 0106）と、認証情報の Org の指定を確かめる。
func testRetiredLookups(t *testing.T, h Harness) {
	s, _ := open(t, h)
	r := id.New(id.Realm)
	owner := newUser(r)
	u := owner.ID
	keep := newCredential(r, u, "passkey", []byte("cred-1"))
	keep.ReserveLookup, keep.LookupKeyID = true, "ik_1"
	plain := newCredential(r, u, "x509", []byte("cert-1"))
	at := T0.Add(time.Hour)
	tx(t, s, func(ctx context.Context, tx port.Tx) error {
		repo := tx.Credentials()
		for _, x := range []port.Credential{keep, plain} {
			if err := repo.Create(ctx, x); err != nil {
				return err
			}
		}
		if got, err := repo.Get(ctx, r, keep.ID); err != nil || !got.ReserveLookup || got.PreferredOrgID != "" {
			return fmt.Errorf("reserved credential = %+v, %v", got, err)
		}
		org := id.New(id.Org)
		if err := repo.SetPreferredOrg(ctx, r, keep.ID, org); err != nil {
			return err
		}
		if got, err := repo.Get(ctx, r, keep.ID); err != nil || got.PreferredOrgID != org {
			return fmt.Errorf("preferred org = %+v, %v", got, err)
		}
		for name, err := range map[string]error{
			"org in another realm": repo.SetPreferredOrg(ctx, id.New(id.Realm), keep.ID, ""),
			"org of missing":       repo.SetPreferredOrg(ctx, r, id.New(id.Credential), ""),
		} {
			if err := notFound(name, err); err != nil {
				return err
			}
		}
		// 無効化：印のあるものは検索キーを退役させ、同じ方式では作り直せない。印の無いものは作り直せる。
		for _, x := range []port.Credential{keep, plain} {
			if err := repo.Revoke(ctx, r, x.ID, at, "revoked_by_user"); err != nil {
				return err
			}
		}
		if ok, err := repo.LookupRetired(ctx, r, "passkey", []byte("cred-1")); err != nil || !ok {
			return fmt.Errorf("retired = %v, %v", ok, err)
		}
		for name, q := range map[string][3]string{"plain": {r, "x509", "cert-1"}, "other method": {r, "x509", "cred-1"},
			"other realm": {id.New(id.Realm), "passkey", "cred-1"}, "other value": {r, "passkey", "cred-2"}} {
			if ok, err := repo.LookupRetired(ctx, q[0], q[1], []byte(q[2])); err != nil || ok {
				return fmt.Errorf("%s retired = %v, %v", name, ok, err)
			}
		}
		if ok, err := repo.LookupRetired(ctx, r, "passkey", nil); err != nil || ok {
			return fmt.Errorf("empty lookup retired = %v, %v", ok, err)
		}
		if err := conflict("re-create retired", repo.Create(ctx, newCredential(r, id.New(id.User), "passkey", []byte("cred-1")))); err != nil {
			return err
		}
		// 無効化した行としてなら作れる（移行で履歴を写す）。
		hist := newCredential(r, u, "passkey", []byte("cred-1"))
		hist.RevokedAt = &at
		if err := repo.Create(ctx, hist); err != nil {
			return fmt.Errorf("revoked history: %w", err)
		}
		for _, x := range []port.Credential{newCredential(r, u, "x509", []byte("cert-1")), newCredential(r, u, "other", []byte("cred-1"))} {
			if err := repo.Create(ctx, x); err != nil {
				return fmt.Errorf("create %s: %w", x.Method, err)
			}
		}
		// Retire は重ねても何もしない。空の検索キーは誤り。
		if err := repo.Retire(ctx, port.RetiredLookup{RealmID: r, Method: "passkey", Lookup: []byte("cred-1"), LookupKeyID: "ik_other", RetiredAt: at}); err != nil {
			return err
		}
		if err := repo.Retire(ctx, port.RetiredLookup{RealmID: r, Method: "passkey", Lookup: []byte("cred-9"), LookupKeyID: "ik_0", RetiredAt: at}); err != nil {
			return err
		}
		if err := repo.Retire(ctx, port.RetiredLookup{RealmID: r, Method: "passkey", RetiredAt: at}); err == nil {
			return fmt.Errorf("retire of an empty lookup succeeded")
		}
		if ids, err := repo.RetiredLookupKeyIDs(ctx, r, "passkey"); err != nil || !slices.Equal(ids, []string{"ik_0", "ik_1"}) {
			return fmt.Errorf("retired key ids = %v, %v", ids, err)
		}
		if ids, err := repo.RetiredLookupKeyIDs(ctx, r, "x509"); err != nil || len(ids) != 0 {
			return fmt.Errorf("retired key ids of x509 = %v, %v", ids, err)
		}
		// 持ち主を消しても退役は残る（4.6）。
		if err := tx.Users().Create(ctx, owner); err != nil {
			return err
		}
		if err := tx.Users().Erase(ctx, r, u, at); err != nil {
			return err
		}
		if ok, err := repo.LookupRetired(ctx, r, "passkey", []byte("cred-1")); err != nil || !ok {
			return fmt.Errorf("retired after erase = %v, %v", ok, err)
		}
		return nil
	})
}

var passkeyIsolationCase = IsolationCase{
	Name: "Credentials.LookupRetired+RetiredLookupKeyIDs",
	Seed: func(ctx context.Context, tx port.Tx, _ clock.Clock, r string) error {
		return tx.Credentials().Retire(ctx, port.RetiredLookup{RealmID: r, Method: "passkey", Lookup: []byte("iso-cred"), LookupKeyID: "ik_iso", RetiredAt: T0})
	},
	Query: func(ctx context.Context, tx port.Tx, r string) (int, error) {
		ok, err := tx.Credentials().LookupRetired(ctx, r, "passkey", []byte("iso-cred"))
		if err != nil {
			return 0, err
		}
		n := 0
		if ok {
			n++
		}
		ids, err := tx.Credentials().RetiredLookupKeyIDs(ctx, r, "passkey")
		return n + len(ids), err
	},
}
