package org_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func TestPick(t *testing.T) {
	k := testkit.New(t)
	s := &org.Service{Clock: k.Clock, Crypter: k.Crypter}
	u, other := k.SeedUser(t), k.SeedUser(t)
	pick := func(ctx context.Context, tx port.Tx, u port.User, in session.OrgPick) session.PickedOrg {
		t.Helper()
		got, err := s.Pick(ctx, tx, u, in)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		// 手がかりも前回も無ければ個人 Org。無ければ作り、2回目は同じものを返す。
		first := pick(ctx, tx, u, session.OrgPick{})
		if again := pick(ctx, tx, u, session.OrgPick{}); again.OrgID != first.OrgID || first.OrgID == "" {
			t.Fatalf("pick again = %+v (want %s)", again, first.OrgID)
		}
		shared, _, err := s.Create(ctx, tx, other, "Acme", false, audit.Actor{Type: "user"}, "")
		if err != nil {
			return err
		}
		// Membership の無い Org には入れない。
		if _, err := s.Pick(ctx, tx, u, session.OrgPick{Explicit: shared.ID}); !errors.Is(err, org.ErrNoAvailableOrg) {
			t.Fatalf("pick foreign org = %v", err)
		}
		if got := pick(ctx, tx, other, session.OrgPick{Explicit: shared.ID}); got.OrgID != shared.ID {
			t.Fatalf("pick own shared org = %+v", got)
		}
		return nil
	})
}

func TestPickByHints(t *testing.T) {
	k := testkit.New(t)
	s := &org.Service{Clock: k.Clock, Crypter: k.Crypter}
	u := k.SeedUser(t)
	work, a, b := id.New(id.Email), port.Org{}, port.Org{}
	var personal port.Org
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		var err error
		if personal, err = s.CreatePersonal(ctx, tx, u, audit.Actor{}, ""); err != nil {
			return err
		}
		ix, err := k.Crypter.EmailIndex(ctx, "pat@work.example")
		if err != nil {
			return err
		}
		if err := tx.Emails().Create(ctx, port.UserEmail{ID: work, PublicID: id.NewExternal(id.Email), RealmID: u.RealmID, UserID: u.ID,
			Index: ix.Value, IndexKeyID: ix.KeyID, VerifiedAt: new(k.Clock.Now()), CreatedAt: k.Clock.Now()}); err != nil {
			return err
		}
		for _, o := range []*port.Org{&a, &b} {
			var m port.Membership
			if *o, m, err = s.Create(ctx, tx, u, "Org", false, audit.Actor{}, ""); err != nil {
				return err
			}
			m.EmailID = work
			if err := tx.Memberships().Update(ctx, m); err != nil {
				return err
			}
		}
		return nil
	})
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		// 仕事用のメールが2つの Org に結び付いていて、前回の Org がどちらでもなければ選ばせる（入るのは個人 Org）。
		got, err := s.Pick(ctx, tx, u, session.OrgPick{Credentials: []string{work}})
		if err != nil || got.OrgID != personal.ID || len(got.Choices) != 2 {
			t.Fatalf("ambiguous hint = %+v, %v", got, err)
		}
		// OAuth のプロバイダが返したアドレスでも同じ。
		if got, _ := s.Pick(ctx, tx, u, session.OrgPick{Email: "Pat@Work.example"}); len(got.Choices) != 2 {
			t.Fatalf("oauth email hint = %+v", got)
		}
		// 前回の Org が手がかりの中にあればそれ。
		if err := tx.Sessions().Create(ctx, port.Session{ID: id.NewExternal(id.Session), RealmID: u.RealmID, PrincipalType: port.PrincipalUser,
			PrincipalID: u.ID, ActiveOrgID: b.ID, CreatedAt: k.Clock.Now(), LastSeenAt: k.Clock.Now(), ExpiresAt: k.Clock.Now().Add(time.Hour)}); err != nil {
			return err
		}
		if got, _ := s.Pick(ctx, tx, u, session.OrgPick{Credentials: []string{work}}); got.OrgID != b.ID || len(got.Choices) != 0 {
			t.Fatalf("hint with last = %+v", got)
		}
		// 手がかりが無ければ前回の Org。
		if got, _ := s.Pick(ctx, tx, u, session.OrgPick{}); got.OrgID != b.ID {
			t.Fatalf("last = %+v", got)
		}
		// passkey の既定の Org は1つに決まる。
		p := port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: u.RealmID, UserID: u.ID,
			CredentialID: []byte("cred"), PreferredOrgID: a.ID, CreatedAt: k.Clock.Now()}
		if err := tx.Passkeys().Create(ctx, p); err != nil {
			return err
		}
		if got, _ := s.Pick(ctx, tx, u, session.OrgPick{Credentials: []string{p.ID}}); got.OrgID != a.ID {
			t.Fatalf("passkey preferred org = %+v", got)
		}
		return nil
	})
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{" Acme ": "Acme", "株式会社": "株式会社"} {
		if got, err := org.NormalizeName(in); err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", " ", "a\tb", "\x00", string([]byte{0xff})} {
		if _, err := org.NormalizeName(in); !errors.Is(err, org.ErrNameInvalid) {
			t.Errorf("NormalizeName(%q) = %v", in, err)
		}
	}
}
