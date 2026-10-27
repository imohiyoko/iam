package org_test

import (
	"context"
	"errors"
	"testing"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/port"
)

func TestPick(t *testing.T) {
	k := testkit.New(t)
	s := &org.Service{Clock: k.Clock}
	u, other := k.SeedUser(t), k.SeedUser(t)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		// 個人 Org が無ければ作り、2回目は同じものを返す。
		first, err := s.Pick(ctx, tx, u, "", "")
		if err != nil {
			return err
		}
		again, err := s.Pick(ctx, tx, u, "", "")
		if err != nil || again != first {
			t.Fatalf("pick again = %s, %v (want %s)", again, err, first)
		}
		shared, _, err := s.Create(ctx, tx, other, "Acme", false, audit.Actor{Type: "user"}, "")
		if err != nil {
			return err
		}
		// Membership の無い Org には入れない。
		if _, err := s.Pick(ctx, tx, u, shared.ID, ""); !errors.Is(err, org.ErrNoAvailableOrg) {
			t.Fatalf("pick foreign org = %v", err)
		}
		if got, err := s.Pick(ctx, tx, other, shared.ID, ""); err != nil || got != shared.ID {
			t.Fatalf("pick own shared org = %s, %v", got, err)
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
