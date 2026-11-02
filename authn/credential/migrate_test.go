package credential_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	pwm "github.com/imohiyoko/iam/authn/method/password"
	totpm "github.com/imohiyoko/iam/authn/method/totp"
	"github.com/imohiyoko/iam/internal/testkit"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

func TestMigrateLegacy(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	u, v := k.SeedUser(t), k.SeedUser(t)
	secret := []byte("12345678901234567890")
	revokedAt := k.Clock.Now().Add(-time.Hour)
	live := port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: k.RealmID, UserID: u.ID, LastUsedStep: 42,
		CreatedAt: k.Clock.Now().Add(-2 * time.Hour)}
	old := port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: k.RealmID, UserID: v.ID, LastUsedStep: 7,
		CreatedAt: k.Clock.Now().Add(-3 * time.Hour), RevokedAt: &revokedAt, RevokeReason: "revoked_by_user"}
	pw := port.PasswordCredential{ID: id.New(id.Password), RealmID: k.RealmID, UserID: u.ID, Hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		CreatedAt: k.Clock.Now().Add(-time.Minute)}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		for _, c := range []*port.TOTPCredential{&live, &old} {
			ct, err := k.Crypter.Encrypt(ctx, tx.DataKeys(), c.UserID, secret, totpm.LegacySecretAAD)
			if err != nil {
				return err
			}
			c.SecretCiphertext = ct
			if err := tx.TOTP().Create(ctx, *c); err != nil {
				return err
			}
		}
		return tx.Passwords().Create(ctx, pw)
	})

	m, err := credential.MigrateLegacy(ctx, k.Storage, k.Crypter, k.Clock, 1)
	if err != nil || m != (credential.Migrated{TOTP: 2, Passwords: 1}) {
		t.Fatalf("migrate = %+v, %v", m, err)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if ts, _ := tx.TOTP().ListAll(ctx, 10); len(ts) != 0 {
			t.Errorf("legacy totp left: %d", len(ts))
		}
		if ps, _ := tx.Passwords().ListAll(ctx, 10); len(ps) != 0 {
			t.Errorf("legacy passwords left: %d", len(ps))
		}
		// TOTP は ID と公開 ID を保ち、秘密と使った窓を方式のデータとして持つ。
		c, err := tx.Credentials().GetByPublicID(ctx, k.RealmID, live.PublicID)
		if err != nil || c.ID != live.ID || c.Method != "totp" || c.UserID != u.ID || !c.CreatedAt.Equal(live.CreatedAt) || c.RevokedAt != nil {
			t.Fatalf("migrated totp = %+v, %v", c, err)
		}
		mc, err := method.Open(ctx, tx, k.Crypter, c)
		if err != nil {
			return err
		}
		var d totpm.Data
		if err := json.Unmarshal(mc.Data, &d); err != nil || !bytes.Equal(d.Secret, secret) || d.LastStep != 42 {
			t.Fatalf("totp data = %+v, %v", d, err)
		}
		r, err := tx.Credentials().Get(ctx, k.RealmID, old.ID)
		if err != nil || r.RevokedAt == nil || !r.RevokedAt.Equal(revokedAt) || r.RevokeReason != "revoked_by_user" {
			t.Fatalf("revoked totp = %+v, %v", r, err)
		}
		p, err := tx.Credentials().Get(ctx, k.RealmID, pw.ID)
		if err != nil || p.Method != "password" || p.PublicID == "" {
			t.Fatalf("migrated password = %+v, %v", p, err)
		}
		pc, err := method.Open(ctx, tx, k.Crypter, p)
		if err != nil {
			return err
		}
		if h, err := pwm.HashOf(pc); err != nil || h != pw.Hash {
			t.Fatalf("password hash = %q, %v", h, err)
		}
		ledger, err := tx.Features().List(ctx)
		if err != nil || len(ledger) != 1 || ledger[0].Feature != credential.MigrationTOTPPassword || !feature.IsMigration(ledger[0].Feature) {
			t.Fatalf("ledger = %+v, %v", ledger, err)
		}
		return nil
	})
	// もう一度呼んでも何もしない（起動のたび）。
	if m, err := credential.MigrateLegacy(ctx, k.Storage, k.Crypter, k.Clock, 0); err != nil || m != (credential.Migrated{}) {
		t.Fatalf("second run = %+v, %v", m, err)
	}
}

// 秘密を戻せなければ（データ鍵が無いなど）、移さずに止まる（fail-closed）。古い行は残る。
func TestMigrateLegacyFailsClosed(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	u := k.SeedUser(t)
	c := port.TOTPCredential{ID: id.New(id.TOTP), PublicID: id.NewExternal(id.TOTP), RealmID: k.RealmID, UserID: u.ID,
		SecretCiphertext: []byte("not a ciphertext"), CreatedAt: k.Clock.Now()}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.TOTP().Create(ctx, c) })
	if _, err := credential.MigrateLegacy(ctx, k.Storage, k.Crypter, k.Clock, 10); err == nil {
		t.Fatal("migrated an undecryptable secret")
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if ts, _ := tx.TOTP().ListAll(ctx, 10); len(ts) != 1 {
			t.Errorf("legacy row removed: %d", len(ts))
		}
		if ledger, _ := tx.Features().List(ctx); len(ledger) != 0 {
			t.Errorf("ledger recorded: %+v", ledger)
		}
		return nil
	})
}
