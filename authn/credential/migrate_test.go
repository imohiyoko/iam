package credential_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
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

// passkey の方式専用の表の行は、ID・公開 ID・ハンドルを保って authn_credentials へ移り、無効化した credential ID は
// 退役した検索キーへ移る（ADR 0106）。持ち主が消えた無効化済みの credential ID も残る。
func TestMigratePasskeys(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	u, v := k.SeedUser(t), k.SeedUser(t)
	used := k.Clock.Now().Add(-time.Minute)
	live := port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: k.RealmID, UserID: u.ID,
		CredentialID: []byte("cred-live"), PublicKey: []byte("cose"), Alg: -7, SignCount: 9, Flags: 0x1d, AAGUID: make([]byte, 16),
		Transports: []string{"usb"}, Name: "YubiKey", AttestationFormat: "packed", Attested: true,
		CreatedAt: k.Clock.Now().Add(-2 * time.Hour), LastUsedAt: &used}
	handled := port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: k.RealmID, UserID: v.ID,
		CredentialID: []byte("cred-handle"), PublicKey: []byte("cose"), Alg: -8, UserHandle: []byte("merged-handle"), Name: "Phone",
		CreatedAt: k.Clock.Now().Add(-time.Hour)}
	old := port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: k.RealmID, UserID: u.ID,
		CredentialID: []byte("cred-old"), PublicKey: []byte("cose"), Alg: -7, Name: "Old", CreatedAt: k.Clock.Now().Add(-3 * time.Hour)}
	revokedAt := k.Clock.Now().Add(-30 * time.Minute)
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		for _, p := range []port.Passkey{live, handled, old} {
			if err := tx.Passkeys().Create(ctx, p); err != nil {
				return err
			}
		}
		return tx.Passkeys().Revoke(ctx, k.RealmID, old.ID, revokedAt, "revoked_by_user")
	})

	m, err := credential.MigratePasskeys(ctx, k.Storage, k.Crypter, k.Clock, 1)
	if err != nil || m != (credential.MigratedPasskeys{Passkeys: 3, Retired: 1}) {
		t.Fatalf("migrate = %+v, %v", m, err)
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if ps, _ := tx.Passkeys().ListAll(ctx, 10); len(ps) != 0 {
			t.Errorf("legacy passkeys left: %d", len(ps))
		}
		if rs, _ := tx.Passkeys().ListRevoked(ctx, 10); len(rs) != 0 {
			t.Errorf("legacy revoked ids left: %d", len(rs))
		}
		c, err := tx.Credentials().GetByPublicID(ctx, k.RealmID, live.PublicID)
		if err != nil || c.ID != live.ID || c.Method != passkeym.Name || c.UserID != u.ID || !c.CreatedAt.Equal(live.CreatedAt) ||
			c.LastUsedAt == nil || !c.LastUsedAt.Equal(used) || !c.ReserveLookup || c.RevokedAt != nil {
			t.Fatalf("migrated passkey = %+v, %v", c, err)
		}
		_, d, err := passkeym.Read(ctx, tx, k.Crypter, c)
		if err != nil {
			return err
		}
		// ハンドルが無かったものは持ち主の公開 ID を持つ（それまでの検証と同じ値）。
		if !bytes.Equal(d.CredentialID, live.CredentialID) || d.SignCount != 9 || d.Flags != 0x1d || d.Name != "YubiKey" ||
			!d.Attested || d.AttestationFormat != "packed" || string(d.UserHandle) != u.PublicID || len(d.Transports) != 1 {
			t.Fatalf("passkey data = %+v", d)
		}
		ix, err := k.Crypter.Index(ctx, method.LookupPurpose(passkeym.Name), passkeym.Lookup(live.CredentialID))
		if err != nil {
			return err
		}
		if f, err := tx.Credentials().GetByLookup(ctx, k.RealmID, passkeym.Name, ix.Value); err != nil || f.ID != live.ID {
			t.Fatalf("lookup = %+v, %v", f, err)
		}
		h, err := tx.Credentials().Get(ctx, k.RealmID, handled.ID)
		if err != nil {
			return err
		}
		if _, d, err := passkeym.Read(ctx, tx, k.Crypter, h); err != nil || string(d.UserHandle) != "merged-handle" {
			t.Fatalf("handle = %q, %v", d.UserHandle, err)
		}
		r, err := tx.Credentials().Get(ctx, k.RealmID, old.ID)
		if err != nil || r.RevokedAt == nil || !r.RevokedAt.Equal(revokedAt) || r.RevokeReason != "revoked_by_user" {
			t.Fatalf("revoked passkey = %+v, %v", r, err)
		}
		oix, err := k.Crypter.Index(ctx, method.LookupPurpose(passkeym.Name), passkeym.Lookup(old.CredentialID))
		if err != nil {
			return err
		}
		if ok, err := tx.Credentials().LookupRetired(ctx, k.RealmID, passkeym.Name, oix.Value); err != nil || !ok {
			t.Fatalf("revoked credential id not retired: %v, %v", ok, err)
		}
		ledger, err := tx.Features().List(ctx)
		if err != nil || len(ledger) != 1 || ledger[0].Feature != credential.MigrationPasskeys || !feature.IsMigration(ledger[0].Feature) {
			t.Fatalf("ledger = %+v, %v", ledger, err)
		}
		return nil
	})
	if m, err := credential.MigratePasskeys(ctx, k.Storage, k.Crypter, k.Clock, 0); err != nil || m != (credential.MigratedPasskeys{}) {
		t.Fatalf("second run = %+v, %v", m, err)
	}
}

// 持ち主が見つからず（ハンドルが無く）移せない行があれば、止まる（fail-closed）。古い行は残り、台帳に記録しない。
func TestMigratePasskeysFailsClosed(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	p := port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: k.RealmID, UserID: "usr_missing",
		CredentialID: []byte("cred"), PublicKey: []byte("cose"), Alg: -7, CreatedAt: k.Clock.Now()}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error { return tx.Passkeys().Create(ctx, p) })
	if _, err := credential.MigratePasskeys(ctx, k.Storage, k.Crypter, k.Clock, 10); err == nil {
		t.Fatal("migrated a passkey without an owner")
	}
	k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		if ps, _ := tx.Passkeys().ListAll(ctx, 10); len(ps) != 1 {
			t.Errorf("legacy row removed: %d", len(ps))
		}
		if ledger, _ := tx.Features().List(ctx); len(ledger) != 0 {
			t.Errorf("ledger recorded: %+v", ledger)
		}
		return nil
	})
}
