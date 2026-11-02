package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/imohiyoko/iam/authn/method"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
	pwm "github.com/imohiyoko/iam/authn/method/password"
	totpm "github.com/imohiyoko/iam/authn/method/totp"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// MigrationTOTPPassword は、TOTP とパスワードを方式専用の表から authn_credentials へ移したことの台帳の記録（ADR 0101）。
// 移す前のバイナリは、この記録を知らないので起動を拒む（移した後の DB では、TOTP とパスワードが見えなくなるため）。
const MigrationTOTPPassword = feature.MigrationPrefix + "authn_credentials_totp_password"

func init() { feature.RegisterMigration(MigrationTOTPPassword) }

// Migrated は移した件数。
type Migrated struct{ TOTP, Passwords int }

// MigrateLegacy は方式専用の表（authn_totp_credentials・authn_password_credentials）の行を、無効化したものも含めて
// authn_credentials へ移す（ADR 0101）。1行ずつ、同じトランザクションで作って古い行を消すので、途中で止まっても続きから
// やり直せる。起動のたびに呼び、移す前のバイナリが（移行の途中で）書いた行も拾う。終わったら台帳に記録する。
//
// TOTP は内部 ID と公開 ID（otp_）を保つ（セッションの結び付きと、方式専用のパスの無効化が続けて効く）。秘密はユーザーの
// データ鍵で復号し、方式のデータとして暗号化し直す。パスワードは内部 ID（pwd_）を保ち、公開 ID（crd_）を新しく作る。
// 戻すときは、移す前に `iam storage export` で書き出したものを `iam storage import` で読み込む（0068）。
func MigrateLegacy(ctx context.Context, st port.Storage, crypter *pii.Crypter, clk clock.Clock, batch int) (Migrated, error) {
	if batch <= 0 {
		batch = 100
	}
	var out Migrated
	for {
		var n int
		err := st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			ts, err := tx.TOTP().ListAll(ctx, batch)
			if err != nil {
				return err
			}
			for _, t := range ts {
				if err := migrateTOTP(ctx, tx, crypter, t); err != nil {
					return fmt.Errorf("credential: migrate totp %s: %w", t.ID, err)
				}
			}
			n = len(ts)
			return nil
		})
		if err != nil {
			return out, err
		}
		if out.TOTP += n; n < batch {
			break
		}
	}
	for {
		var n int
		err := st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			ps, err := tx.Passwords().ListAll(ctx, batch)
			if err != nil {
				return err
			}
			for _, p := range ps {
				if err := migratePassword(ctx, tx, crypter, p); err != nil {
					return fmt.Errorf("credential: migrate password %s: %w", p.ID, err)
				}
			}
			n = len(ps)
			return nil
		})
		if err != nil {
			return out, err
		}
		if out.Passwords += n; n < batch {
			break
		}
	}
	err := st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ledger, err := tx.Features().List(ctx)
		if err != nil {
			return err
		}
		recorded := false
		for _, r := range ledger {
			recorded = recorded || r.Feature == MigrationTOTPPassword
		}
		if recorded && out == (Migrated{}) {
			return nil
		}
		if !recorded {
			if err := tx.Features().Put(ctx, port.FeatureRecord{Feature: MigrationTOTPPassword, State: port.FeatureActive, DataVersion: 1,
				UpdatedAt: clk.Now()}); err != nil {
				return err
			}
		}
		if out == (Migrated{}) {
			return nil // 移すものが無かった（新しい DB など）。
		}
		_, err = eventlog.Record(ctx, tx, clk, audit.Event{
			Type: "credentials.migrated", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"migration": MigrationTOTPPassword, "totp": out.TOTP, "passwords": out.Passwords},
		})
		return err
	})
	return out, err
}

func migrateTOTP(ctx context.Context, tx port.Tx, crypter *pii.Crypter, t port.TOTPCredential) error {
	secret, err := crypter.Decrypt(ctx, tx.DataKeys(), t.UserID, t.SecretCiphertext, totpm.LegacySecretAAD)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(totpm.Data{Secret: secret, LastStep: t.LastUsedStep}) // #nosec G117 -- ユーザーのデータ鍵で暗号化して置く
	if err != nil {
		return err
	}
	return moveLegacy(ctx, tx, crypter, port.Credential{ID: t.ID, PublicID: t.PublicID, RealmID: t.RealmID, UserID: t.UserID,
		Method: totpm.Name, DataVersion: 1, CreatedAt: t.CreatedAt, RevokedAt: t.RevokedAt, RevokeReason: t.RevokeReason}, raw,
		func() error { return tx.TOTP().Delete(ctx, t.RealmID, t.ID) })
}

func migratePassword(ctx context.Context, tx port.Tx, crypter *pii.Crypter, p port.PasswordCredential) error {
	raw, err := json.Marshal(pwm.Data{Hash: p.Hash})
	if err != nil {
		return err
	}
	return moveLegacy(ctx, tx, crypter, port.Credential{ID: p.ID, PublicID: id.NewExternal(id.Credential), RealmID: p.RealmID, UserID: p.UserID,
		Method: pwm.Name, DataVersion: 1, CreatedAt: p.CreatedAt, RevokedAt: p.RevokedAt, RevokeReason: p.RevokeReason}, raw,
		func() error { return tx.Passwords().Delete(ctx, p.RealmID, p.ID) })
}

// moveLegacy は c を、方式のデータ data を暗号化して作り、古い行を消す。
func moveLegacy(ctx context.Context, tx port.Tx, crypter *pii.Crypter, c port.Credential, data []byte, del func() error) error {
	ct, err := crypter.Encrypt(ctx, tx.DataKeys(), c.UserID, data, method.DataAAD(c.Method, c.ID))
	if err != nil {
		return err
	}
	c.Data = ct
	if err := tx.Credentials().Create(ctx, c); err != nil {
		return err
	}
	return del()
}

// MigrationPasskeys は、passkey を方式専用の表から authn_credentials へ移したことの台帳の記録（ADR 0106）。移す前のバイナリは、
// この記録を知らないので起動を拒む（移した後の DB では、passkey が見えなくなるため）。
const MigrationPasskeys = feature.MigrationPrefix + "authn_credentials_passkey"

func init() { feature.RegisterMigration(MigrationPasskeys) }

// MigratedPasskeys は移した件数。Retired は無効化済みの credential ID（退役した検索キーへ移したもの）。
type MigratedPasskeys struct{ Passkeys, Retired int }

// MigratePasskeys は方式専用の表（authn_passkeys・authn_revoked_passkey_credentials）の行を authn_credentials と
// authn_retired_credential_lookups へ移す（ADR 0106）。MigrateLegacy と同じく、1行ずつ同じトランザクションで作って古い行を消し、
// 起動のたびに呼び、終わったら台帳に記録する。
//
// passkey は内部 ID（psk_ の接頭辞のもの）と公開 ID を保つ（セッションの結び付き、方式専用のパスの名前の変更・無効化、Org の
// 指定が続けて効く）。credential ID は検索キー（ブラインドインデックス）にし、公開鍵・署名の回数・フラグ・名前・attestation の結果と、
// ユーザーハンドル（空なら持ち主の公開 ID）は方式のデータとして持ち主のデータ鍵で暗号化する。無効化した credential ID は、
// 持ち主を消した後のものも、退役した検索キーにする。データ鍵や持ち主が無ければ、移さずに起動を止める（fail-closed）。
func MigratePasskeys(ctx context.Context, st port.Storage, crypter *pii.Crypter, clk clock.Clock, batch int) (MigratedPasskeys, error) {
	if batch <= 0 {
		batch = 100
	}
	var out MigratedPasskeys
	for {
		var n int
		err := st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			ps, err := tx.Passkeys().ListAll(ctx, batch)
			if err != nil {
				return err
			}
			for _, p := range ps {
				if err := migratePasskey(ctx, tx, crypter, p); err != nil {
					return fmt.Errorf("credential: migrate passkey %s: %w", p.ID, err)
				}
			}
			n = len(ps)
			return nil
		})
		if err != nil {
			return out, err
		}
		if out.Passkeys += n; n < batch {
			break
		}
	}
	for {
		var n int
		err := st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			rs, err := tx.Passkeys().ListRevoked(ctx, batch)
			if err != nil {
				return err
			}
			for _, r := range rs {
				ix, err := crypter.Index(ctx, method.LookupPurpose(passkeym.Name), passkeym.Lookup(r.CredentialID))
				if err != nil {
					return fmt.Errorf("credential: migrate revoked passkey: %w", err)
				}
				if err := tx.Credentials().Retire(ctx, port.RetiredLookup{RealmID: r.RealmID, Method: passkeym.Name, Lookup: ix.Value,
					LookupKeyID: ix.KeyID, RetiredAt: r.RevokedAt}); err != nil {
					return err
				}
				if err := tx.Passkeys().DeleteRevoked(ctx, r.RealmID, r.CredentialID); err != nil {
					return err
				}
			}
			n = len(rs)
			return nil
		})
		if err != nil {
			return out, err
		}
		if out.Retired += n; n < batch {
			break
		}
	}
	err := st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ledger, err := tx.Features().List(ctx)
		if err != nil {
			return err
		}
		recorded := slices.ContainsFunc(ledger, func(r port.FeatureRecord) bool { return r.Feature == MigrationPasskeys })
		if !recorded {
			if err := tx.Features().Put(ctx, port.FeatureRecord{Feature: MigrationPasskeys, State: port.FeatureActive, DataVersion: 1,
				UpdatedAt: clk.Now()}); err != nil {
				return err
			}
		}
		if out == (MigratedPasskeys{}) {
			return nil // 移すものが無かった（新しい DB など）。
		}
		_, err = eventlog.Record(ctx, tx, clk, audit.Event{
			Type: "credentials.migrated", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"migration": MigrationPasskeys, "passkeys": out.Passkeys, "retired": out.Retired},
		})
		return err
	})
	return out, err
}

func migratePasskey(ctx context.Context, tx port.Tx, crypter *pii.Crypter, p port.Passkey) error {
	handle := p.UserHandle
	if len(handle) == 0 {
		u, err := tx.Users().Get(ctx, p.RealmID, p.UserID)
		if err != nil {
			return err
		}
		handle = []byte(u.PublicID)
	}
	raw, err := passkeym.Encode(passkeym.Data{CredentialID: p.CredentialID, PublicKey: p.PublicKey, Alg: p.Alg, SignCount: p.SignCount,
		Flags: p.Flags, AAGUID: p.AAGUID, Transports: p.Transports, UserHandle: handle, Name: p.Name,
		AttestationFormat: p.AttestationFormat, Attested: p.Attested})
	if err != nil {
		return err
	}
	ix, err := crypter.Index(ctx, method.LookupPurpose(passkeym.Name), passkeym.Lookup(p.CredentialID))
	if err != nil {
		return err
	}
	return moveLegacy(ctx, tx, crypter, port.Credential{ID: p.ID, PublicID: p.PublicID, RealmID: p.RealmID, UserID: p.UserID,
		Method: passkeym.Name, Lookup: ix.Value, LookupKeyID: ix.KeyID, DataVersion: 1, PreferredOrgID: p.PreferredOrgID, ReserveLookup: true,
		CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt, RevokedAt: p.RevokedAt, RevokeReason: p.RevokeReason}, raw,
		func() error { return tx.Passkeys().Delete(ctx, p.RealmID, p.ID) })
}
