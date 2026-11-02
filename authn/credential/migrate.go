package credential

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/imohiyoko/iam/authn/method"
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
