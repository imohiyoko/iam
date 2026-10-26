package account

import (
	"context"
	"errors"
	"strings"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 運営者による認証情報の無効化（design.md 4.6）。本人と違い、最後の1つも無効化できる（以後は復旧の手順で戻る）。
// 削除せず revoked_* を記録し、取り消せない。

// 運営者による無効化の理由。
const (
	ReasonRevokedByAdmin = "revoked_by_admin"
	// ReasonCompromised は侵害の疑いでの一括の無効化。
	ReasonCompromised = "compromised"
)

// Revoked は一括の無効化で無効化した数。
type Revoked struct {
	Passkeys, Identities, TOTP int
	Password                   bool
}

// AdminRevokeCredential はユーザーの passkey・外部 ID の紐付け・TOTP を公開 ID（psk_ / idn_ / otp_）で
// 無効化する。そのユーザーの有効なものでなければ errs.NotFound。その認証情報で作ったセッションは、次の検証
// （遅くとも validity_max_delay の後）から使えない。
func (s *Service) AdminRevokeCredential(ctx context.Context, tx port.Tx, realmID string, u port.User, publicID string, actor audit.Actor, requestID string) error {
	now := s.Clock.Now()
	switch prefix, _, _ := strings.Cut(publicID, "_"); prefix {
	case string(id.Passkey):
		p, err := passkey(ctx, tx, realmID, u.ID, publicID)
		if err != nil {
			return err
		}
		if err := tx.Passkeys().Revoke(ctx, realmID, p.ID, now, ReasonRevokedByAdmin); err != nil {
			return err
		}
		return s.record(ctx, tx, realmID, "passkey.revoked", actor, requestID, map[string]any{"user_id": u.PublicID, "passkey_id": p.PublicID, "reason": ReasonRevokedByAdmin})
	case string(id.Identity):
		i, err := tx.Identities().GetByPublicID(ctx, realmID, publicID)
		if err == nil && (i.UserID != u.ID || i.RevokedAt != nil) {
			err = errs.New(errs.KindNotFound, "identity")
		}
		if err != nil {
			return err
		}
		if err := tx.Identities().Revoke(ctx, realmID, i.ID, now, ReasonRevokedByAdmin); err != nil {
			return err
		}
		return s.record(ctx, tx, realmID, "identity.unlinked", actor, requestID,
			map[string]any{"user_id": u.PublicID, "identity_id": i.PublicID, "connection_id": i.ConnectionID, "reason": ReasonRevokedByAdmin})
	case string(id.TOTP):
		c, err := tx.TOTP().GetByPublicID(ctx, realmID, publicID)
		if err == nil && (c.UserID != u.ID || c.RevokedAt != nil) {
			err = errs.New(errs.KindNotFound, "totp")
		}
		if err != nil {
			return err
		}
		if err := tx.TOTP().Revoke(ctx, realmID, c.ID, now, ReasonRevokedByAdmin); err != nil {
			return err
		}
		return s.record(ctx, tx, realmID, "totp.revoked", actor, requestID, map[string]any{"user_id": u.PublicID, "totp_id": c.PublicID, "reason": ReasonRevokedByAdmin})
	}
	return errs.New(errs.KindNotFound, "credential")
}

// AdminRevokePassword はユーザーのパスワードを無効化する（再設定は復旧の手順で行う）。無ければ errs.NotFound。
// 呼び出し側はユーザーの全セッションを失効させる。
func (s *Service) AdminRevokePassword(ctx context.Context, tx port.Tx, realmID string, u port.User, actor audit.Actor, requestID string) error {
	c, err := tx.Passwords().GetActive(ctx, realmID, u.ID)
	if err != nil {
		return err
	}
	if err := tx.Passwords().Revoke(ctx, realmID, c.ID, s.Clock.Now(), ReasonRevokedByAdmin); err != nil {
		return err
	}
	return s.record(ctx, tx, realmID, "password.removed", actor, requestID, map[string]any{"user_id": u.PublicID, "reason": ReasonRevokedByAdmin})
}

// RevokeAllCredentials は侵害時の初動として、ユーザーの passkey・外部 ID の紐付け・TOTP・パスワードをすべて無効化する。
// メールは残す（復旧の経路。4.12）。呼び出し側はユーザーの全セッションを失効させる。
func (s *Service) RevokeAllCredentials(ctx context.Context, tx port.Tx, realmID string, u port.User, actor audit.Actor, requestID string) (Revoked, error) {
	m, err := s.ListMethods(ctx, tx, realmID, u.ID)
	if err != nil {
		return Revoked{}, err
	}
	now := s.Clock.Now()
	var out Revoked
	for _, p := range m.Passkeys {
		if err := tx.Passkeys().Revoke(ctx, realmID, p.ID, now, ReasonCompromised); err != nil {
			return Revoked{}, err
		}
		out.Passkeys++
	}
	for _, i := range m.Identities {
		if err := tx.Identities().Revoke(ctx, realmID, i.ID, now, ReasonCompromised); err != nil {
			return Revoked{}, err
		}
		out.Identities++
	}
	for _, c := range m.TOTP {
		if err := tx.TOTP().Revoke(ctx, realmID, c.ID, now, ReasonCompromised); err != nil {
			return Revoked{}, err
		}
		out.TOTP++
	}
	if m.Password != nil {
		if err := tx.Passwords().Revoke(ctx, realmID, m.Password.ID, now, ReasonCompromised); err != nil && !errors.Is(err, errs.NotFound) {
			return Revoked{}, err
		}
		out.Password = true
	}
	return out, s.record(ctx, tx, realmID, "credentials.revoked_all", actor, requestID, map[string]any{
		"user_id": u.PublicID, "passkeys": out.Passkeys, "identities": out.Identities, "totp": out.TOTP, "password": out.Password, "reason": ReasonCompromised,
	})
}
