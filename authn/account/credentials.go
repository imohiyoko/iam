package account

import (
	"context"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 汎用の認証情報（認証方式のプラグイン。ADR 0090、0092）の無効化。削除せず revoked_* を記録する（4.6）。

// credential は公開 ID の、ユーザーの有効な汎用の認証情報を返す。無ければ errs.NotFound。
func credential(ctx context.Context, tx port.Tx, realmID, userID, publicID string) (port.Credential, error) {
	c, err := tx.Credentials().GetByPublicID(ctx, realmID, publicID)
	if err == nil && (c.UserID != userID || c.RevokedAt != nil) {
		err = errs.New(errs.KindNotFound, "credential")
	}
	return c, err
}

// RevokeCredential は本人が汎用の認証情報を無効化する。1要素目に使える方式の、最後のログインの手段なら ErrLastMethod。
// 方式が動いていれば、無効化の前に方式の Revoke を呼ぶ（エラーなら無効化しない）。その認証情報で作ったセッションは、次の検証
// （遅くとも validity_max_delay の後）から使えない。
func (s *Service) RevokeCredential(ctx context.Context, tx port.Tx, realmID, userID, publicID string, actor audit.Actor, requestID string) (port.Credential, error) {
	c, err := credential(ctx, tx, realmID, userID, publicID)
	if err != nil {
		return port.Credential{}, err
	}
	if s.Methods.Supports(c.Method, port.UsageFirstFactor) {
		m, err := s.ListMethods(ctx, tx, realmID, userID)
		if err != nil {
			return port.Credential{}, err
		}
		if s.loginMethods(m) <= 1 {
			return port.Credential{}, ErrLastMethod
		}
	}
	now := s.Clock.Now()
	if a, ok := s.Methods.Get(c.Method); ok {
		mc, err := method.Open(ctx, tx, s.Crypter, c)
		if err != nil {
			return port.Credential{}, err
		}
		env := port.MethodEnv{RealmID: realmID, UserID: userID, Now: now,
			Credentials: &method.Store{Tx: tx, Crypter: s.Crypter, RealmID: realmID, Info: a.Info(), Now: now}}
		if err := a.Revoke(ctx, env, mc); err != nil {
			return port.Credential{}, err
		}
	}
	if err := tx.Credentials().Revoke(ctx, realmID, c.ID, now, ReasonRevokedByUser); err != nil {
		return port.Credential{}, err
	}
	return c, s.record(ctx, tx, realmID, "credential.revoked", actor, requestID,
		map[string]any{"credential_id": c.PublicID, "method": c.Method, "reason": ReasonRevokedByUser})
}

// adminRevokeCredential は運営者が汎用の認証情報を無効化する。方式の Revoke は呼ばない（方式の都合で止められないように）。
func (s *Service) adminRevokeCredential(ctx context.Context, tx port.Tx, realmID string, u port.User, publicID string, actor audit.Actor, requestID string) error {
	c, err := credential(ctx, tx, realmID, u.ID, publicID)
	if err != nil {
		return err
	}
	if err := tx.Credentials().Revoke(ctx, realmID, c.ID, s.Clock.Now(), ReasonRevokedByAdmin); err != nil {
		return err
	}
	return s.record(ctx, tx, realmID, "credential.revoked", actor, requestID,
		map[string]any{"user_id": u.PublicID, "credential_id": c.PublicID, "method": c.Method, "reason": ReasonRevokedByAdmin})
}
