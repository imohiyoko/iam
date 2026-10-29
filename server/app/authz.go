package app

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可の判定（authz/check）の、authn 側の所属の問い合わせ（design.md 4.5、ADR 0064）。authz は authn を import しないので、
// ここで組み立てる。

// authzMembers は check.Members の実装。ユーザーの Membership が Org の可否（停止・有効期間・削除）の上で使える間、その
// org_role を返す。Org に属するサービスアカウント（11.2）は、それ自身と Org が使える間、その Org に所属する。
// サービスアカウントに org_role は無いので、Org の既定ロールは付かず、Org の範囲の付与と Org の Group だけが効く。
type authzMembers struct{}

func (authzMembers) OrgRole(ctx context.Context, tx port.Tx, realmID string, p check.Principal, orgID string, now time.Time) (port.OrgRole, bool, error) {
	if p.Type == port.PrincipalServiceAccount {
		ok, err := serviceAccountMember(ctx, tx, realmID, p.ID, orgID, now)
		return "", ok, err
	}
	if p.Type != port.PrincipalUser {
		return "", false, nil
	}
	m, err := tx.Memberships().GetByUserOrg(ctx, realmID, p.ID, orgID)
	if errors.Is(err, errs.NotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	o, err := tx.Orgs().Get(ctx, realmID, orgID)
	if err != nil {
		return "", false, err
	}
	if _, err := org.Check(ctx, tx, o, m, now); err != nil {
		if _, ok := errors.AsType[*account.UnavailableError](err); ok || errors.Is(err, org.ErrNoAvailableOrg) {
			return "", false, nil
		}
		return "", false, err
	}
	return m.Role, true, nil
}

// serviceAccountMember はサービスアカウント id が now に orgID（内部 ID）に所属して使えるかを返す。
func serviceAccountMember(ctx context.Context, tx port.Tx, realmID, id, orgID string, now time.Time) (bool, error) {
	sa, err := tx.ServiceAccounts().Get(ctx, realmID, id)
	if errors.Is(err, errs.NotFound) {
		return false, nil
	}
	if err != nil || sa.OrgID != orgID {
		return false, err
	}
	if err := serviceaccount.Available(ctx, tx, sa, now); err != nil {
		if _, ok := errors.AsType[*account.UnavailableError](err); ok || errors.Is(err, serviceaccount.ErrDeleted) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
