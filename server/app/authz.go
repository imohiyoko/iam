package app

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可の判定（authz/check）の、authn 側の所属の問い合わせ（design.md 4.5、ADR 0064）。authz は authn を import しないので、
// ここで組み立てる。

// authzMembers は check.Members の実装。ユーザーの Membership が Org の可否（停止・有効期間・削除）の上で使える間、その
// org_role を返す。サービスアカウントの Org への所属は M4 では無い（使える所属は無い）。
type authzMembers struct{}

func (authzMembers) OrgRole(ctx context.Context, tx port.Tx, realmID string, p check.Principal, orgID string, now time.Time) (port.OrgRole, bool, error) {
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

func (authzMembers) OrgUsable(ctx context.Context, tx port.Tx, realmID, orgID string, now time.Time) (bool, error) {
	o, err := tx.Orgs().Get(ctx, realmID, orgID)
	if errors.Is(err, errs.NotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return org.Usable(ctx, tx, o, now)
}
