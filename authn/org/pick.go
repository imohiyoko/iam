package org

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Pick はログインで入る Org を決める（design.md 4.4、ADR 0057）。
//
//  1. 候補：active な Membership を持ち、Org と Membership が停止中でも有効期間の外でもなく、Org の段で deny にした警告に当たらない Org
//     （Check、warningsDenied。ログインポリシーは後で足す）
//     管理ユーザー（ADR 0076）は、管理する Org がこの条件を満たさなければログインそのものが失敗する
//  2. 明示的な指定があれば、それが候補にあること（所属が無ければ ErrNoAvailableOrg、使えなければ理由つきの *account.UnavailableError）。
//     Fallback なら、候補に無いときは指定が無いものとして 3 へ進む
//  3. ログインの手がかり（使ったメールや OAuth のアドレスを結び付けた Membership、passkey の既定の Org）に結び付いた候補。
//     1つならそれ。複数なら前回の Org がその中にあればそれ、無ければ選ばせる（Choices を返し、4 へ進む）
//  4. 前回の Org（最後に発行したセッションの Org）が候補にあればそれ
//  5. 個人 Org（無ければ作る）
func (s *Service) Pick(ctx context.Context, tx port.Tx, u port.User, in session.OrgPick) (session.PickedOrg, error) {
	ms, err := tx.Memberships().ListByUser(ctx, u.RealmID, u.ID)
	if err != nil {
		return session.PickedOrg{}, err
	}
	now := s.Clock.Now()
	var candidates []port.Membership
	for _, m := range ms {
		if m.Status != port.MembershipActive {
			continue
		}
		o, err := tx.Orgs().Get(ctx, u.RealmID, m.OrgID)
		if err != nil {
			return session.PickedOrg{}, err
		}
		_, err = Check(ctx, tx, o, m, now)
		if err == nil {
			// Org の段で deny にした警告に当たる認証では、その Org に入れない（ログインは成功する。10章）。
			err = s.warningsDenied(o, in.Warnings)
		}
		if err == nil {
			// ログインポリシーを満たさなければ、その Org に入れない（ログインは成功する。4.4）。
			err = s.policyDenied(ctx, tx, o, m, in)
		}
		// 管理ユーザーは、管理する Org に入れなければログインそのものができない（停止・ログインポリシー。ADR 0076。Fallback でも同じ）。
		if err != nil && ((m.OrgID == in.Explicit && !in.Fallback) || IsManaged(u, o)) {
			return session.PickedOrg{}, err
		}
		if _, ok := errors.AsType[*account.UnavailableError](err); ok {
			continue
		}
		if _, ok := errors.AsType[*warning.DeniedError](err); ok {
			continue
		}
		if err != nil {
			return session.PickedOrg{}, err
		}
		candidates = append(candidates, m)
	}
	has := func(orgID string) bool {
		return slices.ContainsFunc(candidates, func(m port.Membership) bool { return m.OrgID == orgID })
	}
	if in.Explicit != "" {
		if has(in.Explicit) {
			return session.PickedOrg{OrgID: in.Explicit}, nil
		}
		if !in.Fallback {
			return session.PickedOrg{}, ErrNoAvailableOrg
		}
	}
	hinted, err := s.hinted(ctx, tx, u, candidates, in)
	if err != nil {
		return session.PickedOrg{}, err
	}
	if len(hinted) == 1 {
		return session.PickedOrg{OrgID: hinted[0]}, nil
	}
	last, err := lastOrg(ctx, tx, u)
	if err != nil {
		return session.PickedOrg{}, err
	}
	var out session.PickedOrg
	if len(hinted) > 1 {
		if slices.Contains(hinted, last) {
			return session.PickedOrg{OrgID: last}, nil
		}
		for _, o := range hinted {
			org, err := tx.Orgs().Get(ctx, u.RealmID, o)
			if err != nil {
				return session.PickedOrg{}, err
			}
			out.Choices = append(out.Choices, org.PublicID)
		}
	}
	if last != "" && has(last) && len(hinted) == 0 {
		out.OrgID = last
		return out, nil
	}
	p, err := s.EnsurePersonal(ctx, tx, u, in.RequestID)
	if err != nil {
		return session.PickedOrg{}, err
	}
	out.OrgID = p.ID
	return out, nil
}

// hinted はログインの手がかりに結び付いた候補の Org（内部 ID、Membership の作成の順）を返す。
func (s *Service) hinted(ctx context.Context, tx port.Tx, u port.User, candidates []port.Membership, in session.OrgPick) ([]string, error) {
	emails := map[string]bool{}
	preferred := map[string]bool{}
	for _, c := range in.Credentials {
		switch {
		case strings.HasPrefix(c, string(id.Email)+"_"):
			emails[c] = true
		case strings.HasPrefix(c, string(id.Passkey)+"_"):
			ps, err := tx.Passkeys().ListByUser(ctx, u.RealmID, u.ID)
			if err != nil {
				return nil, err
			}
			for _, p := range ps {
				if p.ID == c && p.PreferredOrgID != "" {
					preferred[p.PreferredOrgID] = true
				}
			}
		}
	}
	if addr, err := account.NormalizeEmail(in.Email); err == nil && s.Crypter != nil {
		// OAuth のプロバイダが返したアドレスは、その場で HMAC を計算して本人のメールと照らす（4.4）。
		ix, err := s.Crypter.EmailIndex(ctx, addr)
		if err != nil {
			return nil, err
		}
		e, err := tx.Emails().GetByIndex(ctx, u.RealmID, ix.Value)
		switch {
		case err == nil && e.UserID == u.ID:
			emails[e.ID] = true
		case err != nil && !errors.Is(err, errs.NotFound):
			return nil, err
		}
	}
	var out []string
	for _, m := range candidates {
		if (m.EmailID != "" && emails[m.EmailID]) || preferred[m.OrgID] {
			out = append(out, m.OrgID)
		}
	}
	return out, nil
}

// lastOrg は最後に発行したセッションの Org（内部 ID）を返す。無ければ空。
func lastOrg(ctx context.Context, tx port.Tx, u port.User) (string, error) {
	ss, err := tx.Sessions().ListByPrincipal(ctx, u.RealmID, port.PrincipalUser, u.ID)
	if err != nil {
		return "", err
	}
	for _, s := range ss {
		if s.ActiveOrgID != "" {
			return s.ActiveOrgID, nil
		}
	}
	return "", nil
}
