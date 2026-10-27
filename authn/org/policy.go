package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Org のログインポリシー（design.md 4.4、4.9、フィーチャー org_login_policy、ADR 0069）。
//
// 入場の条件で、ログインと Org の切り替えのときに判定する。満たさなければその Org に入れず、理由は policy.<type>
// （ログインは個人 Org などで成功する）。ポリシーは Org の設定（orgs.settings の login_policy）に持つ。個人 Org には無い。

// PolicyFeature は Org のログインポリシーの宣言（features/orgloginpolicy が登録する）。
var PolicyFeature = feature.Feature{Name: feature.OrgLoginPolicy, DataVersion: 1, Requires: []string{feature.Org}}

// ログインポリシーの種類（拒否理由は "policy." + 種類）。
const (
	PolicyRequirePasskey        = "require_passkey"
	PolicyMembershipEmailDomain = "membership_email_domain"
	PolicyIPAllowlist           = "ip_allowlist"
	// PolicyRequireSSO はその Org の connection（Org 専用 SSO。ADR 0077）での認証。フィーチャー org_managed_users も要る。
	PolicyRequireSSO = "require_sso"
)

// 上限。
const (
	MaxPolicyDomains = 50
	MaxPolicyCIDRs   = 100
)

// LoginPolicy は Org のログインポリシー。空の項目は判定しない。
type LoginPolicy struct {
	// RequirePasskey は passkey（amr の hwk）で本人確認したセッションだけを入れる。
	RequirePasskey bool `json:"require_passkey,omitempty"`
	// MembershipEmailDomains は Membership に結び付けたメール（無ければ primary）のドメインがこのどれかであること。
	MembershipEmailDomains []string `json:"membership_email_domains,omitempty"`
	// IPAllowlist はログイン・切り替えの要求の IP がこのどれか（CIDR）に入ること。
	IPAllowlist []string `json:"ip_allowlist,omitempty"`
	// RequireSSO はその Org の connection で認証したセッションだけを入れる（ADR 0077）。
	RequireSSO bool `json:"require_sso,omitempty"`
}

func (p *LoginPolicy) empty() bool {
	return p == nil || (!p.RequirePasskey && !p.RequireSSO && len(p.MembershipEmailDomains) == 0 && len(p.IPAllowlist) == 0)
}

// checkPolicy は設定しようとするポリシーを確かめ、正規化したものを返す。
func (s *Service) checkPolicy(p *LoginPolicy) (*LoginPolicy, error) {
	if p.empty() {
		return nil, nil
	}
	if !s.LoginPolicies {
		return nil, settingInvalid("login_policy: the org_login_policy feature is not enabled")
	}
	if p.RequireSSO && !s.ManagedUsers {
		return nil, settingInvalid("login_policy.require_sso: the org_managed_users feature is not enabled")
	}
	out := &LoginPolicy{RequirePasskey: p.RequirePasskey, RequireSSO: p.RequireSSO}
	if len(p.MembershipEmailDomains) > MaxPolicyDomains || len(p.IPAllowlist) > MaxPolicyCIDRs {
		return nil, settingInvalid("login_policy: too many entries")
	}
	for _, d := range p.MembershipEmailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.ContainsAny(d, "@ /") || !strings.Contains(d, ".") || len(d) > 253 {
			return nil, settingInvalid("login_policy.membership_email_domains: invalid domain %q", d)
		}
		if !slices.Contains(out.MembershipEmailDomains, d) {
			out.MembershipEmailDomains = append(out.MembershipEmailDomains, d)
		}
	}
	for _, c := range p.IPAllowlist {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, settingInvalid("login_policy.ip_allowlist: invalid CIDR %q", c)
		}
		if v := pfx.Masked().String(); !slices.Contains(out.IPAllowlist, v) {
			out.IPAllowlist = append(out.IPAllowlist, v)
		}
	}
	return out, nil
}

// policyDenied はログイン・切り替えの要求 in が o のログインポリシーを満たすかを確かめ、満たさなければ
// 理由つきの *account.UnavailableError を返す。2要素目の前の段（Partial）では判定しない（完了のときに判定する）。
func (s *Service) policyDenied(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, in session.OrgPick) error {
	if !s.LoginPolicies || in.Partial || o.Kind == port.OrgPersonal || len(o.Settings) == 0 {
		return nil
	}
	st, err := SettingsOf(o)
	if err != nil || st.LoginPolicy.empty() {
		return err
	}
	p := st.LoginPolicy
	var codes []string
	if p.RequirePasskey && !slices.Contains(in.AuthMethods, passkey.AMRKey) {
		codes = append(codes, "policy."+PolicyRequirePasskey)
	}
	if len(p.MembershipEmailDomains) > 0 {
		ok, err := s.emailInDomains(ctx, tx, m, p.MembershipEmailDomains)
		if err != nil {
			return err
		}
		if !ok {
			codes = append(codes, "policy."+PolicyMembershipEmailDomain)
		}
	}
	if len(p.IPAllowlist) > 0 && !ipAllowed(in.IP, p.IPAllowlist) {
		codes = append(codes, "policy."+PolicyIPAllowlist)
	}
	if p.RequireSSO && s.ManagedUsers { // フィーチャーがオフなら判定しない（無効化の片付けで外す）
		ok, err := usedOrgConnection(ctx, tx, o, in.Credentials)
		if err != nil {
			return err
		}
		if !ok {
			codes = append(codes, "policy."+PolicyRequireSSO)
		}
	}
	if len(codes) == 0 {
		return nil
	}
	return &account.UnavailableError{Codes: codes}
}

// emailInDomains は Membership に結び付けたメール（無ければ primary）のドメインが domains のどれかかを返す。
// ドメインはブラインドインデックス（メールと同じインデックス鍵）で比べ、復号しない。
func (s *Service) emailInDomains(ctx context.Context, tx port.Tx, m port.Membership, domains []string) (bool, error) {
	es, err := tx.Emails().ListByUser(ctx, m.RealmID, m.UserID)
	if err != nil {
		return false, err
	}
	var e *port.UserEmail
	for i := range es {
		if (m.EmailID != "" && es[i].ID == m.EmailID) || (m.EmailID == "" && es[i].IsPrimary) {
			e = &es[i]
		}
	}
	if e == nil || e.VerifiedAt == nil || s.Crypter == nil {
		return false, nil
	}
	for _, d := range domains {
		ix, err := s.Crypter.IndexWith(ctx, e.IndexKeyID, "email_domain", d)
		if errors.Is(err, errs.NotFound) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("org policy: domain index: %w", err)
		}
		if slices.Equal(ix.Value, e.DomainIndex) {
			return true, nil
		}
	}
	return false, nil
}

// usedOrgConnection は、認証に使った認証情報（内部 ID）に o の connection の外部 ID があるかを返す。
func usedOrgConnection(ctx context.Context, tx port.Tx, o port.Org, credentials []string) (bool, error) {
	for _, c := range credentials {
		if !strings.HasPrefix(c, string(id.Identity)+"_") {
			continue
		}
		ident, err := tx.Identities().Get(ctx, o.RealmID, c)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		conn, err := tx.Connections().Get(ctx, o.RealmID, ident.ConnectionID)
		if errors.Is(err, errs.NotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		if conn.OwnerOrgID == o.ID && ident.RevokedAt == nil {
			return true, nil
		}
	}
	return false, nil
}

func ipAllowed(ip string, cidrs []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, c := range cidrs {
		if pfx, err := netip.ParsePrefix(c); err == nil && pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// HasLoginPolicy は Org の設定にログインポリシーがあるかを返す（フィーチャーの無効化で数える。11.12）。
func HasLoginPolicy(o port.Org) (bool, error) {
	st, err := SettingsOf(o)
	return !st.LoginPolicy.empty(), err
}

// ClearLoginPolicy は Org の設定からログインポリシーを外す（フィーチャーの無効化の片付け。11.12）。外したら true。
func ClearLoginPolicy(ctx context.Context, tx port.Tx, o port.Org, now time.Time) (bool, error) {
	st, err := SettingsOf(o)
	if err != nil || st.LoginPolicy.empty() {
		return false, err
	}
	st.LoginPolicy = nil
	var raw []byte
	if !st.empty() {
		if raw, err = json.Marshal(st); err != nil {
			return false, err
		}
	}
	return true, tx.Orgs().SetSettings(ctx, o.RealmID, o.ID, raw, now)
}

// HasRequireSSO は Org のログインポリシーに require_sso があるかを返す（org_managed_users の無効化で数える。11.12）。
func HasRequireSSO(o port.Org) (bool, error) {
	st, err := SettingsOf(o)
	return st.LoginPolicy != nil && st.LoginPolicy.RequireSSO, err
}

// ClearRequireSSO は Org のログインポリシーから require_sso を外す（org_managed_users の無効化の片付け。11.12）。外したら true。
func ClearRequireSSO(ctx context.Context, tx port.Tx, o port.Org, now time.Time) (bool, error) {
	st, err := SettingsOf(o)
	if err != nil || st.LoginPolicy == nil || !st.LoginPolicy.RequireSSO {
		return false, err
	}
	st.LoginPolicy.RequireSSO = false
	if st.LoginPolicy.empty() {
		st.LoginPolicy = nil
	}
	var raw []byte
	if !st.empty() {
		if raw, err = json.Marshal(st); err != nil {
			return false, err
		}
	}
	return true, tx.Orgs().SetSettings(ctx, o.RealmID, o.ID, raw, now)
}
