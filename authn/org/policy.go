package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/passkey/attestation"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
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
	// PolicyPasskeyAuthenticator は、認証に使った passkey の認証器が Org の段の認証器のポリシーを満たすこと（ADR 0096）。
	// フィーチャー passkey_attestation も要る。
	PolicyPasskeyAuthenticator = "passkey_authenticator"
)

// EventPasskeyPolicyDenied は、Org の段の認証器のポリシーでその Org に入れなかったことの監査ログの種類（ADR 0096）。
const EventPasskeyPolicyDenied = "org.passkey_policy_denied"

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
	// Passkey は Org の段の認証器のポリシー（ADR 0096）。認証に使った passkey が realm の段に加えてこれも満たすこと。
	// passkey を使っていない認証には効かない（passkey を求めるなら RequirePasskey と組み合わせる）。
	Passkey *attestation.Policy `json:"passkey,omitempty"`
}

func (p *LoginPolicy) empty() bool {
	return p == nil || (!p.RequirePasskey && !p.RequireSSO && len(p.MembershipEmailDomains) == 0 && len(p.IPAllowlist) == 0 && p.Passkey.Empty())
}

// checkPolicy は設定しようとするポリシー p を確かめ、正規化したものを返す。フィーチャーが止まっていても、
// 保存済みのポリシー prev をそのまま残す更新は受ける（止めている間は判定しないが設定は残す。ADR 0069）。
func (s *Service) checkPolicy(p, prev *LoginPolicy) (*LoginPolicy, error) {
	if p.empty() {
		return nil, nil
	}
	out, err := normalizePolicy(p)
	if err != nil {
		return nil, err
	}
	if !s.LoginPolicies {
		if keep, err := normalizePolicy(prev); err == nil && !prev.empty() && reflect.DeepEqual(out, keep) {
			return out, nil
		}
		return nil, settingInvalid("login_policy: the org_login_policy feature is not enabled")
	}
	if out.RequireSSO && !s.ManagedUsers && (prev == nil || !prev.RequireSSO) {
		return nil, settingInvalid("login_policy.require_sso: the org_managed_users feature is not enabled")
	}
	if out.Passkey != nil && s.Passkeys == nil {
		if keep, err := normalizePolicy(prev); err != nil || keep == nil || !reflect.DeepEqual(out.Passkey, keep.Passkey) {
			return nil, settingInvalid("login_policy.passkey: the passkey_attestation feature is not enabled")
		}
	}
	return out, nil
}

func normalizePolicy(p *LoginPolicy) (*LoginPolicy, error) {
	if p.empty() {
		return nil, nil
	}
	out := &LoginPolicy{RequirePasskey: p.RequirePasskey, RequireSSO: p.RequireSSO}
	if len(p.MembershipEmailDomains) > MaxPolicyDomains || len(p.IPAllowlist) > MaxPolicyCIDRs {
		return nil, settingInvalid("login_policy: too many entries")
	}
	var err error
	if out.Passkey, err = attestation.Normalize(p.Passkey); err != nil {
		return nil, settingInvalid("login_policy.passkey: %s", err.Error())
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
		// 要求の IP は IPv4 に戻して比べる（ipAllowed）ので、IPv4-mapped の CIDR は IPv4 の CIDR に直す。
		if a := pfx.Addr(); a.Is4In6() {
			if pfx.Bits() < 96 {
				return nil, settingInvalid("login_policy.ip_allowlist: invalid CIDR %q", c)
			}
			pfx = netip.PrefixFrom(a.Unmap(), pfx.Bits()-96)
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
	if !p.Passkey.Empty() && s.Passkeys != nil { // フィーチャーがオフなら判定しない（無効化の片付けで外す）
		ok, err := s.passkeyAllowed(ctx, tx, o, m, p.Passkey, in)
		if err != nil {
			return err
		}
		if !ok {
			codes = append(codes, "policy."+PolicyPasskeyAuthenticator)
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

// passkeyAllowed は、認証に使った passkey（in.Credentials のうち passkey のもの）の認証器が、realm の段に加えて Org の段の
// ポリシー p も満たすかを返す（ADR 0096）。passkey を使っていなければ true。満たさなければ AAGUID と判定を監査ログに残す
// （ログインのトランザクションに書くので、ログインそのものが失敗すれば残らない。失敗は passkey の側で残す）。
func (s *Service) passkeyAllowed(ctx context.Context, tx port.Tx, o port.Org, m port.Membership, p *attestation.Policy, in session.OrgPick) (bool, error) {
	var ps []port.Passkey
	for _, c := range in.Credentials {
		if !strings.HasPrefix(c, string(id.Passkey)+"_") {
			continue
		}
		if ps == nil {
			var err error
			if ps, err = tx.Passkeys().ListByUser(ctx, o.RealmID, m.UserID); err != nil {
				return false, err
			}
		}
		for _, k := range ps {
			if k.ID != c {
				continue
			}
			d := s.Passkeys.Evaluate(s.Clock.Now(), k, attestation.Tiered{Tier: "org", Policy: p})
			if d.Allowed {
				continue
			}
			u, err := tx.Users().Get(ctx, o.RealmID, m.UserID)
			if err != nil {
				return false, err
			}
			details := d.Audit()
			details["passkey_id"] = k.PublicID
			_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
				Type: EventPasskeyPolicyDenied, Result: audit.ResultFailure, RealmID: o.RealmID, OrgID: o.PublicID,
				Actor: audit.Actor{Type: "user", ID: u.PublicID}, RequestID: in.RequestID, Details: details,
			})
			return false, err
		}
	}
	return true, nil
}

// RecordPasskeyDenied は、Org の切り替えが Org の段の認証器のポリシーで拒否されたときに、その判定を監査ログに残す
// （切り替えの拒否はトランザクションごと戻るため、別のトランザクションで判定し直して記録する。ADR 0096）。
func (s *Service) RecordPasskeyDenied(ctx context.Context, st port.Storage, realmID, sessionID, orgID, requestID string) error {
	if s.Passkeys == nil {
		return nil
	}
	return st.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		sess, err := tx.Sessions().Get(ctx, realmID, sessionID)
		if err != nil {
			return err
		}
		o, err := tx.Orgs().Get(ctx, realmID, orgID)
		if err != nil {
			return err
		}
		m, err := tx.Memberships().GetByUserOrg(ctx, realmID, sess.PrincipalID, orgID)
		if err != nil {
			return err
		}
		set, err := SettingsOf(o)
		if err != nil || set.LoginPolicy == nil || set.LoginPolicy.Passkey.Empty() {
			return err
		}
		_, err = s.passkeyAllowed(ctx, tx, o, m, set.LoginPolicy.Passkey, session.OrgPick{Credentials: sess.AuthCredentialIDs, RequestID: requestID})
		return err
	})
}

// HasPasskeyPolicy は Org のログインポリシーに passkey があるかを返す（passkey_attestation の無効化で数える。11.12）。
func HasPasskeyPolicy(o port.Org) (bool, error) {
	st, err := SettingsOf(o)
	return st.LoginPolicy != nil && !st.LoginPolicy.Passkey.Empty(), err
}

// ClearPasskeyPolicy は Org のログインポリシーから passkey を外す（passkey_attestation の無効化の片付け。11.12）。外したら true。
func ClearPasskeyPolicy(ctx context.Context, tx port.Tx, o port.Org, now time.Time) (bool, error) {
	st, err := SettingsOf(o)
	if err != nil || st.LoginPolicy == nil || st.LoginPolicy.Passkey.Empty() {
		return false, err
	}
	st.LoginPolicy.Passkey = nil
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
