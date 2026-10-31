package org

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// ドメインの所有証明（design.md 11.3、フィーチャー org_managed_users、ADR 0075）。
//
// Org の owner がドメインを登録すると、IAM がトークンを作る。owner が `_iam-challenge.<domain>` に
// TXT `iam-domain-verification=<token>` を置き、確認を求めると、IAM が DNS を引いて証明済みにする。
// 証明済みのドメインは realm で1つの Org だけが持てる（後から証明しようとした Org は domain_taken）。
// DNS はトランザクションの外で引く（LookupDomain）。結果を書くのは MarkDomainChecked。
// 証明済みのドメインは DomainRechecker が定期的に確かめ直し、TXT が猶予の間ずっと無ければ証明を外す（RecheckDomain。ADR 0085）。

// ManagedUsersFeature は Org 管理ユーザー（ドメインの所有証明を含む）の宣言（features/orgmanagedusers が登録する）。
var ManagedUsersFeature = feature.Feature{Name: feature.OrgManagedUsers, DataVersion: 1, Requires: []string{feature.Org}}

const (
	// DomainChallengeLabel は TXT を置く名前の先頭のラベル。
	DomainChallengeLabel = "_iam-challenge"
	// DomainTXTPrefix は TXT の値の接頭辞。後ろにトークンが続く。
	DomainTXTPrefix = "iam-domain-verification="
	// MaxDomainsPerOrg は1つの Org に登録できるドメインの数の上限。
	MaxDomainsPerOrg = 20
	// DomainLookupTimeout は DNS の問い合わせの時間の上限。
	DomainLookupTimeout = 5 * time.Second

	EventDomainAdded    = "org.domain.added"
	EventDomainVerified = "org.domain.verified"
	EventDomainRemoved  = "org.domain.removed"
	// EventDomainMissing は確かめ直して TXT が見つからなくなったこと（猶予の始まり）。EventDomainUnverified は猶予を過ぎて証明を外したこと。
	EventDomainMissing    = "org.domain.missing"
	EventDomainUnverified = "org.domain.unverified"
)

var (
	// ErrDomainInvalid はドメインの形式が正しくないこと。
	ErrDomainInvalid = errs.WithCode(errs.KindInvalid, "invalid_domain", "invalid domain")
	// ErrDomainExists は Org に同じドメインを登録済みであること。
	ErrDomainExists = errs.WithCode(errs.KindConflict, "domain_exists", "domain already added to the org")
	// ErrDomainTaken は realm の別の Org がドメインを証明済みであること。
	ErrDomainTaken = errs.WithCode(errs.KindConflict, "domain_taken", "domain verified by another org")
	// ErrDomainLimit は Org のドメインの数が上限に達したこと。
	ErrDomainLimit = errs.WithCode(errs.KindFailedPrecondition, "domain_limit", "too many domains")
	// ErrDomainNotProven は TXT が見つからないこと。
	ErrDomainNotProven = errs.WithCode(errs.KindFailedPrecondition, "domain_not_verified", "verification TXT record not found")
)

// TXTResolver は TXT を引く。*net.Resolver が満たす。
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NormalizeDomain はドメインを小文字にし、末尾の点を除き、形式を確かめる。ASCII だけを受け付ける（IDN は A ラベル）。
// ラベルは2つ以上で、最後のラベル（TLD）は数字だけではないこと（IP アドレスを除く）。
func NormalizeDomain(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if d == "" || len(d) > 253 {
		return "", ErrDomainInvalid
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", ErrDomainInvalid
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrDomainInvalid
		}
		for i := range len(l) {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", ErrDomainInvalid
			}
		}
	}
	if !strings.ContainsFunc(labels[len(labels)-1], func(r rune) bool { return r < '0' || r > '9' }) {
		return "", ErrDomainInvalid
	}
	return d, nil
}

// DomainRecord は d の証明に置く TXT の名前と値を返す。
func DomainRecord(d port.OrgDomain) (name, value string) {
	return DomainChallengeLabel + "." + d.Domain, DomainTXTPrefix + d.Token
}

func newDomainToken() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b) // crypto/rand.Read は失敗しない
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// Domains は Org のドメインを登録の順に返す。
func (s *Service) Domains(ctx context.Context, tx port.Tx, o port.Org) ([]port.OrgDomain, error) {
	return tx.OrgDomains().ListByOrg(ctx, o.RealmID, o.ID)
}

// Domain は Org の、公開 ID のドメインを返す。別の Org のものは errs.NotFound。
func (s *Service) Domain(ctx context.Context, tx port.Tx, o port.Org, publicID string) (port.OrgDomain, error) {
	d, err := tx.OrgDomains().GetByPublicID(ctx, o.RealmID, publicID)
	if err == nil && d.OrgID != o.ID {
		err = errs.New(errs.KindNotFound, "org domain")
	}
	return d, err
}

// AddDomain はドメインを未証明で登録する。個人 Org には登録できない。
func (s *Service) AddDomain(ctx context.Context, tx port.Tx, o port.Org, domain string, actor audit.Actor, requestID string) (port.OrgDomain, error) {
	if o.Kind != port.OrgShared {
		return port.OrgDomain{}, ErrPersonalOrg
	}
	name, err := NormalizeDomain(domain)
	if err != nil {
		return port.OrgDomain{}, err
	}
	ds, err := tx.OrgDomains().ListByOrg(ctx, o.RealmID, o.ID)
	if err != nil {
		return port.OrgDomain{}, err
	}
	if slices.ContainsFunc(ds, func(d port.OrgDomain) bool { return d.Domain == name }) {
		return port.OrgDomain{}, ErrDomainExists
	}
	if len(ds) >= MaxDomainsPerOrg {
		return port.OrgDomain{}, ErrDomainLimit
	}
	if _, err := tx.OrgDomains().GetVerified(ctx, o.RealmID, name); err == nil {
		return port.OrgDomain{}, ErrDomainTaken
	} else if !errors.Is(err, errs.NotFound) {
		return port.OrgDomain{}, err
	}
	d := port.OrgDomain{ID: id.New(id.OrgDomain), PublicID: id.NewExternal(id.OrgDomain), RealmID: o.RealmID, OrgID: o.ID, Domain: name,
		Token: newDomainToken(), CreatedBy: actor.ID, CreatedAt: s.Clock.Now()}
	if err := tx.OrgDomains().Create(ctx, d); err != nil {
		if errors.Is(err, errs.Conflict) {
			return port.OrgDomain{}, ErrDomainExists
		}
		return port.OrgDomain{}, err
	}
	return d, s.recordDomain(ctx, tx, o, EventDomainAdded, d, actor, requestID)
}

// LookupDomain は d の TXT を引き、置かれているかを返す。トランザクションの外で呼ぶ。
// 名前が無いのは false。DNS の障害は errs.KindUnavailable。
func (s *Service) LookupDomain(ctx context.Context, d port.OrgDomain) (bool, error) {
	r := s.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, DomainLookupTimeout)
	defer cancel()
	name, want := DomainRecord(d)
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		if de, ok := errors.AsType[*net.DNSError](err); ok && de.IsNotFound {
			return false, nil
		}
		return false, errs.Wrap(errs.KindUnavailable, err, "org: domain lookup")
	}
	return slices.ContainsFunc(txts, func(t string) bool { return strings.TrimSpace(t) == want }), nil
}

// MarkDomainChecked は LookupDomain の結果を書く。found なら証明済みにする（既に証明済みなら、確かめ直しの猶予を消すだけ）。
// 見つからなければ確かめた時刻だけを書き、ErrDomainNotProven を返す。token は LookupDomain に渡した行のトークンで、
// 間に消されて登録し直されたら errs.NotFound。別の Org が先に証明していれば ErrDomainTaken。
func (s *Service) MarkDomainChecked(ctx context.Context, tx port.Tx, o port.Org, publicID, token string, found bool, actor audit.Actor, requestID string) (port.OrgDomain, error) {
	d, err := s.Domain(ctx, tx, o, publicID)
	if err != nil {
		return port.OrgDomain{}, err
	}
	if d.Token != token {
		return port.OrgDomain{}, errs.New(errs.KindNotFound, "org domain")
	}
	now := s.Clock.Now()
	if d.VerifiedAt != nil {
		// 確かめ直しで TXT が見つからなくなった後に置き直したなら、猶予を消す（ADR 0085）。
		if found && d.MissingSince != nil {
			d.CheckedAt, d.MissingSince = &now, nil
			return d, tx.OrgDomains().Update(ctx, d)
		}
		return d, nil
	}
	d.CheckedAt = &now
	if !found {
		if err := tx.OrgDomains().Update(ctx, d); err != nil {
			return port.OrgDomain{}, err
		}
		return d, ErrDomainNotProven
	}
	d.VerifiedAt = &now
	if err := tx.OrgDomains().Update(ctx, d); err != nil {
		if errors.Is(err, errs.Conflict) {
			return port.OrgDomain{}, ErrDomainTaken
		}
		return port.OrgDomain{}, err
	}
	return d, s.recordDomain(ctx, tx, o, EventDomainVerified, d, actor, requestID)
}

// RecheckDomain は証明済みのドメイン d を LookupDomain で確かめ直した結果を書く（ADR 0085）。見つかれば MissingSince を消す。
// 見つからなければ、初めてなら MissingSince を付けて org.domain.missing を出し、MissingSince から grace を過ぎていれば
// 証明を外して org.domain.unverified を出す（外したら true）。d の後に消された・登録し直された・証明を外されたなら何もしない。
func (s *Service) RecheckDomain(ctx context.Context, tx port.Tx, d port.OrgDomain, found bool, grace time.Duration) (bool, error) {
	cur, err := tx.OrgDomains().GetByPublicID(ctx, d.RealmID, d.PublicID)
	if errors.Is(err, errs.NotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if cur.ID != d.ID || cur.Token != d.Token || cur.VerifiedAt == nil {
		return false, nil
	}
	now := s.Clock.Now()
	cur.CheckedAt = &now
	event := ""
	switch {
	case found:
		cur.MissingSince = nil
	case cur.MissingSince == nil:
		cur.MissingSince, event = &now, EventDomainMissing
	case now.Sub(*cur.MissingSince) >= grace:
		cur.VerifiedAt, cur.MissingSince, event = nil, nil, EventDomainUnverified
	}
	if err := tx.OrgDomains().Update(ctx, cur); err != nil {
		return false, err
	}
	if event == "" {
		return false, nil
	}
	o, err := tx.Orgs().Get(ctx, cur.RealmID, cur.OrgID)
	if err != nil {
		return false, err
	}
	return event == EventDomainUnverified, s.recordDomain(ctx, tx, o, event, cur, audit.Actor{Type: "system"}, "")
}

// DeferRecheck は DNS の障害で確かめられなかったドメインの CheckedAt だけを進める（猶予には数えない）。障害の続くドメインが
// 確かめ直しの1回分を占めて、他のドメインを待たせないため。
func (s *Service) DeferRecheck(ctx context.Context, tx port.Tx, d port.OrgDomain) error {
	cur, err := tx.OrgDomains().GetByPublicID(ctx, d.RealmID, d.PublicID)
	if errors.Is(err, errs.NotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if cur.ID != d.ID || cur.Token != d.Token || cur.VerifiedAt == nil {
		return nil
	}
	now := s.Clock.Now()
	cur.CheckedAt = &now
	return tx.OrgDomains().Update(ctx, cur)
}

// RemoveDomain はドメインを消す。
func (s *Service) RemoveDomain(ctx context.Context, tx port.Tx, o port.Org, d port.OrgDomain, actor audit.Actor, requestID string) error {
	if err := tx.OrgDomains().Delete(ctx, o.RealmID, d.ID); err != nil {
		return err
	}
	return s.recordDomain(ctx, tx, o, EventDomainRemoved, d, actor, requestID)
}

func (s *Service) recordDomain(ctx context.Context, tx port.Tx, o port.Org, typ string, d port.OrgDomain, actor audit.Actor, requestID string) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID,
		Actor: actor, RequestID: requestID, Details: map[string]any{"domain_id": d.PublicID, "domain": d.Domain, "verified": d.VerifiedAt != nil}})
	return err
}
