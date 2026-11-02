package ldap

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 同期の上限（1 回の同期で扱う量を限る）。
const (
	pageSize = 500
	// MaxEntries は 1 回に読む項目の上限。超えれば読み切れなかった回として、停止と所属の削除をしない。
	MaxEntries = 100_000
	// maxProvision は 1 回に事前に登録する人数の上限（残りは次の回）。
	maxProvision = 1000
	// maxGroups は 1 回に扱う Group の上限。
	maxGroups = 1000
	// batch は 1 つのトランザクションで扱う外部 ID の数。
	batch = 100
	// 停止の安全装置：消えた本人が guardMin 人を超え、かつ有効な外部 ID の guardRatio を超えるなら、その回は停止しない
	// （検索の基点や絞り込みの誤り、ディレクトリの一時的な欠けで全員を止めない）。
	guardMin   = 10
	guardRatio = 5 // 1/5 = 20%
)

// SyncResult は 1 回の同期の件数。
type SyncResult struct {
	Entries, Skipped, Linked, Provisioned, ProvisionSkipped     int
	Missing, Suspended, Reactivated                             int
	GroupsCreated, GroupConflicts, MembersAdded, MembersRemoved int
	// Complete は全件を読み切ったか。DeprovisionAborted は安全装置で停止を見送ったか。
	Complete, DeprovisionAborted bool
}

func (r SyncResult) details() map[string]any {
	return map[string]any{"entries": r.Entries, "skipped": r.Skipped, "linked": r.Linked, "provisioned": r.Provisioned,
		"provision_skipped": r.ProvisionSkipped, "missing": r.Missing, "suspended": r.Suspended, "reactivated": r.Reactivated,
		"groups_created": r.GroupsCreated, "group_conflicts": r.GroupConflicts, "members_added": r.MembersAdded,
		"members_removed": r.MembersRemoved, "complete": r.Complete, "deprovision_aborted": r.DeprovisionAborted}
}

var systemActor = audit.Actor{Type: "system"}

// suspendRef は同期の停止の ExternalRef の接頭辞（connection ごと）。停止のたびに時刻を足して一意にする。
func suspendRef(c port.Connection) string { return "ldap:" + c.ID + ":" }

// Sync は connection のディレクトリを読み、外部 ID の紐付いたユーザーの停止・解除と、Group の所属を合わせる。
// ディレクトリとの通信はトランザクションの外で行い、書き込みは小分けのトランザクションにする。
func (s *Service) Sync(ctx context.Context, c port.Connection, requestID string) (SyncResult, error) {
	res, err := s.sync(ctx, c, requestID)
	typ, result := "ldap.sync.completed", audit.ResultSuccess
	details := res.details()
	details["connection_id"] = c.ID
	if err != nil {
		typ, result = "ldap.sync.failed", audit.ResultFailure
		details["reason"] = err.Error()
	}
	if rerr := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{Type: typ, Result: result, RealmID: c.RealmID, Actor: systemActor,
			RequestID: requestID, Details: details})
		return err
	}); rerr != nil && err == nil {
		err = rerr
	}
	return res, err
}

func (s *Service) sync(ctx context.Context, c port.Connection, requestID string) (SyncResult, error) {
	var res SyncResult
	cfg, err := ConfigOf(c)
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		return res, err
	}
	if c.OwnerOrgID != "" && !s.OAuth.OrgSSOEnabled() {
		return res, errors.New("org connections are disabled")
	}
	entries, complete, skipped, err := s.read(ctx, c, cfg)
	if err != nil {
		return res, err
	}
	res.Entries, res.Complete, res.Skipped = len(entries), complete, skipped

	// 有効な外部 ID をすべて読む（connection の内部 ID の順）。
	var idents []port.Identity
	for after := ""; ; {
		var page []port.Identity
		if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			page, err = tx.Identities().ListActiveByConnection(ctx, c.RealmID, c.ID, after, batch)
			return err
		}); err != nil {
			return res, err
		}
		idents = append(idents, page...)
		if len(page) < batch {
			break
		}
		after = page[len(page)-1].ID
	}
	res.Linked = len(idents)
	for _, i := range idents {
		if e, ok := entries[i.ProviderSubject]; !ok || e.Disabled {
			res.Missing++
		}
	}
	deprovision := cfg.Sync.OnMissing == OnMissingSuspend && complete
	if deprovision && res.Missing > guardMin && res.Missing*guardRatio > len(idents) {
		deprovision, res.DeprovisionAborted = false, true
	}

	// 紐付いた本人：停止・解除。ディレクトリに居て有効な本人の所属を集める。
	members := map[string]entry{} // ユーザーの内部 ID → 項目
	var suspended []string
	for chunk := range slices.Chunk(idents, batch) {
		var sus []string
		var reactivated int
		if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			sus, reactivated = nil, 0
			for _, i := range chunk {
				e, ok := entries[i.ProviderSubject]
				u, err := tx.Users().Get(ctx, c.RealmID, i.UserID)
				if errors.Is(err, errs.NotFound) {
					continue
				}
				if err != nil {
					return err
				}
				// Org 専用の connection は、その Org の管理ユーザーだけを扱う（ADR 0077）。
				if c.OwnerOrgID != "" && u.ManagedOrgID != c.OwnerOrgID {
					continue
				}
				if ok && !e.Disabled {
					members[u.ID] = e
					n, err := s.reactivate(ctx, tx, c, u, requestID)
					if err != nil {
						return err
					}
					reactivated += n
					continue
				}
				if !deprovision {
					continue
				}
				done, err := s.suspend(ctx, tx, c, u, ok, requestID)
				if err != nil {
					return err
				}
				if done {
					sus = append(sus, u.ID)
				}
			}
			return nil
		}); err != nil {
			return res, err
		}
		suspended = append(suspended, sus...)
		res.Suspended += len(sus)
		res.Reactivated += reactivated
	}
	for _, uid := range suspended {
		s.Sessions.Forget(ctx, c.RealmID, uid)
	}

	// まだ紐付いていない本人の事前の登録（ログインと同じ規則）。
	if cfg.Sync.Provision {
		linked := map[string]bool{}
		for _, i := range idents {
			linked[i.ProviderSubject] = true
		}
		subs := slices.Sorted(maps.Keys(entries))
		for _, sub := range subs {
			e := entries[sub]
			if linked[sub] || e.Disabled || e.Email == "" {
				continue
			}
			if res.Provisioned >= maxProvision {
				break
			}
			var ident port.Identity
			err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				var err error
				ident, err = s.OAuth.ProvisionFederated(ctx, tx, c.RealmID, c, federated(cfg, c, e), requestID)
				return err
			})
			switch {
			case err == nil:
				res.Provisioned++
				members[ident.UserID] = e
			case errors.Is(err, oauth.ErrQuotaExceeded):
				res.ProvisionSkipped++
				s.logger().WarnContext(ctx, "ldap sync: quota exceeded; provisioning stops", "connection_id", c.ID)
			case errors.Is(err, oauth.ErrAccountExists), errors.Is(err, oauth.ErrEmailUnverified), errors.Is(err, oauth.ErrSSODomainNotVerified),
				errors.Is(err, errs.Conflict):
				res.ProvisionSkipped++
				continue
			default:
				return res, err
			}
			if errors.Is(err, oauth.ErrQuotaExceeded) {
				break
			}
		}
	}

	if cfg.GroupBaseDN != "" {
		if err := s.syncGroups(ctx, c, cfg, members, complete, requestID, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// read はディレクトリの本人をページに分けて読む（識別子 → 項目）。読めない項目と、識別子の重なる項目は飛ばす。
func (s *Service) read(ctx context.Context, c port.Connection, cfg Config) (map[string]entry, bool, int, error) {
	sess, err := s.open(ctx, cfg, s.guarded(c))
	if err != nil {
		return nil, false, 0, err
	}
	defer sess.close()
	out := map[string]entry{}
	dup := map[string]bool{}
	skipped := 0
	paging := ldap.NewControlPaging(pageSize)
	for {
		req := ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(opTimeout.Seconds()), false,
			cfg.UserFilter, attributes(cfg), []ldap.Control{paging})
		r, err := sess.conn.Search(req)
		if err != nil {
			return nil, false, 0, fmt.Errorf("%w: search: %v", ErrUnavailable, err)
		}
		for _, le := range r.Entries {
			e, err := entryOf(cfg, le)
			if err != nil {
				skipped++
				continue
			}
			if _, seen := out[e.Subject]; seen || dup[e.Subject] {
				// 同じ識別子の項目が複数：どれが本人か決まらないので、どちらも使わない（消えたとみなさないよう、無効な項目として残す）。
				dup[e.Subject] = true
				out[e.Subject] = entry{Subject: e.Subject, Disabled: true}
				skipped++
				continue
			}
			out[e.Subject] = e
			if len(out) > MaxEntries {
				return out, false, skipped, nil
			}
		}
		ctl, _ := ldap.FindControl(r.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if ctl == nil {
			// ページングの応答が無いサーバーは、1 回で全件を返したものとみなす。
			return out, true, skipped, nil
		}
		if len(ctl.Cookie) == 0 {
			return out, true, skipped, nil
		}
		paging.SetCookie(ctl.Cookie)
	}
}

// activeSyncSuspensions は、この connection の同期が作った、今効いているか予約の停止を返す。
func (s *Service) activeSyncSuspensions(ctx context.Context, tx port.Tx, c port.Connection, u port.User) ([]port.Suspension, error) {
	ss, err := tx.Suspensions().ListByTarget(ctx, c.RealmID, port.SuspensionTargetUser, u.ID)
	if err != nil {
		return nil, err
	}
	now := s.Clock.Now()
	var out []port.Suspension
	for _, sp := range ss {
		if strings.HasPrefix(sp.ExternalRef, suspendRef(c)) && sp.LiftedAt == nil && (sp.EndsAt == nil || sp.EndsAt.After(now)) {
			out = append(out, sp)
		}
	}
	return out, nil
}

// suspend はディレクトリから消えた・無効にされた本人を停止し、ログインの系列を終える。既に同期の停止があれば何もしない。
// 最後の realm:owner は止めない（account が断る。飛ばして続ける）。
func (s *Service) suspend(ctx context.Context, tx port.Tx, c port.Connection, u port.User, present bool, requestID string) (bool, error) {
	cur, err := s.activeSyncSuspensions(ctx, tx, c, u)
	if err != nil || len(cur) > 0 {
		return false, err
	}
	reason := "ldap: the entry was removed from the directory"
	if present {
		reason = "ldap: the account is disabled in the directory"
	}
	ref := suspendRef(c) + strconv.FormatInt(s.Clock.Now().UnixNano(), 36)
	_, _, err = s.Accounts.SuspendUser(ctx, tx, c.RealmID, u, account.Suspend{Category: account.CategoryCustomerRequest, Reason: reason,
		ExternalRef: ref}, systemActor, requestID)
	if errors.Is(err, account.ErrLastRealmOwner) {
		s.logger().WarnContext(ctx, "ldap sync: the last realm owner is not suspended", "user_id", u.PublicID)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, s.Sessions.EndUserTx(ctx, tx, c.RealmID, u.ID, session.ReasonSuspended, requestID)
}

// reactivate は同期の停止を解除する（ディレクトリで有効に戻った本人）。運営者の停止は解除しない。
func (s *Service) reactivate(ctx context.Context, tx port.Tx, c port.Connection, u port.User, requestID string) (int, error) {
	cur, err := s.activeSyncSuspensions(ctx, tx, c, u)
	if err != nil {
		return 0, err
	}
	for _, sp := range cur {
		if _, err := s.Accounts.LiftSuspension(ctx, tx, c.RealmID, sp, "ldap: the entry is active in the directory", systemActor, requestID); err != nil {
			return 0, err
		}
	}
	return len(cur), nil
}

// syncGroups は GroupBaseDN の下の Group を、同期が管理する Group（directory_groups）として作り、ユーザーの所属を合わせる。
// 手で作った Group と同じ名前なら引き取らずに飛ばす。Org 専用の connection の Group はその Org の Group で、その Org の
// 有効なメンバーだけを入れる。
func (s *Service) syncGroups(ctx context.Context, c port.Connection, cfg Config, members map[string]entry, complete bool, requestID string, res *SyncResult) error {
	base, err := ldap.ParseDN(cfg.GroupBaseDN)
	if err != nil {
		return err
	}
	type want struct {
		name  string
		users map[string]bool
	}
	desired := map[string]*want{}
	truncated := false
	for _, uid := range slices.Sorted(maps.Keys(members)) {
		for _, dn := range members[uid].Groups {
			key, name, ok := groupOf(dn, base)
			if !ok {
				continue
			}
			w := desired[key]
			if w == nil {
				if len(desired) >= maxGroups {
					truncated = true
					continue
				}
				w = &want{name: name, users: map[string]bool{}}
				desired[key] = w
			}
			w.users[uid] = true
		}
	}
	var links []port.DirectoryGroup
	if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		links, err = tx.DirectoryGroups().ListByConnection(ctx, c.RealmID, c.ID)
		return err
	}); err != nil {
		return err
	}
	linked := map[string]port.DirectoryGroup{}
	for _, l := range links {
		linked[l.ExternalKey] = l
	}
	changed := false
	// 読み切った回だけ、ディレクトリで空になった・消えた Group からユーザーを外す。
	if complete && !truncated {
		for _, l := range links {
			if _, ok := desired[l.ExternalKey]; ok {
				continue
			}
			if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				g, err := tx.Groups().Get(ctx, c.RealmID, l.GroupID)
				if errors.Is(err, errs.NotFound) {
					return tx.DirectoryGroups().Delete(ctx, c.RealmID, c.ID, l.ExternalKey)
				}
				if err != nil {
					return err
				}
				added, removed, err := s.reconcile(ctx, tx, c, g, nil, requestID)
				res.MembersAdded += added
				res.MembersRemoved += removed
				changed = changed || added+removed > 0
				return err
			}); err != nil {
				return err
			}
		}
	}
	for _, key := range slices.Sorted(maps.Keys(desired)) {
		w := desired[key]
		if err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var g port.Group
			l, ok := linked[key]
			if ok {
				var err error
				g, err = tx.Groups().Get(ctx, c.RealmID, l.GroupID)
				if errors.Is(err, errs.NotFound) {
					// 手で消された Group：対応を外して作り直す。
					if err := tx.DirectoryGroups().Delete(ctx, c.RealmID, c.ID, key); err != nil {
						return err
					}
					ok = false
				} else if err != nil {
					return err
				}
			}
			if !ok {
				now := s.Clock.Now()
				g = port.Group{ID: id.New(id.Group), PublicID: id.NewExternal(id.Group), RealmID: c.RealmID, OrgID: c.OwnerOrgID, Name: w.name,
					CreatedAt: now, UpdatedAt: now}
				if err := tx.Groups().Create(ctx, g); errors.Is(err, errs.Conflict) {
					// 同じ名前の Group が既にある：引き取らない（手で作った Group の所属をディレクトリに渡さない）。
					res.GroupConflicts++
					return nil
				} else if err != nil {
					return err
				}
				if err := tx.DirectoryGroups().Create(ctx, port.DirectoryGroup{RealmID: c.RealmID, ConnectionID: c.ID, ExternalKey: key, GroupID: g.ID,
					CreatedAt: now}); err != nil {
					return err
				}
				res.GroupsCreated++
				if err := s.record(ctx, tx, c, g.OrgID, "group.created", requestID, map[string]any{"group_id": g.PublicID, "name": g.Name,
					"connection_id": c.ID}); err != nil {
					return err
				}
			}
			added, removed, err := s.reconcile(ctx, tx, c, g, w.users, requestID)
			res.MembersAdded += added
			res.MembersRemoved += removed
			changed = changed || added+removed > 0
			return err
		}); err != nil {
			return err
		}
	}
	if changed && s.GroupsChanged != nil {
		s.GroupsChanged(c.RealmID)
	}
	return nil
}

// reconcile は Group のユーザーの所属を want に合わせる（サービスアカウントと Group の所属は変えない）。
func (s *Service) reconcile(ctx context.Context, tx port.Tx, c port.Connection, g port.Group, want map[string]bool, requestID string) (int, int, error) {
	cur, err := tx.Groups().ListMembers(ctx, c.RealmID, g.ID)
	if err != nil {
		return 0, 0, err
	}
	have := map[string]bool{}
	var added, removed []string
	for _, m := range cur {
		if m.MemberType != port.PrincipalUser {
			continue
		}
		have[m.MemberID] = true
		if !want[m.MemberID] {
			if err := tx.Groups().RemoveMember(ctx, c.RealmID, g.ID, port.PrincipalUser, m.MemberID); err != nil {
				return 0, 0, err
			}
			removed = append(removed, m.MemberID)
		}
	}
	now := s.Clock.Now()
	for _, uid := range slices.Sorted(maps.Keys(want)) {
		if have[uid] {
			continue
		}
		if c.OwnerOrgID != "" {
			m, err := tx.Memberships().GetByUserOrg(ctx, c.RealmID, uid, c.OwnerOrgID)
			if errors.Is(err, errs.NotFound) || (err == nil && m.Status != port.MembershipActive) {
				continue
			}
			if err != nil {
				return 0, 0, err
			}
		}
		if err := tx.Groups().AddMember(ctx, c.RealmID, port.GroupMember{GroupID: g.ID, MemberType: port.PrincipalUser, MemberID: uid, CreatedAt: now}); err != nil {
			return 0, 0, err
		}
		added = append(added, uid)
	}
	if len(added)+len(removed) == 0 {
		return 0, 0, nil
	}
	pub := func(ids []string) ([]string, error) {
		out := make([]string, 0, min(len(ids), 100))
		for _, x := range ids[:min(len(ids), 100)] {
			u, err := tx.Users().Get(ctx, c.RealmID, x)
			if err != nil {
				return nil, err
			}
			out = append(out, u.PublicID)
		}
		return out, nil
	}
	a, err := pub(added)
	if err != nil {
		return 0, 0, err
	}
	r, err := pub(removed)
	if err != nil {
		return 0, 0, err
	}
	return len(added), len(removed), s.record(ctx, tx, c, g.OrgID, "group.members_synced", requestID, map[string]any{"group_id": g.PublicID,
		"connection_id": c.ID, "added": len(added), "removed": len(removed), "added_user_ids": a, "removed_user_ids": r})
}

func (s *Service) record(ctx context.Context, tx port.Tx, c port.Connection, orgID, typ, requestID string, details map[string]any) error {
	ev := audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: c.RealmID, Actor: systemActor, RequestID: requestID, Details: details}
	if orgID != "" {
		o, err := tx.Orgs().Get(ctx, c.RealmID, orgID)
		if err != nil {
			return err
		}
		ev.OrgID = o.PublicID
	}
	_, err := eventlog.Record(ctx, tx, s.Clock, ev)
	return err
}
