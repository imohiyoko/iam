package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// preparers は、後からフィーチャーを有効にするときの準備処理（design.md 11.12 の enabling）。冪等にする。
var preparers = map[string]func(ctx context.Context, a *App) error{
	feature.Org: prepareOrg,
}

// cleaner はフィーチャーを無効にするときの、データの数え上げと片付け（11.12 の disabling）。
// Purge は1つのトランザクションで最大 limit 件片付け、片付けた件数を返す。nil なら片付けは運営者が API で行う。
type cleaner struct {
	Count func(ctx context.Context, tx port.Tx) (int, error)
	Purge func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error)
	// Hint は Purge が無いときに、データの片付け方を示す。
	Hint string
}

// cleaners はデータを残すフィーチャーの片付け。無いフィーチャーはデータを残さない（warnings など）。
var cleaners = map[string]cleaner{
	feature.Org: {Count: countSharedOrgs,
		Hint: "delete the shared Orgs (POST /v1/admin/orgs/{org_id}:delete); personal Orgs are kept and reused when org is enabled again"},
	feature.OrgLoginPolicy: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return org.HasLoginPolicy(o) })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachOrg(ctx, tx, limit, func(o port.Org) (bool, error) { return org.ClearLoginPolicy(ctx, tx, o, now) })
	}},
	feature.Quota: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.QuotaGrants().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.QuotaGrants().Purge(ctx, limit)
		}},
	// 管理ユーザーは個人ユーザーに戻し、ドメインを消す（ADR 0076）。
	feature.OrgManagedUsers: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := tx.Users().CountManaged(ctx)
		if err != nil {
			return 0, err
		}
		d, err := tx.OrgDomains().Count(ctx)
		return n + d, err
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := tx.Users().ReleaseManaged(ctx, limit, now)
		if err != nil || n >= limit {
			return n, err
		}
		d, err := tx.OrgDomains().Purge(ctx, limit-n)
		return n + d, err
	}},
	feature.ServiceAccounts: {Count: func(ctx context.Context, tx port.Tx) (int, error) {
		return eachServiceAccount(ctx, tx, -1, func(port.ServiceAccount) (bool, error) { return true, nil })
	}, Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		return eachServiceAccount(ctx, tx, limit, func(sa port.ServiceAccount) (bool, error) {
			return true, tx.ServiceAccounts().SetDeleted(ctx, sa.RealmID, sa.ID, now)
		})
	}},
	feature.Password: {Count: func(ctx context.Context, tx port.Tx) (int, error) { return tx.Passwords().Count(ctx) },
		Purge: func(ctx context.Context, tx port.Tx, _ time.Time, limit int) (int, error) {
			return tx.Passwords().Purge(ctx, limit)
		}},
}

// countSharedOrgs は削除されていない共有 Org を数える。
func countSharedOrgs(ctx context.Context, tx port.Tx) (int, error) {
	return eachOrg(ctx, tx, -1, func(o port.Org) (bool, error) { return o.Kind == port.OrgShared && o.DeletedAt == nil, nil })
}

// eachOrg は全 realm の Org に fn を呼び、true を返した数を数える。limit が 0 以上なら、その数で止める。
func eachOrg(ctx context.Context, tx port.Tx, limit int, fn func(port.Org) (bool, error)) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		for after := ""; ; {
			page, err := tx.Orgs().List(ctx, r.ID, after, prepareBatch)
			if err != nil {
				return n, err
			}
			for _, o := range page {
				after = o.ID
				ok, err := fn(o)
				if err != nil {
					return n, err
				}
				if ok {
					n++
				}
				if limit >= 0 && n >= limit {
					return n, nil
				}
			}
			if len(page) < prepareBatch {
				break
			}
		}
	}
	return n, nil
}

// eachServiceAccount は全 realm の、削除していない配信用でないサービスアカウント（フィーチャー service_accounts のデータ）に
// fn を呼び、true を返した数を数える。limit が 0 以上なら、その数で止める。
func eachServiceAccount(ctx context.Context, tx port.Tx, limit int, fn func(port.ServiceAccount) (bool, error)) (int, error) {
	realms, err := tx.Realms().List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range realms {
		for after := ""; ; {
			page, err := tx.ServiceAccounts().List(ctx, r.ID, after, prepareBatch)
			if err != nil {
				return n, err
			}
			for _, sa := range page {
				after = sa.ID
				if sa.DeletedAt != nil {
					continue
				}
				if delivery, err := deliveryOnly(ctx, tx, sa); err != nil || delivery {
					if err != nil {
						return n, err
					}
					continue
				}
				ok, err := fn(sa)
				if err != nil {
					return n, err
				}
				if ok {
					n++
				}
				if limit >= 0 && n >= limit {
					return n, nil
				}
			}
			if len(page) < prepareBatch {
				break
			}
		}
	}
	return n, nil
}

// prepareBatch は準備処理の1つのトランザクションで扱う件数。
const prepareBatch = 200

// EnableFeature はフィーチャーを有効にする（11.12）：台帳を enabling にし、準備処理を行い、active にする。
// 既に active なら何もせず false を返す。動いているサーバーには、再起動で反映する。
func (a *App) EnableFeature(ctx context.Context, name string) (bool, error) {
	i := slices.IndexFunc(a.binary, func(f feature.Feature) bool { return f.Name == name })
	if i < 0 {
		return false, fmt.Errorf("feature: %s is not included in this binary", name)
	}
	f := a.binary[i]
	if enabled := derefFeatures(a.cfg.Features); (enabled == nil && !f.DefaultEnabled) || (enabled != nil && !slices.Contains(enabled, name)) {
		return false, fmt.Errorf("feature: %s is disabled in config; enable it in `features` first", name)
	}
	var ledger []port.FeatureRecord
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		ledger, err = tx.Features().List(ctx)
		return err
	}); err != nil {
		return false, err
	}
	state := func(n string) port.FeatureState {
		for _, r := range ledger {
			if r.Feature == n {
				return r.State
			}
		}
		return ""
	}
	if state(name) == port.FeatureActive {
		return false, nil
	}
	for _, r := range f.Requires {
		if state(r) != port.FeatureActive {
			return false, fmt.Errorf("feature: %s requires %s; enable it first", name, r)
		}
	}
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return tx.Features().Put(ctx, port.FeatureRecord{Feature: name, State: port.FeatureEnabling, DataVersion: f.DataVersion, UpdatedAt: a.deps.Clock.Now()})
	}); err != nil {
		return false, err
	}
	if p := preparers[name]; p != nil {
		if err := p(ctx, a); err != nil {
			return false, fmt.Errorf("feature: prepare %s: %w", name, err)
		}
	}
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Features().Put(ctx, port.FeatureRecord{Feature: name, State: port.FeatureActive, DataVersion: f.DataVersion, UpdatedAt: a.deps.Clock.Now()}); err != nil {
			return err
		}
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "feature.enabled", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"features": []string{name}, "reason": "cli"},
		})
		return err
	})
	return err == nil, err
}

// prepareOrg は既存のユーザーに個人 Org を作る（11.13）。既存の realm 範囲のロール付与は realm 範囲のまま残す。
// 準備の後に作られたユーザーの取りこぼしは、ログイン時に org.Service.Pick が作って補う。
func prepareOrg(ctx context.Context, a *App) error {
	svc := &org.Service{Clock: a.deps.Clock}
	var realms []port.Realm
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		realms, err = tx.Realms().List(ctx)
		return err
	}); err != nil {
		return err
	}
	for _, r := range realms {
		for after := ""; ; {
			var n int
			err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
				us, err := tx.Users().List(ctx, r.ID, after, prepareBatch)
				if err != nil {
					return err
				}
				n = len(us)
				for _, u := range us {
					after = u.ID
					if u.Status != port.UserActive {
						continue
					}
					if _, err := svc.EnsurePersonal(ctx, tx, u, ""); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			if n < prepareBatch {
				break
			}
		}
	}
	return nil
}

// DisableResult は DisableFeature の結果。
type DisableResult struct {
	// Done は無効化が終わった（データが 0 件になり、台帳から消した）。
	Done bool
	// Remaining は残っているデータの件数。Purged は今回片付けた件数。
	Remaining, Purged int
	// Hint は Purge できないときの片付け方。
	Hint string
}

// ErrFeatureRequired は、無効にしようとしたフィーチャーに依存するものがまだ有効なこと。
var ErrFeatureRequired = errors.New("feature: required by another feature")

// DisableFeature はフィーチャーを無効にする（11.12）：台帳を disabling にし（再起動したサーバーは書き込まない）、
// データが 0 件なら台帳から消す。purge なら片付けてから数える。データが残れば disabling のまま Remaining を返す。
// 台帳に無ければ何もせず Done を返す。
func (a *App) DisableFeature(ctx context.Context, name string, purge bool) (DisableResult, error) {
	if !slices.ContainsFunc(a.binary, func(f feature.Feature) bool { return f.Name == name }) {
		return DisableResult{}, fmt.Errorf("feature: %s is not included in this binary; disable it with a binary that includes it", name)
	}
	var rec *port.FeatureRecord
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ledger, err := tx.Features().List(ctx)
		if err != nil {
			return err
		}
		for _, r := range ledger {
			if r.Feature == name {
				rec = &r
				continue
			}
			for _, f := range a.binary {
				if f.Name == r.Feature && slices.Contains(f.Requires, name) {
					return fmt.Errorf("%w: %s requires %s; disable %s first", ErrFeatureRequired, r.Feature, name, r.Feature)
				}
			}
		}
		if rec == nil || rec.State == port.FeatureDisabling {
			return nil
		}
		rec.State, rec.UpdatedAt = port.FeatureDisabling, a.deps.Clock.Now()
		if err := tx.Features().Put(ctx, *rec); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "feature.disabling", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"features": []string{name}, "reason": "cli"},
		})
		return err
	}); err != nil || rec == nil {
		return DisableResult{Done: err == nil}, err
	}
	c, hasData := cleaners[name]
	var res DisableResult
	if hasData && purge && c.Purge == nil {
		return res, fmt.Errorf("feature: %s data cannot be purged here: %s", name, c.Hint)
	}
	for hasData && purge {
		var n int
		if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			n, err = c.Purge(ctx, tx, a.deps.Clock.Now(), prepareBatch)
			return err
		}); err != nil {
			return res, err
		}
		res.Purged += n
		if n < prepareBatch {
			break
		}
	}
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if hasData {
			var err error
			if res.Remaining, err = c.Count(ctx, tx); err != nil || res.Remaining > 0 {
				res.Hint = c.Hint
				return err
			}
		}
		if err := tx.Features().Delete(ctx, name); err != nil {
			return err
		}
		res.Done = true
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "feature.disabled", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
			Details: map[string]any{"features": []string{name}, "reason": "cli", "purged": res.Purged},
		})
		return err
	})
	return res, err
}
