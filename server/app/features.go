package app

import (
	"context"
	"fmt"
	"slices"

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
