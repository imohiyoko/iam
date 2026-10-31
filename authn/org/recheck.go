package org

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

// DomainRechecker は証明済みのドメインの TXT を定期的に確かめ直す（ADR 0087）。TXT を消した、ドメインを手放したなどで
// 所有が続いていないドメインに、証明を残さない。DNS の障害（errs.KindUnavailable）は猶予に数えず、Every の後にやり直す。
type DomainRechecker struct {
	Storage port.Storage
	Clock   clock.Clock
	Service *Service
	// Every は1つのドメインを確かめ直す間隔。Grace は TXT が見つからなくなってから証明を外すまでの猶予。
	Every, Grace time.Duration
	// Interval は確かめ直す対象を探す間隔。Batch は1回に確かめる件数の上限。
	Interval time.Duration
	Batch    int
	Log      *slog.Logger
}

// Rechecked は1回の確かめ直しの件数。
type Rechecked struct {
	Checked, Unverified, Failed int
}

// Run は ctx が終わるまで確かめ直しを繰り返す。
func (r *DomainRechecker) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if n, err := r.Sweep(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger().Warn("org domain recheck failed", "error", err)
		} else if n.Unverified > 0 || n.Failed > 0 {
			r.logger().Info("org domain recheck", "checked", n.Checked, "unverified", n.Unverified, "failed", n.Failed)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep は確かめ直す時期の来たドメインを最大 Batch 件確かめる。DNS はトランザクションの外で引く。
func (r *DomainRechecker) Sweep(ctx context.Context) (Rechecked, error) {
	var n Rechecked
	var due []port.OrgDomain
	if err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		due, err = tx.OrgDomains().ListToRecheck(ctx, r.Clock.Now().Add(-r.Every), r.Batch)
		return err
	}); err != nil {
		return n, err
	}
	for _, d := range due {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		found, lookupErr := r.Service.LookupDomain(ctx, d)
		var unverified bool
		if err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			if lookupErr != nil {
				return r.Service.DeferRecheck(ctx, tx, d)
			}
			var err error
			unverified, err = r.Service.RecheckDomain(ctx, tx, d, found, r.Grace)
			return err
		}); err != nil {
			return n, err
		}
		if lookupErr != nil {
			n.Failed++
			r.logger().Warn("org domain recheck lookup", "domain_id", d.PublicID, "error", lookupErr)
			continue
		}
		n.Checked++
		if unverified {
			n.Unverified++
		}
	}
	return n, nil
}

func (r *DomainRechecker) logger() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}
