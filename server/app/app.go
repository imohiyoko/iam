// Package app は設定とアダプタから IAM を組み立てて起動する（design.md 2.2 の server/）。
//
// 起動時の安全装置：
//   - フィーチャー台帳とバイナリの構成が合わなければ起動を拒否する（11.12）
//   - 複数インスタンスで共有できない EphemeralStore を使う構成を拒否する（2.4）
//   - DB との時刻のずれを警告する（2.7）
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Deps はアダプタ（ポートの実装）。
type Deps struct {
	Storage   port.Storage
	Ephemeral port.EphemeralStore
	Notifier  port.Notifier
	KeyStore  port.KeyStore
	EventSink port.EventSink
	Clock     clock.Clock
	Logger    *slog.Logger
}

// App は組み立て済みの IAM。
type App struct {
	cfg   config.Config
	deps  Deps
	plan  feature.Plan
	realm port.Realm
	relay *eventlog.Relay
	pii   *pii.Crypter
	// sessions はセッションの発行・検証（authn/session）。
	sessions *session.Manager
	accounts *account.Service
	notify   *notify.Service
	email    *emailflow.Service
	oauth    *oauth.Service
	notifier *eventlog.Relay
	public   http.Handler
	admin    http.Handler
}

// New は起動前の検査を行い、App を組み立てる。binary はこのバイナリに含まれるフィーチャー。
func New(ctx context.Context, cfg config.Config, d Deps, binary []feature.Feature) (*App, error) {
	if d.Storage == nil || d.Ephemeral == nil || d.KeyStore == nil || d.EventSink == nil || d.Notifier == nil {
		return nil, errors.New("app: all adapters are required")
	}
	if d.Clock == nil {
		d.Clock = clock.System{}
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if cfg.Server.MultiInstance && !d.Ephemeral.Shared() {
		return nil, errors.New("app: server.multi_instance requires an ephemeral store shared across instances (e.g. redis)")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	id.SetGenerators(id.Generators[cfg.IDs.Internal], id.Generators[cfg.IDs.External])
	if err := checkKeys(ctx, d.KeyStore); err != nil {
		return nil, err
	}

	var ledger []port.FeatureRecord
	if err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		ledger, err = tx.Features().List(ctx)
		return err
	}); err != nil {
		return nil, fmt.Errorf("app: read feature ledger: %w", err)
	}
	plan, err := feature.Resolve(ledger, binary, derefFeatures(cfg.Features))
	if err != nil {
		return nil, err
	}
	for _, w := range plan.Warnings {
		d.Logger.Warn("feature", "message", w)
	}

	a := &App{cfg: cfg, deps: d, plan: plan}
	a.checkClockSkew(ctx)
	if a.realm, err = a.ensureRealm(ctx); err != nil {
		return nil, err
	}
	a.relay = &eventlog.Relay{
		Storage: d.Storage, Sink: d.EventSink, Clock: d.Clock,
		Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
	}
	a.pii = pii.New(d.KeyStore)
	ss := cfg.Security.Session
	a.sessions = &session.Manager{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Log: d.Logger,
		Config: session.Config{
			AbsoluteLifetime: ss.AbsoluteLifetime.Default.D(), IdleTimeout: ss.IdleTimeout.Default.D(),
			ValidityMaxDelay: ss.ValidityMaxDelay.D(), RotationInterval: ss.RotationInterval.D(), RotationGrace: ss.RotationGrace.D(),
		},
	}
	via := make([]port.VerifiedVia, 0, len(cfg.Realm.VerifiedVia))
	for _, v := range cfg.Realm.VerifiedVia {
		via = append(via, port.VerifiedVia(v))
	}
	if !slices.Contains(via, port.VerifiedViaCode) {
		d.Logger.Warn("realm.verified_via does not include code: email codes and links are disabled, and email recovery is unavailable")
	}
	a.accounts = &account.Service{Crypter: a.pii, Clock: d.Clock, VerifiedVia: via}
	a.notify = &notify.Service{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock}
	a.email = &emailflow.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions,
		Notify: a.notify, Log: d.Logger,
		Config: emailflow.Config{TTL: cfg.Security.EmailFlow.TTL.D(), MaxAttempts: cfg.Security.EmailFlow.MaxAttempts},
	}
	a.oauth = &oauth.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions,
		Dev: cfg.Dev, TTL: cfg.Security.EmailFlow.TTL.D(), Log: d.Logger,
	}
	a.notifier = &eventlog.Relay{
		Storage: d.Storage, Topic: notify.Topic, Deliver: notify.Deliverer(d.Notifier, d.Logger), Clock: d.Clock,
		Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
	}
	a.public = withCommon(newPublicHandler(a))
	a.admin = withCommon(newAdminHandler(a))
	return a, nil
}

func derefFeatures(f *[]string) []string {
	if f == nil {
		return nil
	}
	if *f == nil {
		return []string{}
	}
	return *f
}

// checkKeys は現在の鍵が取り出せることを確かめる。鍵が無いまま個人情報を書き始めないため。
func checkKeys(ctx context.Context, ks port.KeyStore) error {
	mid, err := ks.CurrentMasterKeyID(ctx)
	if err != nil {
		return fmt.Errorf("app: keystore: %w", err)
	}
	if k, err := ks.MasterKey(ctx, mid); err != nil || len(k) != pii.KeySize {
		return fmt.Errorf("app: keystore: master key %q unusable: %v", mid, err)
	}
	iid, err := ks.CurrentIndexKeyID(ctx)
	if err != nil {
		return fmt.Errorf("app: keystore: %w", err)
	}
	if k, err := ks.IndexKey(ctx, iid); err != nil || len(k) != pii.KeySize {
		return fmt.Errorf("app: keystore: index key %q unusable: %v", iid, err)
	}
	return nil
}

func (a *App) checkClockSkew(ctx context.Context) {
	dbNow, err := a.deps.Storage.Now(ctx)
	if err != nil {
		a.deps.Logger.Warn("could not read database clock", "error", err)
		return
	}
	skew := a.deps.Clock.Now().Sub(dbNow).Abs()
	if limit := a.cfg.Server.ClockSkewWarn.D(); limit > 0 && skew > limit {
		a.deps.Logger.Warn("clock skew between IAM and database", "skew", skew.String(), "threshold", limit.String())
	}
}

// ensureRealm は設定の realm が無ければ作る（監査ログにも残す）。
func (a *App) ensureRealm(ctx context.Context) (port.Realm, error) {
	var r port.Realm
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		r, err = tx.Realms().GetBySlug(ctx, a.cfg.Realm.Slug)
		if err == nil || !errors.Is(err, errs.NotFound) {
			return err
		}
		settings, _ := json.Marshal(map[string]any{"timezone": a.cfg.Realm.Timezone})
		r = port.Realm{ID: id.NewExternal(id.Realm), Slug: a.cfg.Realm.Slug, Settings: settings, CreatedAt: a.deps.Clock.Now()}
		if err := tx.Realms().Create(ctx, r); err != nil {
			return err
		}
		_, err = eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "realm.created", Result: audit.ResultSuccess, RealmID: r.ID,
			Actor: audit.Actor{Type: "system"}, Details: map[string]any{"slug": r.Slug},
		})
		return err
	})
	return r, err
}

// Plan は起動時に決まったフィーチャーの構成を返す。
func (a *App) Plan() feature.Plan { return a.plan }

// Realm は既定の realm を返す。
func (a *App) Realm() port.Realm { return a.realm }

// PublicHandler は公開 API のハンドラを返す（テスト用）。
func (a *App) PublicHandler() http.Handler { return a.public }

// AdminHandler は管理 API のハンドラを返す（テスト用）。
func (a *App) AdminHandler() http.Handler { return a.admin }

// Run は公開 API と管理 API を待ち受け、ctx が終わったら止める。
func (a *App) Run(ctx context.Context) error {
	pubL, err := net.Listen("tcp", a.cfg.Server.PublicAddr)
	if err != nil {
		return err
	}
	admL, err := net.Listen("tcp", a.cfg.Server.AdminAddr)
	if err != nil {
		_ = pubL.Close()
		return err
	}
	return a.Serve(ctx, pubL, admL)
}

// Serve は与えられたリスナーで待ち受ける。
func (a *App) Serve(ctx context.Context, pubL, admL net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, a.deps.Clock, audit.Event{
			Type: "system.started", Result: audit.ResultSuccess, RealmID: a.realm.ID,
			Actor: audit.Actor{Type: "system"}, Details: map[string]any{"features": a.plan.Active},
		})
		return err
	}); err != nil {
		return err
	}

	servers := []*http.Server{newHTTPServer(a.public), newHTTPServer(a.admin)}
	errc := make(chan error, 3)
	for i, l := range []net.Listener{pubL, admL} {
		go func() { errc <- servers[i].Serve(l) }()
	}
	relayDone, notifyDone := make(chan struct{}), make(chan struct{})
	go func() { a.relay.Run(ctx); close(relayDone) }()
	go func() { a.notifier.Run(ctx); close(notifyDone) }()

	a.deps.Logger.Info("iam started", "public", pubL.Addr().String(), "admin", admL.Addr().String(),
		"realm", a.realm.Slug, "features", a.plan.Active)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	<-relayDone
	<-notifyDone
	// 止める前に残りを送る（届かなければ次の起動で送る）。
	for _, r := range []*eventlog.Relay{a.relay, a.notifier} {
		if _, err := r.Flush(shutdownCtx); err != nil {
			a.deps.Logger.Warn("final outbox flush failed", "topic", r.Topic, "error", err)
		}
	}
	return runErr
}

// newHTTPServer は遅いクライアントで接続を占有されないよう、各段階に時間の上限を付ける。
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}
