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
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/authn/loginlink"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/recovery"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/totp"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/manage"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// Deps はアダプタ（ポートの実装）。
type Deps struct {
	Storage   port.Storage
	Ephemeral port.EphemeralStore
	Notifier  port.Notifier
	KeyStore  port.KeyStore
	EventSink port.EventSink
	// BreachCheck は漏洩済みパスワードの確認。nil なら確認しない。
	BreachCheck port.BreachChecker
	Clock       clock.Clock
	Logger      *slog.Logger
}

// App は組み立て済みの IAM。
type App struct {
	cfg  config.Config
	deps Deps
	plan feature.Plan
	// binary はこのバイナリに含まれるフィーチャー（EnableFeature で使う）。
	binary []feature.Feature
	// clientSealer は監査ログの IP と User-Agent の全文を暗号化する（ADR 0063）。
	clientSealer *eventlog.ClientSealer
	realm        port.Realm
	relay        *eventlog.Relay
	pii          *pii.Crypter
	// sessions はセッションの発行・検証（authn/session）。
	sessions *session.Manager
	accounts *account.Service
	// orgs は Org と Membership（4.4、11.13）。フィーチャー org が動いていなければ nil。
	orgs   *org.Service
	notify *notify.Service
	email  *emailflow.Service
	oauth  *oauth.Service
	// passkeys は passkey の登録とログイン。Relying Party が決まらない構成（public_url も rp_id も無い）では nil。
	passkeys *passkey.Service
	// totp は TOTP の登録と照合（2要素目）。
	totp *totp.Service
	// password はメール + パスワード。フィーチャー password が動いていなければ nil。
	password *password.Service
	perIP    *ratelimit.Limiter
	links    *loginlink.Service
	// recovery はリカバリーコードと復旧の完了（4.12）。
	recovery *recovery.Service
	notifier *eventlog.Relay
	// clients と keys は OIDC Provider の連携先と ID トークンの署名鍵（5.5、9.3）。
	clients *provider.Clients
	keys    *provider.Keys
	// issuer は OIDC の iss（server.public_url）。空なら OIDC Provider のエンドポイントを出さない。
	issuer string
	flow   *provider.Flow
	tokens *provider.Tokens
	// authz は認可の判定（ADR 0064）。manage はロール・付与・Group の管理。
	authz  *check.Checker
	manage *manage.Service
	// scheduler は時刻の境界の出来事（停止・有効期間）を監査ログに出す（design.md 4.8）。
	scheduler *eventlog.Scheduler
	public    http.Handler
	admin     http.Handler
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

	enabled := derefFeatures(cfg.Features)
	var ledger []port.FeatureRecord
	if err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		if ledger, err = tx.Features().List(ctx); err != nil {
			return err
		}
		ledger, err = activateOnFreshInstall(ctx, tx, d.Clock, ledger, binary, enabled)
		return err
	}); err != nil {
		return nil, fmt.Errorf("app: read feature ledger: %w", err)
	}
	plan, err := feature.Resolve(ledger, binary, enabled)
	if err != nil {
		return nil, err
	}
	for _, w := range plan.Warnings {
		d.Logger.Warn("feature", "message", w)
	}

	// 監査ログの IP と User-Agent の全文は、本人のデータ鍵と日ごとの鍵で暗号化する（ADR 0063）。
	crypter := pii.New(d.KeyStore)
	clientSealer := &eventlog.ClientSealer{Crypter: crypter, Clock: d.Clock, Retention: cfg.Realm.ClientDataRetention.D()}
	d.Storage = clientSealer.Storage(d.Storage)
	a := &App{cfg: cfg, deps: d, plan: plan, binary: binary, clientSealer: clientSealer}
	a.checkClockSkew(ctx)
	if a.realm, err = a.ensureRealm(ctx); err != nil {
		return nil, err
	}
	a.relay = &eventlog.Relay{
		Storage: d.Storage, Sink: d.EventSink, Clock: d.Clock,
		Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
	}
	a.pii = crypter
	ss := cfg.Security.Session
	var warnings *warning.Evaluator
	if plan.IsActive(feature.Warnings) {
		if warnings, err = warning.New(cfg.WarningActions()); err != nil {
			return nil, err
		}
	}
	a.sessions = &session.Manager{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Log: d.Logger, Warnings: warnings,
		Config: session.Config{
			AbsoluteLifetime: ss.AbsoluteLifetime.Default.D(), IdleTimeout: ss.IdleTimeout.Default.D(), MaxAuthAge: ss.MaxAuthAge.Default.D(),
			ValidityMaxDelay: ss.ValidityMaxDelay.D(), RotationInterval: ss.RotationInterval.D(), RotationGrace: ss.RotationGrace.D(),
			RequireSecondFactor: cfg.Security.SecondFactor.Required, SecondFactorTTL: cfg.Security.SecondFactor.TTL.D(),
			RecoveryTTL: cfg.Security.Recovery.TTL.D(),
		},
	}
	via := make([]port.VerifiedVia, 0, len(cfg.Realm.VerifiedVia))
	for _, v := range cfg.Realm.VerifiedVia {
		via = append(via, port.VerifiedVia(v))
	}
	if !slices.Contains(via, port.VerifiedViaCode) {
		d.Logger.Warn("realm.verified_via does not include code: email codes and links are disabled, and email recovery is unavailable")
	}
	a.accounts = &account.Service{Crypter: a.pii, Clock: d.Clock, VerifiedVia: via, ExtraCategories: cfg.Security.SuspensionCategories,
		DeletionGrace: cfg.Realm.UserDeletionGrace.D()}
	a.notify = &notify.Service{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock}
	if plan.IsActive(feature.Org) {
		a.orgs = &org.Service{Clock: d.Clock, Crypter: a.pii, Accounts: a.accounts, Notify: a.notify, Policy: org.CreationPolicy(cfg.Realm.OrgCreation),
			DeletionGrace: cfg.Realm.OrgDeletionGrace.D(), Rules: org.Rules{
				AbsoluteLifetime: ss.AbsoluteLifetime.Rule("session.absolute_lifetime"), IdleTimeout: ss.IdleTimeout.Rule("session.idle_timeout"),
				MaxAuthAge: ss.MaxAuthAge.Rule("session.max_auth_age"), Warnings: warnings,
			}}
		a.accounts.Orgs, a.sessions.Orgs = a.orgs, a.orgs
	}
	// 判定の材料のキャッシュは、セッションの検証と同じ反映の遅れの上限（5.3）まで。
	a.authz = &check.Checker{Storage: d.Storage, Clock: d.Clock, TTL: ss.ValidityMaxDelay.D()}
	if a.orgs != nil {
		a.authz.Members = authzMembers{}
	}
	a.manage = &manage.Service{Checker: a.authz, Clock: d.Clock}
	a.clients = &provider.Clients{Clock: d.Clock}
	a.keys = &provider.Keys{Crypter: a.pii, Clock: d.Clock, RetiredKeyTTL: cfg.OIDC.RetiredKeyTTL.D()}
	// ID トークンの署名鍵は起動時に用意しておく（JWKS が空のまま公開されないように）。
	if err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return a.keys.Ensure(ctx, tx, a.realm.ID) }); err != nil {
		return nil, err
	}
	a.issuer = strings.TrimSuffix(cfg.Server.PublicURL, "/")
	if a.issuer == "" {
		d.Logger.Info("the OIDC provider is disabled: set server.public_url")
	}
	a.flow = &provider.Flow{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, CodeTTL: cfg.OIDC.CodeTTL.D()}
	a.tokens = &provider.Tokens{Clock: d.Clock, Keys: a.keys, Sessions: a.sessions, Accounts: a.accounts, Orgs: a.orgs, Issuer: a.issuer,
		AccessTokenTTL: cfg.OIDC.AccessTokenTTL.D(), IDTokenTTL: cfg.OIDC.IDTokenTTL.D(), GrantTTL: cfg.OIDC.RefreshTokenTTL.D()}
	a.email = &emailflow.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions,
		Notify: a.notify, Log: d.Logger,
		Config:     emailflow.Config{TTL: cfg.Security.EmailFlow.TTL.D(), MaxAttempts: cfg.Security.EmailFlow.MaxAttempts},
		PerAccount: a.limiter(cfg.Security.Login.RateLimit.PerAccount),
	}
	a.perIP = a.limiter(cfg.Security.Login.RateLimit.PerIP)
	a.links = &loginlink.Service{Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Sessions: a.sessions, Log: d.Logger}
	ar := cfg.Security.Password.Argon2
	a.recovery = &recovery.Service{
		Storage: d.Storage, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions, Notify: a.notify,
		Params:     password.Params{Memory: ar.MemoryKiB, Time: ar.Iterations, Threads: ar.Parallelism},
		PerAccount: a.limiter(cfg.Security.Login.RateLimit.PerAccount), Log: d.Logger,
	}

	a.oauth = &oauth.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions,
		Dev: cfg.Dev, TTL: cfg.Security.EmailFlow.TTL.D(), Log: d.Logger,
	}
	if rpID, rpName, origins, ok := cfg.PasskeyRP(); ok {
		a.passkeys, err = passkey.New(passkey.Config{RPID: rpID, RPName: rpName, Origins: origins}, passkey.Service{
			Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions, Log: d.Logger,
		})
		if err != nil {
			return nil, err
		}
	} else {
		d.Logger.Info("passkeys are disabled: set server.public_url or passkey.rp_id and passkey.origins")
	}
	issuer := cfg.Security.SecondFactor.Issuer
	if issuer == "" {
		_, issuer, _, _ = cfg.PasskeyRP()
	}
	a.totp = &totp.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Issuer: issuer,
		TTL: cfg.Security.SecondFactor.TTL.D(), MaxAttempts: cfg.Security.SecondFactor.MaxAttempts,
		PerUser: a.limiter(cfg.Security.Login.RateLimit.PerAccount), Log: d.Logger,
	}
	if plan.IsActive(feature.Password) {
		minLength := password.MinLength
		if cfg.Security.SecondFactor.Required {
			minLength = password.MinLengthWithSecondFactor
		}
		a.password = &password.Service{
			Storage: d.Storage, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions, Breach: d.BreachCheck,
			Params:    password.Params{Memory: ar.MemoryKiB, Time: ar.Iterations, Threads: ar.Parallelism},
			MinLength: minLength, PerAccount: a.limiter(cfg.Security.Login.RateLimit.PerAccount), Log: d.Logger,
		}
		if d.BreachCheck == nil {
			d.Logger.Warn("password breach check is disabled: set breach_check.driver")
		}
	}
	// 開発用の Notifier には、秘密の取り出し方を渡す（配信用のアプリ無しでメールのログインを試せるように）。
	if dc, ok := d.Notifier.(devClaimer); ok && cfg.Dev {
		dc.SetDevClaim(strings.TrimSuffix(cfg.Server.PublicURL, "/"), func(ctx context.Context, realmID, notificationID string) (string, string, string, error) {
			sec, err := a.notify.Claim(ctx, realmID, notificationID)
			return sec.To, sec.Code, sec.Token, err
		})
	}
	a.scheduler = &eventlog.Scheduler{Storage: d.Storage, Clock: d.Clock, Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger}
	a.scheduler.Handlers = map[string]eventlog.Handler{account.EventUserDeleted: a.accounts.PurgeDue,
		eventlog.EventClientKeyExpired: clientSealer.Expire}
	if a.orgs != nil {
		a.scheduler.Handlers[org.EventOrgDeleted] = a.orgs.PurgeDue
		a.scheduler.Handlers[org.EventInvitationExpired] = a.orgs.ExpireDue
	}
	a.notifier = &eventlog.Relay{
		Storage: d.Storage, Topic: notify.Topic, Deliver: notify.Deliverer(d.Notifier, d.Clock, d.Logger), Clock: d.Clock,
		Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
	}
	login, err := newHosted(a, cfg.Server.LoginTemplates)
	if err != nil {
		return nil, err
	}
	a.public = withCommon(newPublicHandler(a, login))
	a.admin = withCommon(newAdminHandler(a))
	return a, nil
}

// devClaimer は開発用の Notifier（adapters/notifier/dev）が持つ。
type devClaimer interface {
	SetDevClaim(baseURL string, claim func(ctx context.Context, realmID, notificationID string) (to, code, token string, err error))
}

func (a *App) limiter(limit int) *ratelimit.Limiter {
	rl := a.cfg.Security.Login.RateLimit
	return &ratelimit.Limiter{Cache: a.deps.Ephemeral, Clock: a.deps.Clock, Window: rl.Window.D(), Limit: int64(limit)}
}

// activateOnFreshInstall は、空の DB（台帳も realm も無い）で起動したとき、有効にするフィーチャーを台帳に
// active で記録する。片付けるデータも準備するデータも無いため、enable の手順（11.12）を省ける。
// 既存の DB では何もしない（`iam features enable` で明示的に進める）。
func activateOnFreshInstall(ctx context.Context, tx port.Tx, clk clock.Clock, ledger []port.FeatureRecord, binary []feature.Feature, enabled []string) ([]port.FeatureRecord, error) {
	if len(ledger) > 0 {
		return ledger, nil
	}
	realms, err := tx.Realms().List(ctx)
	if err != nil || len(realms) > 0 {
		return ledger, err
	}
	now := clk.Now()
	var names []string
	for _, f := range binary {
		if (enabled == nil && f.DefaultEnabled) || slices.Contains(enabled, f.Name) {
			r := port.FeatureRecord{Feature: f.Name, State: port.FeatureActive, DataVersion: f.DataVersion, UpdatedAt: now}
			if err := tx.Features().Put(ctx, r); err != nil {
				return nil, err
			}
			ledger = append(ledger, r)
			names = append(names, f.Name)
		}
	}
	if len(names) == 0 {
		return ledger, nil
	}
	_, err = eventlog.Record(ctx, tx, clk, audit.Event{
		Type: "feature.enabled", Result: audit.ResultSuccess, Actor: audit.Actor{Type: "system"},
		Details: map[string]any{"features": names, "reason": "fresh_install"},
	})
	return ledger, err
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
	relayDone, notifyDone, schedDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() { a.relay.Run(ctx); close(relayDone) }()
	go func() { a.notifier.Run(ctx); close(notifyDone) }()
	go func() { a.scheduler.Run(ctx); close(schedDone) }()

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
	<-schedDone
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
