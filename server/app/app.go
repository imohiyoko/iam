// Package app は設定とアダプタから IAM を組み立てて起動する（design.md 2.2 の server/）。
//
// 起動時の安全装置：
//   - フィーチャー台帳とバイナリの構成が合わなければ起動を拒否する（11.12）
//   - 複数インスタンスで共有できない EphemeralStore を使う構成を拒否する（2.4）
//   - DB との時刻のずれを警告する（2.7）
package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/authn/botcheck"
	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/device"
	"github.com/imohiyoko/iam/authn/dpop"
	"github.com/imohiyoko/iam/authn/emailflow"
	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/authn/hook"
	"github.com/imohiyoko/iam/authn/lockout"
	"github.com/imohiyoko/iam/authn/loginlink"
	"github.com/imohiyoko/iam/authn/merge"
	"github.com/imohiyoko/iam/authn/method"
	dirldap "github.com/imohiyoko/iam/authn/method/ldap"
	passkeym "github.com/imohiyoko/iam/authn/method/passkey"
	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	pwm "github.com/imohiyoko/iam/authn/method/password"
	totpm "github.com/imohiyoko/iam/authn/method/totp"
	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/password"
	"github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/recovery"
	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/authn/workloadidentity"
	"github.com/imohiyoko/iam/authn/wsfed"
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
	// FIDOMDS は FIDO Metadata Service の BLOB の取得（フィーチャー passkey_attestation。ADR 0096）。nil なら MDS を読まない。
	FIDOMDS port.FIDOMetadataSource
	// SMS と Push は認証方式の送信（フィーチャー sms_otp・push_auth。ADR 0104）。フィーチャーが動いていて nil なら起動しない。
	SMS  port.SMSSender
	Push port.PushSender
	// GeoIP は接続元の場所を引く（フィーチャー login_risk。ADR 0105）。nil なら ip のリスクを評価しない。
	GeoIP port.GeoIP
	// BotVerifier はボットの確認のトークンを確かめる（フィーチャー bot_protection。ADR 0105）。フィーチャーが動いていれば必須。
	BotVerifier port.BotVerifier
	// DNS は Org のドメインの証明で TXT を引く。nil なら net.DefaultResolver。
	DNS org.TXTResolver
	// Hooks は Go のインターフェースで実装したフロー フック（11.8）。設定の hooks で url の無いものに使う。
	Hooks map[string]port.FlowHook
	// Methods は Go のインターフェースで実装した認証方式のプラグイン（組み込みとテスト用。ADR 0092）。フィーチャーを問わずに動く。
	// features/<name> で登録した方式は、フィーチャーが動いているときだけ動く。
	Methods []port.Authenticator
	Clock   clock.Clock
	Logger  *slog.Logger
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
	// hookSecrets はフローフックの Webhook の秘密（secret_env ごと。どの realm も使う）。
	hookSecrets map[string][]byte
	realm       port.Realm
	// root は既定の realm の App（共有の部分と realm の表を持つ）。既定の realm では自分（ADR 0083）。
	root *App
	// base は realm を /realms/{slug} で指すときのパスの接頭辞。既定の realm とホスト名で指す realm では空。
	base string
	// settings は realm ごとの設定（ADR 0083）。
	settings realmSettings
	// realms は既定以外の realm の App。フィーチャー multi_realm が動いている root だけが持つ。
	realms *realmTable
	relay  *eventlog.Relay
	pii    *pii.Crypter
	// sessions はセッションの発行・検証（authn/session）。
	sessions *session.Manager
	accounts *account.Service
	// merge はアカウント統合（11.6）。フィーチャー account_merge が動いていなければ nil。
	merge *merge.Service
	// orgs は Org と Membership（4.4、11.13）。フィーチャー org が動いていなければ nil。
	orgs   *org.Service
	notify *notify.Service
	email  *emailflow.Service
	oauth  *oauth.Service
	// saml は外部 IdP としての SAML 2.0（ADR 0098）。フィーチャー saml が動いていなければ nil。
	saml *saml.Service
	// wsfed は WS-Federation のパッシブ要求者プロファイル（iam が IdP。ADR 0110）。フィーチャー wsfed が動いていないか、
	// issuer（server.public_url）が無ければ nil。
	wsfed *wsfed.Service
	// samlIdP は SAML 2.0 の IdP（iam が IdP。ADR 0115）。フィーチャー saml_idp が動いていないか、issuer（server.public_url）が無ければ nil。
	samlIdP *samlidp.Service
	// par は Pushed Authorization Requests（RFC 9126。ADR 0112）が動いているか（フィーチャー par）。
	par bool
	// fapi2 は FAPI 2.0 Security Profile（ADR 0117）が動いているか（フィーチャー fapi2）。偽なら realm の設定の
	// fapi2_security_profile は見ない（連携先の設定は無効化で外れるまで強いる。fail-closed）。
	fapi2 bool
	// resources は自前の API（リソースサーバー）の登録（RFC 8707。ADR 0112）。フィーチャー resource_indicators が
	// 動いていなければ nil。
	resources *provider.Resources
	// ldap は LDAP / Active Directory のバインド認証と同期（ADR 0102）。フィーチャー ldap が動いていなければ nil。
	ldap *dirldap.Service
	// metadata は認証器のメタデータ（フィーチャー passkey_attestation。ADR 0096）。root だけが持ち、全 realm で共有する。
	// フィーチャーが動いていなければ nil。
	metadata *attestation.Metadata
	// methods は動いている認証方式のプラグイン、credentials はそれを呼ぶコアのサービス（ADR 0092）。
	methods     *method.Set
	credentials *credential.Service
	// password はメール + パスワード。フィーチャー password が動いていなければ nil。
	password *password.Service
	perIP    *ratelimit.Limiter
	// lockout・devices・bot はログインの守り（ADR 0105）。フィーチャー account_lockout・device_recognition・bot_protection が
	// 動いていなければ nil。
	lockout *lockout.Guard
	devices *device.Service
	bot     *botcheck.Guard
	links   *loginlink.Service
	// recovery はリカバリーコードと復旧の完了（4.12）。
	recovery *recovery.Service
	notifier *eventlog.Relay
	// logout は Back-Channel Logout を送る（ADR 0066）。
	logout *eventlog.Relay
	// mtls はクライアント証明書を求める専用の待ち受けのハンドラ、mtlsTLS はその TLS の設定（ADR 0103）。設定が無ければ nil。
	mtls    http.Handler
	mtlsTLS *tls.Config
	// serviceAccounts はサービスアカウントの管理と client credentials（ADR 0074）。
	serviceAccounts *serviceaccount.Service
	// workloadIdentity は Workload Identity Federation（ADR 0116）。フィーチャー workload_identity が動いていなければ nil。
	workloadIdentity *workloadidentity.Service
	// clients と keys は OIDC Provider の連携先と ID トークンの署名鍵（5.5、9.3）。
	clients *provider.Clients
	keys    *provider.Keys
	// issuer は OIDC の iss（server.public_url）。空なら OIDC Provider のエンドポイントを出さない。
	issuer string
	flow   *provider.Flow
	tokens *provider.Tokens
	// device は Device Authorization Grant（ADR 0095）。フィーチャー device_flow が動いていなければ nil。deviceTmpl はその画面。
	device     *provider.Device
	deviceTmpl *template.Template
	// ciba は CIBA（ADR 0114）。フィーチャー ciba が動いていなければ nil。cibaHTTP は ping の通知に使う（nil なら既定）。
	ciba     *provider.Backchannel
	cibaHTTP *http.Client
	// impersonationLimit は運営者ごとのなりすましの回数の上限（フィーチャー impersonation。ADR 0099）。
	impersonationLimit *ratelimit.Limiter
	// logoutTmpl はログアウトの画面（ADR 0094）。フィーチャー oidc_logout が動いていなければ nil。
	logoutTmpl *template.Template
	// authz は認可の判定（ADR 0064）。manage はロール・付与・Group の管理。
	authz  *check.Checker
	manage *manage.Service
	// attributes はカスタム属性（design.md 11.7）。フィーチャー custom_attributes が動いていなければ nil。
	attributes *attribute.Service
	// scheduler は時刻の境界の出来事（停止・有効期間）を監査ログに出す（design.md 4.8）。
	scheduler *eventlog.Scheduler
	retention *eventlog.Retention
	// eventSubs はイベントの Webhook の購読（ADR 0100）。フィーチャー event_subscriptions が動いていなければ nil。
	// eventSubTests はテスト送信の回数の上限。subDelivery は購読の配送（全 realm で1つ。root だけが持つ）。
	eventSubs     *eventsub.Service
	eventSubTests *ratelimit.Limiter
	subDelivery   *eventsub.Deliverer
	// domainRecheck は証明済みのドメインを確かめ直す（ADR 0087）。フィーチャー org_managed_users が無いか、間隔が 0 なら nil。
	domainRecheck *org.DomainRechecker
	// public と admin は待ち受けるハンドラ（複数 realm なら振り分け）。ownPublic と ownAdmin はこの realm のもの。
	public, admin       http.Handler
	ownPublic, ownAdmin http.Handler
	// pats は本人の Personal Access Token（ADR 0109）。フィーチャー personal_access_tokens が動いていなければ nil。
	pats *pat.Service
	// dpop は DPoP の証明の確かめ、oauthMTLS は mTLS の連携先の認証（ADR 0113）。フィーチャー dpop・mtls_client_auth が
	// 動いていなければ nil。
	dpop      *dpop.Verifier
	oauthMTLS *provider.MTLS
	// ssfTx と ssfRx は OpenID Shared Signals Framework の送信側と受信側（ADR 0118）。フィーチャー ssf_transmitter・ssf_receiver が
	// 動いていなければ nil。ssfVerifyLimit は検証のイベントの回数の上限、ssfDelivery は push の配送（全 realm で1つ。root だけが持つ）。
	ssfTx          *ssf.Transmitter
	ssfRx          *ssf.Receiver
	ssfVerifyLimit *ratelimit.Limiter
	ssfDelivery    *ssf.Deliverer
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

	// 監査ログの IP と User-Agent の全文は、本人のデータ鍵と日ごとの鍵で暗号化する（ADR 0063）。
	// 監査ログは最初の1件（新しい DB のフィーチャーの記録）から監査の鍵で鍵付きにする（ADR 0086）。
	crypter := pii.New(d.KeyStore)
	clientSealer := &eventlog.ClientSealer{Crypter: crypter, Clock: d.Clock, Retention: cfg.Realm.ClientDataRetention.D()}
	if ak, ok := d.KeyStore.(port.AuditKeyStore); ok {
		clientSealer.AuditKeys = ak
	}
	d.Storage = clientSealer.Storage(d.Storage)

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

	a := &App{cfg: cfg, deps: d, plan: plan, binary: binary, clientSealer: clientSealer, pii: crypter}
	a.root = a
	a.checkClockSkew(ctx)
	realm, err := a.ensureRealm(ctx)
	if err != nil {
		return nil, err
	}
	a.relay = &eventlog.Relay{
		Storage: d.Storage, Sink: d.EventSink, Clock: d.Clock,
		Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
	}
	if !slices.Contains(cfg.Realm.VerifiedVia, string(port.VerifiedViaCode)) {
		d.Logger.Warn("realm.verified_via does not include code: email codes and links are disabled, and email recovery is unavailable")
	}
	if plan.IsActive(feature.BotProtection) && d.BotVerifier == nil {
		return nil, errors.New("app: the bot_protection feature requires bot_check.driver")
	}
	if plan.IsActive(feature.FlowHooks) {
		if a.hookSecrets, err = hookSecrets(cfg); err != nil {
			return nil, err
		}
	}
	if plan.IsActive(feature.PasskeyAttestation) {
		if a.metadata, err = newMetadata(ctx, cfg, d); err != nil {
			return nil, err
		}
	} else if !cfg.Realm.PasskeyPolicy.Empty() || cfg.Passkey.Attestation.Conveyance != "" {
		d.Logger.Warn("passkey attestation settings are configured but the passkey_attestation feature is not active")
	}
	if err := a.assemble(ctx, realm, defaultRealmSettings(cfg.Realm), endpointFor(cfg, realm, true)); err != nil {
		return nil, err
	}
	if a.issuer == "" {
		d.Logger.Info("the OIDC provider is disabled: set server.public_url")
	}
	if a.passkey() == nil {
		d.Logger.Info("passkeys are disabled: set server.public_url or passkey.rp_id and passkey.origins")
	}
	if plan.IsActive(feature.LoginRisk) && d.GeoIP == nil {
		d.Logger.Warn("login_risk is active without geoip.driver: the ip risk is not evaluated")
	}
	if a.password != nil && d.BreachCheck == nil {
		d.Logger.Warn("password breach check is disabled: set breach_check.driver")
	}
	if !plan.IsActive(feature.FlowHooks) && len(cfg.Hooks) > 0 {
		d.Logger.Warn("hooks are configured but the flow_hooks feature is not active")
	}

	// ここから下は全 realm で共有する（ADR 0083）。realm ごとの処理は、出来事の realm の App で行う。
	a.logout = &eventlog.Relay{
		Storage: d.Storage, Topic: provider.LogoutTopic, Clock: d.Clock, Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
		Deliver: (&provider.LogoutDeliverer{Storage: d.Storage, Keys: a.keys, Clock: d.Clock, Issuer: a.issuer, IssuerOf: a.issuerOf, Log: d.Logger}).Deliver,
	}
	// 開発用の Notifier には、秘密の取り出し方を渡す（配信用のアプリ無しでメールのログインを試せるように）。
	if dc, ok := d.Notifier.(devClaimer); ok && cfg.Dev {
		dc.SetDevClaim(strings.TrimSuffix(cfg.Server.PublicURL, "/"), func(ctx context.Context, realmID, notificationID string) (string, string, string, error) {
			sec, err := a.notify.Claim(ctx, realmID, notificationID)
			return sec.To, sec.Code, sec.Token, err
		})
	}
	a.scheduler = &eventlog.Scheduler{Storage: d.Storage, Clock: d.Clock, Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
		Prepare: a.refreshRealms}
	a.scheduler.Handlers = map[string]eventlog.Handler{
		account.EventUserDeleted:       a.realmHandler(func(r *App) eventlog.Handler { return r.accounts.PurgeDue }),
		eventlog.EventClientKeyExpired: clientSealer.Expire,
		account.EventSuspensionStarted: a.realmHandler(func(r *App) eventlog.Handler { return r.endOnSuspensionStart }),
		account.EventValidityEnded:     a.realmHandler(func(r *App) eventlog.Handler { return r.endOnValidityEnd }),
	}
	if a.orgs != nil {
		a.scheduler.Handlers[org.EventOrgDeleted] = a.realmHandler(func(r *App) eventlog.Handler { return r.orgs.PurgeDue })
		a.scheduler.Handlers[org.EventInvitationExpired] = a.realmHandler(func(r *App) eventlog.Handler { return r.orgs.ExpireDue })
	}
	// 保持期間を過ぎたデータは1時間ごとに消す（design.md 6.5、9.6、ADR 0072）。
	a.retention = &eventlog.Retention{Storage: d.Storage, Clock: d.Clock, RealmID: a.realm.ID, Audit: cfg.Realm.AuditRetention.D(),
		Ended: cfg.Realm.EndedRetention.D(), Interval: time.Hour, Batch: cfg.Outbox.Batch, Log: d.Logger, IndexOnly: a.indexOnlyRealms}
	if a.eventSubs != nil {
		a.subDelivery = &eventsub.Deliverer{Storage: d.Storage, Service: a.eventSubs, Clock: d.Clock, Interval: cfg.Outbox.Interval.D(),
			Batch: cfg.Outbox.Batch, Log: d.Logger}
	}
	if a.ssfTx != nil {
		a.ssfDelivery = &ssf.Deliverer{Storage: d.Storage, Transmitter: a.ssfTx, Issuer: a.issuerOf, Clock: d.Clock,
			Interval: cfg.Outbox.Interval.D(), Log: d.Logger}
	}
	if a.orgs != nil && plan.IsActive(feature.OrgManagedUsers) && cfg.OrgDomains.Recheck.D() > 0 {
		a.domainRecheck = &org.DomainRechecker{Storage: d.Storage, Clock: d.Clock, Service: a.orgs, Every: cfg.OrgDomains.Recheck.D(),
			Grace: cfg.OrgDomains.Grace.D(), Interval: time.Hour, Batch: cfg.Outbox.Batch, Log: d.Logger}
	}
	a.notifier = &eventlog.Relay{
		Storage: d.Storage, Topic: notify.Topic, Deliver: notify.Deliverer(d.Notifier, d.Clock, d.Logger), Clock: d.Clock,
		Interval: cfg.Outbox.Interval.D(), Batch: cfg.Outbox.Batch, Log: d.Logger,
	}
	a.public, a.admin = a.ownPublic, a.ownAdmin
	if plan.IsActive(feature.MultiRealm) {
		a.realms = &realmTable{refresh: cfg.Security.Session.ValidityMaxDelay.D()}
		if err := a.loadRealms(ctx); err != nil {
			return nil, err
		}
		a.public, a.admin = a.dispatch(a.ownPublic, false), a.dispatch(a.ownAdmin, true)
	}
	// クライアント証明書の受け取り（ADR 0103）。
	cc := cfg.Server.ClientCertificates
	if cc.Header != "" {
		proxies, err := cc.ProxyPrefixes()
		if err != nil {
			return nil, err
		}
		a.public = withClientCertHeader(a.public, cc.Header, cc.HeaderFormat, proxies)
	}
	if cc.MTLSAddr != "" {
		if a.mtlsTLS, err = mtlsConfig(cc); err != nil {
			return nil, fmt.Errorf("app: server.client_certificates: %w", err)
		}
		a.mtls = mtlsHandler(a.public, plan.IsActive(feature.MTLSClientAuth))
	}
	for name := range cfg.Methods {
		if _, ok := a.methods.Get(name); !ok {
			d.Logger.Warn("methods settings are configured but the method is not active in the default realm", "method", name)
		}
	}
	return a, nil
}

// MTLSHandler は mTLS の専用の待ち受けのハンドラを返す（テスト用。設定が無ければ nil）。
func (a *App) MTLSHandler() http.Handler { return a.mtls }

// assemble は realm のサービスの組を作る（既定の realm は New から、他の realm は newRealmApp から）。共有の部分（アダプタ・
// 暗号化・outbox の送出など）は a に入っているものを使う。
func (a *App) assemble(ctx context.Context, realm port.Realm, rs realmSettings, ep realmEndpoint) error {
	cfg, d, plan := a.cfg, a.deps, a.plan
	a.realm, a.settings, a.base = realm, rs, ep.base
	ss := cfg.Security.Session
	var warnings *warning.Evaluator
	if plan.IsActive(feature.Warnings) {
		var err error
		if warnings, err = warning.New(cfg.WarningActions()); err != nil {
			return err
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
	via := make([]port.VerifiedVia, 0, len(rs.VerifiedVia))
	for _, v := range rs.VerifiedVia {
		via = append(via, port.VerifiedVia(v))
	}
	// TOTP はコアの方式で、フィーチャーを問わずに動く。パスワードは、フィーチャーが動いていれば設定を入れたものに置き換える（ADR 0101）。
	ar := cfg.Security.Password.Argon2
	builtin := []port.Authenticator{totpm.Method{}}
	var pwMethod *pwm.Method
	if plan.IsActive(feature.Password) {
		minLength := pwm.MinLength
		if cfg.Security.SecondFactor.Required {
			minLength = pwm.MinLengthWithSecondFactor
		}
		pwMethod = &pwm.Method{Params: pwm.Params{Memory: ar.MemoryKiB, Time: ar.Iterations, Threads: ar.Parallelism},
			MinLength: minLength, Breach: d.BreachCheck, Log: d.Logger}
		builtin = append(builtin, pwMethod)
	}
	// passkey はコアの方式で、Relying Party が決まる構成でだけ動く（ADR 0106）。
	var pa *passkeym.Attestation
	if m := a.root.metadata; m != nil {
		pa = &passkeym.Attestation{Metadata: m, Conveyance: cfg.Passkey.Attestation.Conveyance, Policy: rs.PasskeyPolicy}
	}
	if ep.rpOK {
		pk, err := passkeym.New(passkeym.Config{RPID: ep.rpID, RPName: ep.rpName, Origins: ep.origins}, pa)
		if err != nil {
			return err
		}
		builtin = append(builtin, pk)
	}
	methods, err := method.ActiveWith(ctx, plan.IsActive, a.methodSetup(realm.ID, realm.Slug, ep.issuer), append(builtin, d.Methods...)...)
	if err != nil {
		return err
	}
	// realm の設定で止めた方式（ADR 0104）は、この realm では無いものとして扱う。
	methods = methods.Without(rs.DisabledMethods)
	a.methods, a.sessions.Methods = methods, methods
	a.accounts = &account.Service{Crypter: a.pii, Clock: d.Clock, VerifiedVia: via, ExtraCategories: cfg.Security.SuspensionCategories,
		DeletionGrace: rs.userDeletionGrace(), IndexOnly: rs.EmailStorage == "index_only", Roles: authzRoles{}, Methods: methods}
	a.notify = &notify.Service{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock}
	if plan.IsActive(feature.Org) {
		a.orgs = &org.Service{Clock: d.Clock, Crypter: a.pii, Accounts: a.accounts, Notify: a.notify, Policy: org.CreationPolicy(rs.OrgCreation),
			DeletionGrace: rs.orgDeletionGrace(), Rules: org.Rules{
				AbsoluteLifetime: ss.AbsoluteLifetime.Rule("session.absolute_lifetime"), IdleTimeout: ss.IdleTimeout.Rule("session.idle_timeout"),
				MaxAuthAge: ss.MaxAuthAge.Rule("session.max_auth_age"), Warnings: warnings,
			}, LoginPolicies: plan.IsActive(feature.OrgLoginPolicy), Quotas: plan.IsActive(feature.Quota),
			QuotaCount: org.QuotaCount(rs.QuotaCount), ManagedUsers: plan.IsActive(feature.OrgManagedUsers), Resolver: d.DNS,
			Hierarchy: plan.IsActive(feature.OrgHierarchy), ACR: plan.IsActive(feature.ACR)}
		a.accounts.Orgs, a.sessions.Orgs = a.orgs, a.orgs
	}
	// 判定の材料のキャッシュは、セッションの検証と同じ反映の遅れの上限（5.3）まで。
	a.authz = &check.Checker{Storage: d.Storage, Clock: d.Clock, TTL: ss.ValidityMaxDelay.D(), NestedGroups: plan.IsActive(feature.NestedGroups)}
	if a.orgs != nil {
		a.authz.Members, a.authz.Hierarchy = authzMembers{}, a.orgs.Hierarchy
	}
	a.manage = &manage.Service{Checker: a.authz, Clock: d.Clock, NestedGroups: a.authz.NestedGroups}
	a.clients = &provider.Clients{Clock: d.Clock, DeviceFlow: plan.IsActive(feature.DeviceFlow), FrontChannel: plan.IsActive(feature.OIDCLogout),
		CIBA: plan.IsActive(feature.CIBA), PAR: plan.IsActive(feature.PAR), DPoP: plan.IsActive(feature.DPoP), MTLS: plan.IsActive(feature.MTLSClientAuth)}
	a.fapi2 = plan.IsActive(feature.FAPI2)
	a.clients.FAPI2, a.clients.RealmFAPI2 = a.fapi2, a.fapi2 && rs.FAPI2SecurityProfile
	if err := a.setupSenderConstraint(); err != nil {
		return err
	}
	a.keys = &provider.Keys{Crypter: a.pii, Clock: d.Clock, RetiredKeyTTL: cfg.OIDC.RetiredKeyTTL.D()}
	// ID トークンの署名鍵は realm ごとに用意しておく（JWKS が空のまま公開されないように）。
	if err := d.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error { return a.keys.Ensure(ctx, tx, realm.ID) }); err != nil {
		return err
	}
	a.issuer = ep.issuer
	a.serviceAccounts = &serviceaccount.Service{Clock: d.Clock, Replay: d.Ephemeral, Audience: a.issuer,
		TokenTTL: cfg.ServiceAccounts.TokenTTL.D(), Authenticator: serviceaccount.Authenticator{Enabled: plan.IsActive(feature.ServiceAccounts), DeliveryOnly: deliveryOnly}}
	a.flow = &provider.Flow{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, CodeTTL: cfg.OIDC.CodeTTL.D(), PushedTTL: cfg.OIDC.PARRequestURITTL.D()}
	// PAR と自前の API 向けのトークン（ADR 0112）。
	a.par, a.resources = plan.IsActive(feature.PAR), nil
	if plan.IsActive(feature.ResourceIndicators) {
		a.resources = &provider.Resources{Clock: d.Clock}
		a.serviceAccounts.Resource = provider.ResourceForServiceAccount
	}
	a.workloadIdentity = nil
	if plan.IsActive(feature.WorkloadIdentity) {
		// 発行者の JWKS は公開のアドレスからだけ取得する（開発ビルドを除く。ADR 0116）。
		a.workloadIdentity = &workloadidentity.Service{Storage: d.Storage, Cache: d.Ephemeral, Clock: d.Clock, AllowPrivateNetworks: cfg.Dev, Log: d.Logger}
		a.serviceAccounts.Federation = a.workloadIdentity
	}
	a.device, a.deviceTmpl = nil, nil
	if plan.IsActive(feature.DeviceFlow) {
		a.device = &provider.Device{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, TTL: cfg.OIDC.DeviceCodeTTL.D(),
			Interval: cfg.OIDC.DevicePollInterval.D()}
		var err error
		if a.deviceTmpl, err = deviceTemplate(cfg.Server.LoginTemplates); err != nil {
			return err
		}
	}
	a.ciba = nil
	if plan.IsActive(feature.CIBA) {
		a.ciba = &provider.Backchannel{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, TTL: cfg.OIDC.CIBATTL.D(),
			Interval: cfg.OIDC.CIBAPollInterval.D()}
	}
	if plan.IsActive(feature.CustomAttributes) {
		a.attributes = &attribute.Service{Clock: d.Clock, Crypter: a.pii}
	}
	if plan.IsActive(feature.EventSubscriptions) {
		// 公開でないアドレスへの送信は開発ビルドだけ許す（ADR 0100）。
		a.eventSubs = &eventsub.Service{Crypter: a.pii, Clock: d.Clock, Dev: cfg.Dev, AllowPrivateNetworks: cfg.Dev}
		a.eventSubTests = &ratelimit.Limiter{Cache: d.Ephemeral, Clock: d.Clock, Window: time.Minute, Limit: 5}
	}
	// SSF（ADR 0118）。送り先と JWKS の取得は公開のアドレスに限る（開発ビルドだけ許す。イベントの Webhook と同じ）。
	a.ssfTx, a.ssfRx = nil, nil
	if plan.IsActive(feature.SSFTransmitter) {
		a.ssfTx = &ssf.Transmitter{Crypter: a.pii, Clock: d.Clock, Keys: a.keys, Directory: a.accounts, Dev: cfg.Dev, AllowPrivateNetworks: cfg.Dev}
		a.ssfVerifyLimit = &ratelimit.Limiter{Cache: d.Ephemeral, Clock: d.Clock, Window: time.Minute, Limit: 5}
	}
	if plan.IsActive(feature.SSFReceiver) {
		a.ssfRx = &ssf.Receiver{Storage: d.Storage, Replay: d.Ephemeral, Clock: d.Clock, Directory: a.accounts, Effects: ssfEffects{a},
			Dev: cfg.Dev, AllowPrivateNetworks: cfg.Dev, Log: d.Logger}
	}
	a.tokens = &provider.Tokens{Clock: d.Clock, Keys: a.keys, Sessions: a.sessions, Accounts: a.accounts, Orgs: a.orgs, Attributes: a.attributes, Issuer: a.issuer,
		AccessTokenTTL: cfg.OIDC.AccessTokenTTL.D(), IDTokenTTL: cfg.OIDC.IDTokenTTL.D(), GrantTTL: cfg.OIDC.RefreshTokenTTL.D(),
		ACR: plan.IsActive(feature.ACR), ResourceIndicators: a.resources != nil}
	if a.issuer != "" {
		a.sessions.Lineages = a.tokens
	}
	// Token Exchange（ADR 0099）。なりすましは token_exchange に依存する（Requires）ので、動いていれば両方動いている。
	a.tokens.TokenExchange = plan.IsActive(feature.TokenExchange)
	a.wsfed = nil
	if plan.IsActive(feature.WSFed) && a.issuer != "" {
		// RP に渡すトークンは realm の issuer と ES256 の鍵で署名する（ADR 0110）。
		a.wsfed = &wsfed.Service{Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Keys: a.keys, Tokens: a.tokens,
			Issuer: a.issuer, Attributes: a.attributes != nil, Log: d.Logger}
	}
	a.samlIdP = nil
	if plan.IsActive(feature.SAMLIdP) && a.issuer != "" {
		// SP に渡す Response は realm の issuer と ES256 の鍵で署名する（ADR 0115）。
		a.samlIdP = &samlidp.Service{Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Keys: a.keys, Tokens: a.tokens,
			Issuer: a.issuer, Attributes: a.attributes != nil, HardwareAAL: a.hardwareAAL(), Log: d.Logger}
	}
	if plan.IsActive(feature.Impersonation) {
		a.impersonationLimit = a.limiter(cfg.Security.Login.RateLimit.PerAccount)
		a.tokens.Impersonation = &provider.Impersonation{TTL: cfg.OIDC.Impersonation.TokenTTL.D(), Notify: a.notify, Authorize: a.authorizeImpersonation}
	}
	a.email = &emailflow.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions,
		Notify: a.notify, Log: d.Logger,
		Config:     emailflow.Config{TTL: cfg.Security.EmailFlow.TTL.D(), MaxAttempts: cfg.Security.EmailFlow.MaxAttempts},
		PerAccount: a.accountLimiter(),
	}
	a.perIP = a.limiter(cfg.Security.Login.RateLimit.PerIP)
	a.links = &loginlink.Service{Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Sessions: a.sessions, Log: d.Logger}
	a.recovery = &recovery.Service{
		Storage: d.Storage, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions, Notify: a.notify,
		Params:     pwm.Params{Memory: ar.MemoryKiB, Time: ar.Iterations, Threads: ar.Parallelism},
		PerAccount: a.accountLimiter(), Log: d.Logger,
	}

	a.oauth = &oauth.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions,
		Dev: cfg.Dev, TTL: cfg.Security.EmailFlow.TTL.D(), Log: d.Logger,
		// Org 専用 SSO（ADR 0077）。戻り先はホスト型ログイン画面に固定する。
		OrgRedirectURI: a.issuer + "/login/oauth/callback", AllowPrivateNetworks: cfg.Dev,
	}
	if a.orgs != nil && a.orgs.ManagedUsers {
		a.oauth.OrgSSO = a.orgs
	}
	a.saml = nil
	if plan.IsActive(feature.SAML) {
		// ACS と SP の Entity ID は realm の公開の URL から作る（Org は選べない）。
		a.saml = &saml.Service{Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, OAuth: a.oauth, BaseURL: a.issuer,
			Dev: cfg.Dev, TTL: cfg.Security.EmailFlow.TTL.D(), Log: d.Logger}
	}
	a.ldap = nil
	if plan.IsActive(feature.LDAP) {
		// 名前ごとの照合の回数の上限はパスワードと同じ（ディレクトリのアカウントのロックアウトも防ぐ。ADR 0102）。
		a.ldap = &dirldap.Service{Storage: d.Storage, Crypter: a.pii, Clock: d.Clock, OAuth: a.oauth, Accounts: a.accounts, Sessions: a.sessions,
			PerAccount: a.accountLimiter(), GroupsChanged: a.authz.Invalidate, Log: d.Logger}
	}
	if a.orgs != nil {
		a.orgs.Passkeys = pa
	}
	issuer := cfg.Security.SecondFactor.Issuer
	if issuer == "" || a.root != a {
		issuer = ep.rpName
	}
	a.credentials = &credential.Service{
		Storage: d.Storage, Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions, Methods: methods,
		Issuer: issuer, TTL: cfg.Security.SecondFactor.TTL.D(), MaxAttempts: cfg.Security.SecondFactor.MaxAttempts,
		PerUser: a.limiter(cfg.Security.Login.RateLimit.PerAccount), PerLogin: a.accountLimiter(), Log: d.Logger,
	}
	if a.ldap != nil {
		// Kerberos のプリンシパルを LDAP の connection で引く（ADR 0107）。
		a.credentials.Directory = a.ldap.UserBy
	}
	a.loginProtection(cfg, d, plan)
	a.credentials.Lockout = a.lockout
	if a.ciba != nil {
		// 本人の端末（プッシュの承認）が CIBA の要求に答えたら、要求に判断を記録する（ADR 0114）。
		a.credentials.OnBackchannel = a.backchannelAnswered
	}
	a.pats = newPATs(cfg, d, plan)
	a.password = nil
	if pwMethod != nil {
		a.password = &password.Service{
			Storage: d.Storage, Crypter: a.pii, Clock: d.Clock, Accounts: a.accounts, Sessions: a.sessions, Credentials: a.credentials,
			Method: pwMethod, PerAccount: a.accountLimiter(),
		}
	}
	if plan.IsActive(feature.AccountMerge) {
		a.merge = &merge.Service{Cache: d.Ephemeral, Crypter: a.pii, Clock: d.Clock, Sessions: a.sessions, Orgs: a.orgs}
	}
	if plan.IsActive(feature.FlowHooks) {
		runner, err := flowHooks(cfg, d, realm.Slug, a.hookSecrets)
		if err != nil {
			return err
		}
		a.accounts.Hooks, a.sessions.Hooks, a.tokens.Hooks = runner, runner, runner
		if a.orgs != nil {
			a.orgs.Hooks = runner
		}
	}
	login, err := newHosted(a, cfg.Server.LoginTemplates)
	if err != nil {
		return err
	}
	if plan.IsActive(feature.OIDCLogout) {
		if a.logoutTmpl, err = newLogoutTemplate(cfg.Server.LoginTemplates); err != nil {
			return err
		}
	}
	trusted, err := cfg.Server.TrustedProxyPrefixes()
	if err != nil {
		return err
	}
	a.ownPublic = withCommon(newPublicHandler(a, login), trusted)
	a.ownAdmin = withCommon(newAdminHandler(a), trusted)
	return nil
}

// devClaimer は開発用の Notifier（adapters/notifier/dev）が持つ。
type devClaimer interface {
	SetDevClaim(baseURL string, claim func(ctx context.Context, realmID, notificationID string) (to, code, token string, err error))
}

func (a *App) limiter(limit int) *ratelimit.Limiter {
	rl := a.cfg.Security.Login.RateLimit
	return &ratelimit.Limiter{Cache: a.deps.Ephemeral, Clock: a.deps.Clock, Window: rl.Window.D(), Limit: int64(limit)}
}

// accountLimiter はメールアドレスごとの上限（接続元ごとに per_account、接続元を問わず per_account_total）。
func (a *App) accountLimiter() *ratelimit.Limiter {
	l := a.limiter(a.cfg.Security.Login.RateLimit.PerAccount)
	l.Total = int64(a.cfg.Security.Login.RateLimit.PerAccountTotal)
	return l
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
	if aks, ok := ks.(port.AuditKeyStore); ok {
		aid, err := aks.CurrentAuditKeyID(ctx)
		if err != nil {
			return fmt.Errorf("app: keystore: %w", err)
		}
		if k, err := aks.AuditKey(ctx, aid); aid != "" && (err != nil || len(k) != pii.KeySize) {
			return fmt.Errorf("app: keystore: audit key %q unusable: %v", aid, err)
		}
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
	if a.mtls == nil {
		return a.Serve(ctx, pubL, admL)
	}
	mL, err := net.Listen("tcp", a.cfg.Server.ClientCertificates.MTLSAddr)
	if err != nil {
		_ = pubL.Close()
		_ = admL.Close()
		return err
	}
	return a.Serve(ctx, pubL, admL, tls.NewListener(mL, a.mtlsTLS))
}

// Serve は与えられたリスナーで待ち受ける。mtlsL は mTLS の専用の待ち受け（TLS のリスナー。ADR 0103）で、設定があるときだけ渡す。
func (a *App) Serve(ctx context.Context, pubL, admL net.Listener, mtlsL ...net.Listener) error {
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
	listeners := []net.Listener{pubL, admL}
	if a.mtls != nil && len(mtlsL) > 0 {
		servers, listeners = append(servers, newHTTPServer(a.mtls)), append(listeners, mtlsL[0])
	}
	errc := make(chan error, len(servers)+1)
	for i, l := range listeners {
		go func() { errc <- servers[i].Serve(l) }()
	}
	relays := []*eventlog.Relay{a.relay, a.notifier, a.logout}
	relayDone, schedDone, retDone := make(chan struct{}, len(relays)), make(chan struct{}), make(chan struct{})
	for _, r := range relays {
		go func() { r.Run(ctx); relayDone <- struct{}{} }()
	}
	go func() { a.scheduler.Run(ctx); close(schedDone) }()
	go func() { a.retention.Run(ctx); close(retDone) }()
	subDone := make(chan struct{})
	if a.subDelivery != nil {
		go func() { a.subDelivery.Run(ctx); close(subDone) }()
	} else {
		close(subDone)
	}
	ssfDone := make(chan struct{})
	if a.ssfDelivery != nil {
		go func() { a.ssfDelivery.Run(ctx); close(ssfDone) }()
	} else {
		close(ssfDone)
	}
	ldapDone := make(chan struct{})
	if a.plan.IsActive(feature.LDAP) {
		// ディレクトリの同期（ADR 0102）。connection ごとの間隔は EphemeralStore の印で決め、ここは見回りの間隔。
		go func() { a.runLDAPSync(ctx, time.Minute); close(ldapDone) }()
	} else {
		close(ldapDone)
	}
	recheckDone := make(chan struct{})
	if a.domainRecheck != nil {
		go func() { a.domainRecheck.Run(ctx); close(recheckDone) }()
	} else {
		close(recheckDone)
	}
	if a.realms != nil {
		// 他のインスタンスで作った・変えた realm を、要求が無くても読み直す（ADR 0083）。
		go a.watchRealms(ctx)
	}
	if a.metadata != nil && a.deps.FIDOMDS != nil {
		// 認証器のメタデータはバックグラウンドで読み直す（ログインの経路では取りに行かない。ADR 0096）。
		go a.metadata.Run(ctx, a.deps.FIDOMDS, metadataRefresh(a.cfg))
	}

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
	for range relays {
		<-relayDone
	}
	<-schedDone
	<-retDone
	<-subDone
	<-ssfDone
	<-recheckDone
	<-ldapDone
	// 止める前に残りを送る（届かなければ次の起動で送る）。
	for _, r := range relays {
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

// hookSecrets は Webhook のフローフックの署名の秘密を環境変数から一度だけ読み、読んだ環境変数を消す（11.8、ADR 0081）。
// どの realm の Runner もこれを使う（realm は後から増えるので、環境変数は残せない）。
func hookSecrets(cfg config.Config) (map[string][]byte, error) {
	out := map[string][]byte{}
	defer func() {
		for env := range out {
			_ = os.Unsetenv(env)
		}
	}()
	for name, h := range cfg.Hooks {
		if h.URL == "" {
			continue
		}
		if _, ok := out[h.SecretEnv]; !ok {
			out[h.SecretEnv] = []byte(os.Getenv(h.SecretEnv)) // 同じ secret_env を共有するフックがある
		}
		if len(out[h.SecretEnv]) < 32 {
			return nil, fmt.Errorf("app: hooks.%s: %s must hold a secret of at least 32 bytes", name, h.SecretEnv)
		}
	}
	return out, nil
}

// flowHooks は設定の hooks からフロー フックの Runner を作る（11.8、ADR 0081）。url の無いフックは d.Hooks から取り、
// Webhook の秘密は secrets（hookSecrets）から取る。
func flowHooks(cfg config.Config, d Deps, realm string, secrets map[string][]byte) (*hook.Runner, error) {
	r := &hook.Runner{Entries: map[string]hook.Entry{}, Realm: realm, Log: d.Logger}
	for name, h := range cfg.Hooks {
		e := hook.Entry{Timeout: h.Timeout.D(), FailOpen: h.FailOpen}
		if h.URL == "" {
			if e.Hook = d.Hooks[name]; e.Hook == nil {
				return nil, fmt.Errorf("app: hooks.%s has no url and no Go implementation", name)
			}
		} else {
			secret := secrets[h.SecretEnv]
			if len(secret) < 32 {
				return nil, fmt.Errorf("app: hooks.%s: %s must hold a secret of at least 32 bytes", name, h.SecretEnv)
			}
			e.Hook = &hook.Webhook{URL: h.URL, Secret: secret, Clock: d.Clock}
		}
		r.Entries[name] = e
	}
	return r, nil
}
