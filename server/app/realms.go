package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

// 複数 realm（design.md 11.1、ADR 0083）。1つの App のまま、要求ごとにホスト名かパス（/realms/{slug}）から realm を決め、
// その realm のサービスの組（realm ごとの設定・issuer・passkey の RP を持つ App）に渡す。アダプタ・outbox の送出・予約の
// 処理・保持期間の掃除は既定の realm の App（root）が持ち、全 realm で共有する。

// realmPathPrefix は realm をパスで指すときの接頭辞。
const realmPathPrefix = "/realms/"

// realmSettings は realm ごとに変えられる設定（ADR 0083）。既定の realm は設定ファイルの realm の値を使う。
// 時間は秒で持つ（API と同じ）。
type realmSettings struct {
	Timezone                 string             `json:"timezone"`
	VerifiedVia              []string           `json:"verified_via"`
	OrgCreation              string             `json:"org_creation"`
	OrgDeletionGraceSeconds  int64              `json:"org_deletion_grace_seconds"`
	UserDeletionGraceSeconds int64              `json:"user_deletion_grace_seconds"`
	EmailStorage             string             `json:"email_storage"`
	QuotaCount               realmQuotaSettings `json:"quota_count"`
}

type realmQuotaSettings struct {
	Invited   bool `json:"invited"`
	Future    bool `json:"future"`
	Suspended bool `json:"suspended"`
}

// defaultRealmSettings は設定ファイルの realm の値（既定の realm の設定で、新しい realm の既定値）。
func defaultRealmSettings(c config.Realm) realmSettings {
	return realmSettings{
		Timezone: c.Timezone, VerifiedVia: slices.Clone(c.VerifiedVia), OrgCreation: c.OrgCreation,
		OrgDeletionGraceSeconds: int64(c.OrgDeletionGrace.D() / time.Second), UserDeletionGraceSeconds: int64(c.UserDeletionGrace.D() / time.Second),
		EmailStorage: c.EmailStorage, QuotaCount: realmQuotaSettings(c.QuotaCount),
	}
}

// parseRealmSettings は保存した設定を、設定ファイルの値に重ねて読む（保存の後に足した項目は設定ファイルの値になる）。
func parseRealmSettings(c config.Realm, raw []byte) (realmSettings, error) {
	s := defaultRealmSettings(c)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return realmSettings{}, fmt.Errorf("realm settings: %w", err)
		}
	}
	return s, s.validate()
}

func (s realmSettings) validate() error {
	var problems []string
	if _, err := time.LoadLocation(s.Timezone); err != nil {
		problems = append(problems, "timezone")
	}
	for _, v := range s.VerifiedVia {
		if !slices.Contains(config.KnownVerifiedVia, v) {
			problems = append(problems, "verified_via")
			break
		}
	}
	if !slices.Contains(config.KnownOrgCreation, s.OrgCreation) {
		problems = append(problems, "org_creation")
	}
	if !slices.Contains(config.KnownEmailStorage, s.EmailStorage) {
		problems = append(problems, "email_storage")
	}
	if s.OrgDeletionGraceSeconds < 0 || s.UserDeletionGraceSeconds < 0 {
		problems = append(problems, "deletion_grace")
	}
	if len(problems) > 0 {
		return errs.WithCode(errs.KindInvalid, "invalid_realm_settings", "invalid realm settings: "+strings.Join(problems, ", "))
	}
	return nil
}

func (s realmSettings) orgDeletionGrace() time.Duration {
	return time.Duration(s.OrgDeletionGraceSeconds) * time.Second
}
func (s realmSettings) userDeletionGrace() time.Duration {
	return time.Duration(s.UserDeletionGraceSeconds) * time.Second
}

// realmEndpoint は realm の外から見た場所。
type realmEndpoint struct {
	// issuer は OIDC の iss と、Org 専用 SSO の戻り先の基点。server.public_url が無ければ空。
	issuer string
	// base は /realms/{slug} で指すときのパスの接頭辞。既定の realm とホスト名で指す realm では空。
	base string
	// rpID・rpName・origins は passkey の Relying Party。決まらなければ ok が false。
	rpID, rpName string
	origins      []string
	rpOK         bool
}

// endpointFor は realm の場所を決める。既定の realm は設定のまま。ホスト名を持つ realm は最初のホスト名を正とし（issuer と
// passkey の RP）、持たない realm は server.public_url の下の /realms/{slug} に置く（passkey の RP は既定の realm と同じ）。
func endpointFor(cfg config.Config, r port.Realm, isDefault bool) realmEndpoint {
	public := strings.TrimSuffix(cfg.Server.PublicURL, "/")
	rpID, rpName, origins, ok := cfg.PasskeyRP()
	e := realmEndpoint{issuer: public, rpID: rpID, rpName: rpName, origins: origins, rpOK: ok}
	if isDefault {
		return e
	}
	e.rpName = r.Slug
	if len(r.Hosts) == 0 {
		e.base = realmPathPrefix + r.Slug
		if public != "" {
			e.issuer = public + e.base
		}
		return e
	}
	scheme, port := "https", ""
	if u, err := url.Parse(public); err == nil && u.Host != "" {
		scheme = u.Scheme
		if p := u.Port(); p != "" {
			port = ":" + p
		}
	}
	origin := scheme + "://" + r.Hosts[0] + port
	e.issuer, e.rpID, e.origins, e.rpOK = origin, r.Hosts[0], []string{origin}, true
	return e
}

// cookie は realm の Cookie の名前。/realms/{slug} で指す realm は同じホストで既定の realm と並ぶため、名前に slug を付ける
// （`__Host-` は Path=/ を求めるので、パスでは分けられない）。
func (a *App) cookie(name string) string {
	if a.base == "" {
		return name
	}
	return name + "." + a.realm.Slug
}

// ---------------------------------------------------------------------------

// realmTable は既定以外の realm の App。root だけが持つ。refresh ごとに DB の realm を読み直し、更新された realm の
// App を作り直す（他のインスタンスで作った・変えた realm は refresh の間隔の内に反映される）。
type realmTable struct {
	mu      sync.RWMutex
	byID    map[string]*App
	bySlug  map[string]*App
	byHost  map[string]*App
	loaded  time.Time
	refresh time.Duration
	// reload は refresh を1つに絞る。
	reload sync.Mutex
}

// loadRealms は DB の realm を読み、既定以外の realm の App を（変わったものだけ）作り直す。
func (a *App) loadRealms(ctx context.Context) error {
	a.realms.reload.Lock()
	defer a.realms.reload.Unlock()
	return a.loadRealmsLocked(ctx)
}

// loadRealmsLocked は loadRealms の本体。呼び出し側が reload を持つ。
func (a *App) loadRealmsLocked(ctx context.Context) error {
	t := a.realms
	var list []port.Realm
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		list, err = tx.Realms().List(ctx)
		return err
	}); err != nil {
		return err
	}
	t.mu.RLock()
	old := t.byID
	t.mu.RUnlock()
	byID, bySlug, byHost := map[string]*App{}, map[string]*App{}, map[string]*App{}
	for _, r := range list {
		if r.ID == a.realm.ID {
			continue
		}
		ra := old[r.ID]
		if ra == nil || !ra.realm.UpdatedAt.Equal(r.UpdatedAt) || !slices.Equal(ra.realm.Hosts, r.Hosts) {
			var err error
			if ra, err = a.newRealmApp(ctx, r); err != nil {
				// 1つの realm の誤りで他の realm を止めない。
				a.deps.Logger.ErrorContext(ctx, "realm: cannot assemble", "realm", r.Slug, "error", err)
				if ra = old[r.ID]; ra == nil {
					continue
				}
			}
		}
		byID[r.ID], bySlug[r.Slug] = ra, ra
		for _, h := range ra.realm.Hosts {
			byHost[h] = ra
		}
	}
	t.mu.Lock()
	t.byID, t.bySlug, t.byHost, t.loaded = byID, bySlug, byHost, a.deps.Clock.Now()
	t.mu.Unlock()
	return nil
}

// newRealmApp は既定以外の realm の App を作る。共有の部分は root のものを使う。
func (a *App) newRealmApp(ctx context.Context, r port.Realm) (*App, error) {
	rs, err := parseRealmSettings(a.cfg.Realm, r.Settings)
	if err != nil {
		return nil, err
	}
	ra := &App{cfg: a.cfg, deps: a.deps, plan: a.plan, binary: a.binary, clientSealer: a.clientSealer, pii: a.pii, hookSecrets: a.hookSecrets,
		relay: a.relay, notifier: a.notifier, logout: a.logout, scheduler: a.scheduler, retention: a.retention, root: a}
	if err := ra.assemble(ctx, r, rs, endpointFor(a.cfg, r, false)); err != nil {
		return nil, err
	}
	ra.public, ra.admin = ra.ownPublic, ra.ownAdmin
	return ra, nil
}

// RealmApp は slug の realm の App を返す（CLI が既定以外の realm を扱う）。既定の realm の slug なら a。
func (a *App) RealmApp(slug string) (*App, error) {
	root := a.root
	if slug == root.realm.Slug {
		return root, nil
	}
	if root.realms == nil {
		return nil, errs.New(errs.KindFailedPrecondition, "multi_realm is not active")
	}
	if err := root.loadRealms(context.Background()); err != nil {
		return nil, err
	}
	root.realms.mu.RLock()
	defer root.realms.mu.RUnlock()
	if ra := root.realms.bySlug[slug]; ra != nil {
		return ra, nil
	}
	return nil, errs.New(errs.KindNotFound, "realm %q", slug)
}

// BaseURL はこの realm のログイン画面の基点の URL（issuer と同じ。server.public_url が無ければ空）。
func (a *App) BaseURL() string { return a.issuer }

// forRealm は realm の ID の App を返す（既定の realm なら root）。予約の処理など、要求の外で realm を決める。表だけを見る
// （トランザクションの中から呼ばれるため DB を読まない）。表に無ければ ok が false。
func (a *App) forRealm(realmID string) (*App, bool) {
	root := a.root
	if realmID == root.realm.ID {
		return root, true
	}
	if root.realms == nil {
		return nil, false
	}
	root.realms.mu.RLock()
	defer root.realms.mu.RUnlock()
	ra := root.realms.byID[realmID]
	return ra, ra != nil
}

// refreshRealms は間隔を過ぎていれば realm を読み直す。読めなければ今の表のまま続ける。トランザクションの外で呼ぶ。
// 他の要求が読み直していれば待たずに今の表を使う（要求ごとに読み直しが並ばない）。
func (a *App) refreshRealms(ctx context.Context) {
	t := a.realms
	if t == nil || !a.realmsStale() || !t.reload.TryLock() {
		return
	}
	defer t.reload.Unlock()
	if !a.realmsStale() {
		return // 確かめてからロックを取るまでに、他の要求が読み直した
	}
	if err := a.loadRealmsLocked(ctx); err != nil {
		a.deps.Logger.WarnContext(ctx, "realm: reload failed", "error", err)
	}
}

func (a *App) realmsStale() bool {
	t := a.realms
	t.mu.RLock()
	defer t.mu.RUnlock()
	return a.deps.Clock.Now().Sub(t.loaded) >= t.refresh
}

// watchRealms は ctx が終わるまで、refresh の間隔で realm を読み直す。
func (a *App) watchRealms(ctx context.Context) {
	t := time.NewTicker(max(a.realms.refresh, time.Second))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.refreshRealms(ctx)
		}
	}
}

// realmHandler は予約の処理を、出来事の realm の App で行う。まだ表に無い realm（他のインスタンスで作ったばかり）の出来事は
// エラーにして、次の回に回す。
func (a *App) realmHandler(pick func(*App) eventlog.Handler) eventlog.Handler {
	return func(ctx context.Context, tx port.Tx, e port.ScheduledEvent, details map[string]any) error {
		ra, ok := a.forRealm(e.RealmID)
		if !ok {
			return fmt.Errorf("realm %s is not loaded yet", e.RealmID)
		}
		return pick(ra)(ctx, tx, e, details)
	}
}

// issuerOf は realm の iss（Back-Channel Logout の送出に使う）。realm の行から決める（表を待たない）。
func (a *App) issuerOf(ctx context.Context, tx port.Tx, realmID string) (string, error) {
	if realmID == a.realm.ID {
		return a.issuer, nil
	}
	r, err := tx.Realms().Get(ctx, realmID)
	if err != nil {
		return "", err
	}
	return endpointFor(a.cfg, r, false).issuer, nil
}

// indexOnlyRealms はメールの最小化モードの realm（保持期間の掃除に使う）。
func (a *App) indexOnlyRealms() []string {
	var out []string
	if a.accounts.IndexOnly {
		out = append(out, a.realm.ID)
	}
	if a.realms == nil {
		return out
	}
	a.refreshRealms(context.Background())
	a.realms.mu.RLock()
	defer a.realms.mu.RUnlock()
	for id, ra := range a.realms.byID {
		if ra.accounts.IndexOnly {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// dispatch は要求の realm を決め、その realm のハンドラに渡す。ホスト名が realm のものならその realm、/realms/{slug} なら
// （ホスト名を持たない）その realm、どちらでもなければ既定の realm。知らない slug は 404。
func (a *App) dispatch(own http.Handler, admin bool) http.Handler {
	notFound := withCommon(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "realm_not_found")
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.refreshRealms(r.Context())
		ra, rest, ok := a.resolve(r)
		if !ok {
			notFound.ServeHTTP(w, r)
			return
		}
		if ra == nil {
			own.ServeHTTP(w, r)
			return
		}
		h := ra.ownPublic
		if admin {
			h = ra.ownAdmin
		}
		if rest != "" {
			r2 := r.Clone(r.Context())
			r2.URL.Path, r2.URL.RawPath = rest, ""
			r = r2
		}
		h.ServeHTTP(w, r)
	})
}

// resolve は要求の realm（既定の realm なら nil）と、realm の接頭辞を外したパス（外さなければ空）を返す。
func (a *App) resolve(r *http.Request) (ra *App, rest string, ok bool) {
	t := a.realms
	t.mu.RLock()
	defer t.mu.RUnlock()
	if x := t.byHost[normalizeHost(r.Host)]; x != nil {
		return x, "", true
	}
	if !strings.HasPrefix(r.URL.Path, realmPathPrefix) {
		return nil, "", true
	}
	slug, tail, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, realmPathPrefix), "/")
	x := t.bySlug[slug]
	if x == nil || len(x.realm.Hosts) > 0 {
		return nil, "", false
	}
	return x, "/" + tail, true
}

// normalizeHost は Host ヘッダーを、ポートを外した小文字にする。
func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

var (
	realmSlugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	hostLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// validHost はホスト名（ポートなし、小文字の DNS 名）かを返す。
func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if !hostLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}
