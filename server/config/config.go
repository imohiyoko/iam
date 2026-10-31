// Package config は設定ファイル（YAML）を読む（design.md 2.8）。
//
// 起動時に決まるもの（アダプタ、フィーチャー、サーバーの既定値、realm・Org が設定できる範囲）を置く。
// 実行中に変わるもの（realm、IdP 接続、Org のポリシー）は Storage に置き、管理 API で変える。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/settings"
)

// Config は設定ファイルの全体。
type Config struct {
	// Dev は開発モード。開発専用のアダプタ（notifier の dev など）を使えるようにする。本番では false。
	Dev bool `yaml:"dev"`

	Server    Server  `yaml:"server"`
	Storage   Adapter `yaml:"storage"`
	Ephemeral Adapter `yaml:"ephemeral"`
	KeyStore  Adapter `yaml:"keystore"`
	EventSink Adapter `yaml:"event_sink"`
	Notifier  Adapter `yaml:"notifier"`
	// BreachCheck は漏洩済みパスワードの確認（フィーチャー password。design.md 4.1）。driver が空なら確認しない。
	BreachCheck Adapter `yaml:"breach_check"`

	// Features は有効にするフィーチャー名。省略すると各フィーチャーの既定に従う。
	Features *[]string `yaml:"features"`

	// Realm は最初の realm（複数 realm がオフなら唯一の realm）。
	Realm Realm `yaml:"realm"`

	// Security はホスト先が決める既定値と、realm・Org が設定できる範囲（design.md 2.8）。
	Security Security `yaml:"security"`

	Outbox Outbox `yaml:"outbox"`

	// OrgDomains は証明済みのドメインの確かめ直し（フィーチャー org_managed_users。ADR 0085）。
	OrgDomains OrgDomains `yaml:"org_domains"`

	// IDs は採番の方式（ADR 0045）。
	IDs IDs `yaml:"ids"`

	// Passkey は passkey（WebAuthn）の Relying Party（design.md 2.5）。
	Passkey Passkey `yaml:"passkey"`

	// OIDC は OIDC Provider（design.md 5.1、9.3）。issuer は server.public_url。
	OIDC OIDC `yaml:"oidc"`

	// ServiceAccounts は汎用サービスアカウント（フィーチャー service_accounts。ADR 0074）。
	ServiceAccounts ServiceAccounts `yaml:"service_accounts"`

	// Hooks はフロー フック（フィーチャー flow_hooks。design.md 11.8、ADR 0081）。キーはフックの名前。
	Hooks map[string]Hook `yaml:"hooks"`
}

// Hook は1つのフロー フック。url が無ければ、組み込む側が Go のインターフェース（app.Deps.Hooks）で渡す。
type Hook struct {
	// URL は Webhook の宛先（https。dev: true のときだけ http）。
	URL string `yaml:"url"`
	// SecretEnv は署名の秘密（32 バイト以上）を持つ環境変数の名前。読んだ後に消す。
	SecretEnv string `yaml:"secret_env"`
	// Timeout は呼び出しのタイムアウト（5 秒以下）。省略すると 2 秒。
	Timeout Duration `yaml:"timeout"`
	// FailOpen は失敗（タイムアウト・誤った応答）のときに通すか。既定は止める（fail-closed）。
	FailOpen bool `yaml:"fail_open"`
}

// ServiceAccounts はサービスアカウントの設定。
type ServiceAccounts struct {
	// TokenTTL は client credentials で発行するアクセストークンの寿命（1 時間以下）。
	TokenTTL Duration `yaml:"token_ttl"`
}

// OIDC は OIDC Provider のトークンと鍵の設定。
type OIDC struct {
	// CodeTTL は認可コードの寿命。
	CodeTTL Duration `yaml:"code_ttl"`
	// IDTokenTTL は ID トークンの寿命。
	IDTokenTTL Duration `yaml:"id_token_ttl"`
	// AccessTokenTTL は不透明なアクセストークンの寿命（失効はイントロスペクションに validity_max_delay の内に効く）。
	AccessTokenTTL Duration `yaml:"access_token_ttl"`
	// RefreshTokenTTL はリフレッシュトークンのファミリーの寿命（ログインのセッションより長くはならない）。
	RefreshTokenTTL Duration `yaml:"refresh_token_ttl"`
	// RetiredKeyTTL はローテーションで退役した署名鍵を JWKS に残す期間（id_token_ttl より長くする）。
	RetiredKeyTTL Duration `yaml:"retired_key_ttl"`
}

// Passkey は passkey の Relying Party の設定。省略した項目は server.public_url から決める。
// rp_id も public_url も無ければ passkey は使えない。
type Passkey struct {
	// RPID は passkey を結び付けるドメイン（example.com など）。既定は public_url のホスト。
	// 作った後に変えると、登録済みの passkey が使えなくなる。
	RPID   string `yaml:"rp_id"`
	RPName string `yaml:"rp_name"` // 既定は realm.slug
	// Origins は passkey を使う画面の origin。既定は public_url。rp_id のドメインの外の origin は
	// Related Origin Requests（/.well-known/webauthn を rp_id のドメインで返す）で関連付ける。
	Origins []string `yaml:"origins"`
}

// PasskeyRP は passkey の Relying Party を既定値で補って返す。使えなければ ok=false。
func (c Config) PasskeyRP() (rpID, rpName string, origins []string, ok bool) {
	rpID, rpName, origins = c.Passkey.RPID, c.Passkey.RPName, c.Passkey.Origins
	if u, err := url.Parse(c.Server.PublicURL); err == nil && u.Host != "" {
		if rpID == "" {
			rpID = u.Hostname()
		}
		if len(origins) == 0 {
			origins = []string{u.Scheme + "://" + u.Host}
		}
	}
	if rpName == "" {
		rpName = c.Realm.Slug
	}
	return rpID, rpName, origins, rpID != "" && len(origins) > 0
}

// IDs は内部 ID と外部 ID の採番の方式（id.Generators の名前）。
type IDs struct {
	Internal string `yaml:"internal"`
	External string `yaml:"external"`
}

// Server は待ち受けの設定。公開 API と管理 API はポートを分ける（design.md 2.5）。
type Server struct {
	PublicAddr string `yaml:"public_addr"`
	AdminAddr  string `yaml:"admin_addr"`
	// MultiInstance は複数インスタンスで動かすか。true なら共有できる EphemeralStore を必須にする。
	MultiInstance bool `yaml:"multi_instance"`
	// ClockSkewWarn は DB との時刻のずれの警告のしきい値（design.md 2.7）。
	ClockSkewWarn Duration `yaml:"clock_skew_warn"`
	// PublicURL は公開 API の外から見た URL（https://id.example.com）。CLI がログイン画面のリンクを示すのに使う。
	PublicURL string `yaml:"public_url"`
	// LoginTemplates はホスト型ログイン画面のテンプレート（login.html）を置いたディレクトリ。空なら組み込みのもの。
	LoginTemplates string `yaml:"login_templates"`
}

// Adapter はアダプタの選択とその設定。driver 以外の項目はアダプタに渡す。
type Adapter struct {
	Driver  string            `yaml:"driver"`
	Options map[string]string `yaml:",inline"`
}

// Realm は最初の realm の設定。
type Realm struct {
	Slug     string `yaml:"slug"`
	Timezone string `yaml:"timezone"`
	// VerifiedVia はメールを「確認済み」とみなす経路（design.md 4.1）。
	// メールを送れない環境では code を外し、OAuth と運営者による登録で運用する。
	VerifiedVia []string `yaml:"verified_via"`
	// OrgCreation は共有 Org を作れる人（design.md 4.11）：anyone / operators_only / invite_only。
	// 運営者は管理 API からいつでも作れる。
	OrgCreation string `yaml:"org_creation"`
	// OrgDeletionGrace は Org の削除の猶予期間（design.md 4.10）。0 は猶予なし（今削除する）。
	OrgDeletionGrace Duration `yaml:"org_deletion_grace"`
	// UserDeletionGrace はアカウントの削除の猶予期間（design.md 4.10）。0 は猶予なし。
	UserDeletionGrace Duration `yaml:"user_deletion_grace"`
	// ClientDataRetention は監査ログの IP と User-Agent の全文を読める期間（design.md 9.6）。期間の後は切り詰めた値だけが残る。
	ClientDataRetention Duration `yaml:"client_data_retention"`
	// QuotaCount は Quota（フィーチャー quota）で数えるもの（design.md 11.14）。active な Membership は必ず数える。
	QuotaCount QuotaCount `yaml:"quota_count"`
	// AuditRetention は監査ログの保持期間（design.md 6.5）。過ぎたら先頭から切り詰める。0 は切り詰めない。
	AuditRetention Duration `yaml:"audit_retention"`
	// EndedRetention は失効・期限切れのセッション、配送済みの outbox、発火済みの予約イベントを残す期間（9.6）。0 は消さない。
	EndedRetention Duration `yaml:"ended_retention"`
	// EmailStorage はメールの保持モード（9.6）：encrypted（暗号文 + インデックス）/ index_only（インデックスのみ）。
	EmailStorage string `yaml:"email_storage"`
	// DeclaredContextClients は判定（authz:check）で認証の文脈を申告できる呼び出し元（サービスアカウントの公開 ID。ADR 0084）。
	// 申告の文脈は attested でなく、付与の条件にしか効かない。空なら誰も申告できない。
	DeclaredContextClients []string `yaml:"declared_context_clients"`
}

// KnownEmailStorage は realm.email_storage の値。
var KnownEmailStorage = []string{"encrypted", "index_only"}

// QuotaCount は Quota で数えるもの。既定はすべて数える。
type QuotaCount struct {
	Invited   bool `yaml:"invited"`   // 受け入れ待ちの招待
	Future    bool `yaml:"future"`    // 有効期間がまだ始まっていない Membership
	Suspended bool `yaml:"suspended"` // 停止中の Membership
}

// KnownOrgCreation は realm.org_creation の値。
var KnownOrgCreation = []string{"anyone", "operators_only", "invite_only"}

// KnownVerifiedVia は経路の名前。
var KnownVerifiedVia = []string{"code", "oauth_provider", "sso", "invitation", "admin"}

// Security はセキュリティ設定の階層の、ホスト先の段。
type Security struct {
	Session   SessionRules `yaml:"session"`
	EmailFlow EmailFlow    `yaml:"email_flow"`
	Login     Login        `yaml:"login"`
	// SecondFactor は2段階認証（design.md 2.8、4.1）。
	SecondFactor SecondFactor `yaml:"second_factor"`
	// Password はフィーチャー password（design.md 4.1）。
	Password Password `yaml:"password"`
	// Recovery はアカウントの復旧（design.md 4.12）。
	Recovery Recovery `yaml:"recovery"`
	// SuspensionCategories は realm で足す停止の種別（design.md 4.7）。組み込みの種別は書かない。
	// 停止・解除できるのは realm:owner だけ。
	SuspensionCategories []string `yaml:"suspension_categories"`
	// Warnings は警告のコードごとのアクション（ignore / warn / deny。design.md 10章）。無いコードは既定に従う。
	Warnings map[string]string `yaml:"warnings"`
}

// Login はログインの要求に共通の守り（design.md 4.9、4.1）。
type Login struct {
	// MinResponseTime はログインの要求（POST /v1/login/...）の応答時間の下限。本人確認の前の応答時間から、
	// アカウントの有無や失敗の理由を読めないようにする。0 なら揃えない。
	MinResponseTime Duration  `yaml:"min_response_time"`
	RateLimit       RateLimit `yaml:"rate_limit"`
}

// RateLimit はログインの要求の回数の上限（固定窓）。0 なら制限しない。
type RateLimit struct {
	Window Duration `yaml:"window"`
	// PerIP は接続元ごとの上限（IPv6 は /64 で数える）。
	PerIP int `yaml:"per_ip"`
	// PerAccount はメールアドレスと接続元ごとの、メールのフローの開始・パスワードとリカバリーコードの照合の上限。
	PerAccount int `yaml:"per_account"`
	// PerAccountTotal はメールアドレスごとの、接続元を問わない上限（第三者が本人を締め出すのを難しくするため、PerAccount
	// より大きくする）。0 なら無い。
	PerAccountTotal int `yaml:"per_account_total"`
}

// SecondFactor は2段階認証の設定。2要素目（passkey / TOTP）を登録したユーザーには、Required でなくても2要素目を求める。
type SecondFactor struct {
	// Required は2段階認証を必須にする。2要素目が未登録のユーザーは、ログインの後に登録だけできる。
	Required bool `yaml:"required"`
	// TTL は2要素目の確認・登録を待つ制限つきのセッションの寿命。TOTP の登録のフローの期限にも使う。
	TTL Duration `yaml:"ttl"`
	// MaxAttempts は TOTP の登録のフローごとの照合の回数の上限。
	MaxAttempts int `yaml:"max_attempts"`
	// Issuer は認証器アプリに表示する発行者の名前。空なら passkey.rp_name か realm.slug。
	Issuer string `yaml:"issuer"`
}

// Recovery はアカウントの復旧の設定。
type Recovery struct {
	// Methods は使える復旧の経路（recovery_code / email / operator_link）。
	Methods []string `yaml:"methods"`
	// TTL は復旧専用のセッションの寿命。
	TTL Duration `yaml:"ttl"`
}

// KnownRecoveryMethods は復旧の経路。
var KnownRecoveryMethods = []string{"recovery_code", "email", "operator_link"}

// Allows は経路が有効かを返す。
func (r Recovery) Allows(method string) bool { return slices.Contains(r.Methods, method) }

// Password はパスワードの設定。最低長は2段階認証の要否で決まる（必須なら 8 文字、そうでなければ 15 文字）。
type Password struct {
	// Argon2 は新しく作るハッシュのパラメータ。変えると、既存のハッシュはログインの成功時に作り直す。
	Argon2 Argon2 `yaml:"argon2"`
}

// Argon2 は argon2id のパラメータ（RFC 9106）。
type Argon2 struct {
	MemoryKiB   uint32 `yaml:"memory_kib"`
	Iterations  uint32 `yaml:"iterations"`
	Parallelism uint8  `yaml:"parallelism"`
}

// EmailFlow はメールのコード・マジックリンクの設定（design.md 4.1）。
type EmailFlow struct {
	TTL         Duration `yaml:"ttl"`
	MaxAttempts int      `yaml:"max_attempts"`
}

// SessionRules はセッションの寿命の規則（design.md 5.4）。短いほど厳しい。
type SessionRules struct {
	AbsoluteLifetime DurationRule `yaml:"absolute_lifetime"`
	IdleTimeout      DurationRule `yaml:"idle_timeout"`
	MaxAuthAge       DurationRule `yaml:"max_auth_age"`
	// ValidityMaxDelay は変更がセッション検証に反映されるまでの遅れの上限（保証値。design.md 5.3）。
	ValidityMaxDelay Duration `yaml:"validity_max_delay"`
	// RotationInterval ごとに Cookie のセッションの ID を入れ替える（5.2）。0 なら入れ替えない。
	RotationInterval Duration `yaml:"rotation_interval"`
	// RotationGrace は入れ替え前の ID を使える猶予。
	RotationGrace Duration `yaml:"rotation_grace"`
}

// DurationRule は時間の項目の、既定値と realm・Org が設定できる範囲。
type DurationRule struct {
	Default     Duration `yaml:"default"`
	Min         Duration `yaml:"min"`
	Max         Duration `yaml:"max"`
	OrgMayRelax bool     `yaml:"org_may_relax"`
}

// Rule は settings の規則にする。
func (d DurationRule) Rule(key string) settings.Duration {
	return settings.Duration{
		Key: key, Default: d.Default.D(), Min: d.Min.D(), Max: d.Max.D(),
		Direction: settings.LowerIsStricter, OrgMayRelax: d.OrgMayRelax,
	}
}

// 組み込みの停止の種別（authn/account と同じ）。
var (
	builtinCategories = []string{"tos_violation", "customer_request", "security_risk", "billing"}
	categoryRE        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
)

// Outbox は outbox の送出の設定。
type Outbox struct {
	Interval Duration `yaml:"interval"`
	Batch    int      `yaml:"batch"`
}

// OrgDomains は証明済みのドメインの確かめ直しの設定（ADR 0085）。
type OrgDomains struct {
	// Recheck は1つのドメインの TXT を確かめ直す間隔。0 なら確かめ直さない。
	Recheck Duration `yaml:"recheck"`
	// Grace は TXT が見つからなくなってから証明を外すまでの猶予。
	Grace Duration `yaml:"grace"`
}

// Duration は "30s"、"720h" などの形の時間。日数は "30d" と書ける。
type Duration time.Duration

// D は time.Duration を返す。
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML は時間を読む。
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// maxDays は日数で書ける上限（約100年。time.Duration のあふれを防ぐ）。
const maxDays = 36500

// ParseDuration は time.ParseDuration に日（d）を足したもの。
func ParseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err != nil || fmt.Sprint(n) != days || n < 0 || n > maxDays {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Default は既定の設定（design.md の既定値）。
func Default() Config {
	day := 24 * time.Hour
	return Config{
		Server:      Server{PublicAddr: ":8080", AdminAddr: "127.0.0.1:8081", ClockSkewWarn: Duration(time.Second)},
		Storage:     Adapter{Driver: "sqlite", Options: map[string]string{"path": "iam.db", "auto_migrate": "true"}},
		Ephemeral:   Adapter{Driver: "memory"},
		KeyStore:    Adapter{Driver: "file", Options: map[string]string{"path": "keys.json"}},
		EventSink:   Adapter{Driver: "stdout"},
		Notifier:    Adapter{Driver: "dev"},
		BreachCheck: Adapter{Driver: "hibp"},
		Realm: Realm{Slug: "default", Timezone: "UTC", VerifiedVia: []string{"code", "oauth_provider", "sso", "admin"},
			OrgCreation: "anyone", OrgDeletionGrace: Duration(30 * day),
			UserDeletionGrace: Duration(30 * day), ClientDataRetention: Duration(30 * day),
			QuotaCount:     QuotaCount{Invited: true, Future: true, Suspended: true},
			AuditRetention: Duration(90 * day), EndedRetention: Duration(7 * day), EmailStorage: "encrypted"},
		Security: Security{Session: SessionRules{
			AbsoluteLifetime: DurationRule{Default: Duration(30 * day), Min: Duration(time.Hour), Max: Duration(90 * day)},
			IdleTimeout:      DurationRule{Default: Duration(7 * day), Min: Duration(5 * time.Minute), Max: Duration(30 * day)},
			MaxAuthAge:       DurationRule{Default: Duration(15 * time.Minute), Min: Duration(time.Minute), Max: Duration(day)},
			ValidityMaxDelay: Duration(30 * time.Second),
			RotationInterval: Duration(time.Hour),
			RotationGrace:    Duration(time.Minute),
		}, EmailFlow: EmailFlow{TTL: Duration(10 * time.Minute), MaxAttempts: 5},
			SecondFactor: SecondFactor{TTL: Duration(10 * time.Minute), MaxAttempts: 5},
			Password:     Password{Argon2: Argon2{MemoryKiB: 64 * 1024, Iterations: 2, Parallelism: 1}},
			Recovery:     Recovery{Methods: slices.Clone(KnownRecoveryMethods), TTL: Duration(15 * time.Minute)},
			Login: Login{MinResponseTime: Duration(300 * time.Millisecond),
				RateLimit: RateLimit{Window: Duration(10 * time.Minute), PerIP: 100, PerAccount: 5, PerAccountTotal: 20}},
		},
		Outbox:     Outbox{Interval: Duration(time.Second), Batch: 100},
		OrgDomains: OrgDomains{Recheck: Duration(day), Grace: Duration(7 * day)},
		IDs:        IDs{Internal: "uuidv7", External: "random"},
		OIDC: OIDC{CodeTTL: Duration(time.Minute), IDTokenTTL: Duration(time.Hour), AccessTokenTTL: Duration(10 * time.Minute),
			RefreshTokenTTL: Duration(30 * day), RetiredKeyTTL: Duration(7 * day)},
		ServiceAccounts: ServiceAccounts{TokenTTL: Duration(10 * time.Minute)},
	}
}

// Load は path を読み、既定値に重ねて検証する。
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- 設定ファイルのパスは運用者が指定する
	if err != nil {
		return Config{}, err
	}
	return Parse(b)
}

// Parse は YAML を読み、既定値に重ねて検証する。未知の項目はエラーにする。
func Parse(b []byte) (Config, error) {
	c := Default()
	// アダプタの項目は差し替える（既定の sqlite の path が memory に残らないように）。
	c.Storage, c.Ephemeral, c.KeyStore, c.EventSink, c.Notifier = Adapter{}, Adapter{}, Adapter{}, Adapter{}, Adapter{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	d := Default()
	for _, p := range []struct {
		name     string
		got, def *Adapter
	}{
		{"storage", &c.Storage, &d.Storage}, {"ephemeral", &c.Ephemeral, &d.Ephemeral}, {"keystore", &c.KeyStore, &d.KeyStore},
		{"event_sink", &c.EventSink, &d.EventSink}, {"notifier", &c.Notifier, &d.Notifier},
	} {
		switch {
		case p.got.Driver != "":
		case len(p.got.Options) == 0:
			// 項目ごと省略したときだけ既定値を使う。
			*p.got = *p.def
		default:
			// driver を書き忘れたまま既定のアダプタで別の場所を使い始めないように拒否する。
			return Config{}, fmt.Errorf("config: %s.driver is required when %s has options", p.name, p.name)
		}
	}
	return c, c.Validate()
}

func (c Config) validatePasskey() []string {
	var problems []string
	rpID, _, origins, ok := c.PasskeyRP()
	if !ok {
		if c.Passkey.RPID != "" || len(c.Passkey.Origins) > 0 {
			problems = append(problems, "passkey: rp_id and origins are required (or set server.public_url)")
		}
		return problems
	}
	if strings.ContainsAny(rpID, ":/") || strings.Trim(rpID, ".") != rpID {
		problems = append(problems, "passkey.rp_id must be a domain name without scheme or port")
	}
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || !(u.Scheme == "https" || (c.Dev && u.Scheme == "http")) || u.Host == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			problems = append(problems, fmt.Sprintf("passkey.origins: %q must be an https origin (http only with dev: true)", o))
		}
	}
	return problems
}

func (c Config) validateHooks() []string {
	var problems []string
	for name, h := range c.Hooks {
		if !slices.Contains(port.Hooks, name) {
			problems = append(problems, fmt.Sprintf("hooks: unknown hook %q", name))
			continue
		}
		if h.Timeout < 0 || h.Timeout > Duration(5*time.Second) {
			problems = append(problems, fmt.Sprintf("hooks.%s.timeout must be between 0 and 5s", name))
		}
		if h.URL == "" {
			if h.SecretEnv != "" {
				problems = append(problems, fmt.Sprintf("hooks.%s.secret_env needs url", name))
			}
			continue
		}
		u, err := url.Parse(h.URL)
		if err != nil || !(u.Scheme == "https" || (c.Dev && u.Scheme == "http")) || u.Host == "" || u.User != nil || u.Fragment != "" {
			problems = append(problems, fmt.Sprintf("hooks.%s.url must be an https URL (http only with dev: true)", name))
		}
		if h.SecretEnv == "" {
			problems = append(problems, fmt.Sprintf("hooks.%s.secret_env is required", name))
		}
	}
	return problems
}

// WarningActions は security.warnings を評価器の形にする。
func (c Config) WarningActions() map[string]warning.Action {
	out := make(map[string]warning.Action, len(c.Security.Warnings))
	for code, a := range c.Security.Warnings {
		out[code] = warning.Action(a)
	}
	return out
}

// Validate は設定の矛盾を検出する。危険な構成は起動を拒否する（design.md 2.5）。
func (c Config) Validate() error {
	var problems []string
	if c.Server.PublicAddr == "" || c.Server.AdminAddr == "" {
		problems = append(problems, "server.public_addr and server.admin_addr are required")
	} else if c.Server.PublicAddr == c.Server.AdminAddr {
		problems = append(problems, "server.public_addr and server.admin_addr must differ")
	}
	if u := c.Server.PublicURL; u != "" {
		p, err := url.Parse(u)
		schemeOK := err == nil && (p.Scheme == "https" || (c.Dev && p.Scheme == "http"))
		if !schemeOK || p.Host == "" || p.User != nil || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || (p.Path != "" && p.Path != "/") {
			problems = append(problems, "server.public_url must be an https origin (http only with dev: true)")
		}
	}
	if c.Notifier.Driver == "dev" && !c.Dev {
		problems = append(problems, "notifier.driver=dev is only allowed with dev: true")
	}
	if c.Realm.Slug == "" {
		problems = append(problems, "realm.slug is required")
	}
	if c.Realm.OrgDeletionGrace < 0 {
		problems = append(problems, "realm.org_deletion_grace must not be negative")
	}
	if c.Realm.UserDeletionGrace < 0 {
		problems = append(problems, "realm.user_deletion_grace must not be negative")
	}
	if c.Realm.ClientDataRetention <= 0 {
		problems = append(problems, "realm.client_data_retention must be positive")
	}
	if c.Realm.AuditRetention < 0 || c.Realm.EndedRetention < 0 {
		problems = append(problems, "realm.audit_retention and realm.ended_retention must not be negative")
	}
	if !slices.Contains(KnownEmailStorage, c.Realm.EmailStorage) {
		problems = append(problems, fmt.Sprintf("realm.email_storage: unknown %q (known: %v)", c.Realm.EmailStorage, KnownEmailStorage))
	}
	o := c.OIDC
	if o.CodeTTL <= 0 || o.CodeTTL > Duration(10*time.Minute) {
		problems = append(problems, "oidc.code_ttl must be positive and at most 10m")
	}
	if o.IDTokenTTL <= 0 || o.AccessTokenTTL <= 0 || o.RefreshTokenTTL <= 0 {
		problems = append(problems, "oidc: token ttls must be positive")
	}
	if o.RetiredKeyTTL <= o.IDTokenTTL {
		problems = append(problems, "oidc.retired_key_ttl must be longer than oidc.id_token_ttl")
	}
	if t := c.ServiceAccounts.TokenTTL; t <= 0 || t > Duration(time.Hour) {
		problems = append(problems, "service_accounts.token_ttl must be positive and at most 1h")
	}
	if !slices.Contains(KnownOrgCreation, c.Realm.OrgCreation) {
		problems = append(problems, fmt.Sprintf("realm.org_creation: unknown %q (known: %v)", c.Realm.OrgCreation, KnownOrgCreation))
	}
	for _, v := range c.Realm.VerifiedVia {
		if !slices.Contains(KnownVerifiedVia, v) {
			problems = append(problems, fmt.Sprintf("realm.verified_via: unknown %q (known: %v)", v, KnownVerifiedVia))
		}
	}
	if ef := c.Security.EmailFlow; ef.TTL.D() <= 0 || ef.TTL.D() > time.Hour || ef.MaxAttempts < 1 || ef.MaxAttempts > 10 {
		problems = append(problems, "security.email_flow: ttl must be within (0, 1h] and max_attempts within [1, 10]")
	}
	if sf := c.Security.SecondFactor; sf.TTL.D() <= 0 || sf.TTL.D() > time.Hour || sf.MaxAttempts < 1 || sf.MaxAttempts > 10 {
		problems = append(problems, "security.second_factor: ttl must be within (0, 1h] and max_attempts within [1, 10]")
	}
	for _, m := range c.Security.Recovery.Methods {
		if !slices.Contains(KnownRecoveryMethods, m) {
			problems = append(problems, fmt.Sprintf("security.recovery.methods: unknown %q (known: %v)", m, KnownRecoveryMethods))
		}
	}
	if t := c.Security.Recovery.TTL.D(); t <= 0 || t > time.Hour {
		problems = append(problems, "security.recovery.ttl must be within (0, 1h]")
	}
	for _, c := range c.Security.SuspensionCategories {
		if !categoryRE.MatchString(c) || slices.Contains(builtinCategories, c) {
			problems = append(problems, fmt.Sprintf("security.suspension_categories: %q must match %s and not be built in %v", c, categoryRE, builtinCategories))
		}
	}
	// OWASP の下限（m=19MiB, t=2）。開発用の構成では、テストのために軽くできる。
	if a := c.Security.Password.Argon2; a.MemoryKiB > 1<<21 || a.Iterations > 16 || a.Parallelism < 1 || a.Parallelism > 16 ||
		a.MemoryKiB < 8 || a.Iterations < 1 || (!c.Dev && (a.MemoryKiB < 19*1024 || a.Iterations < 2)) {
		problems = append(problems, "security.password.argon2: memory_kib must be within [19456, 2097152], iterations within [2, 16] and parallelism within [1, 16]")
	}
	if l := c.Security.Login; l.MinResponseTime.D() < 0 || l.MinResponseTime.D() > 5*time.Second {
		problems = append(problems, "security.login.min_response_time must be within [0, 5s]")
	}
	if rl := c.Security.Login.RateLimit; rl.PerIP < 0 || rl.PerAccount < 0 || rl.PerAccountTotal < 0 || ((rl.PerIP > 0 || rl.PerAccount > 0 || rl.PerAccountTotal > 0) && rl.Window.D() <= 0) {
		problems = append(problems, "security.login.rate_limit: limits must not be negative and window must be positive")
	}
	if rl := c.Security.Login.RateLimit; rl.PerAccount > 0 && rl.PerAccountTotal > 0 && rl.PerAccountTotal < rl.PerAccount {
		problems = append(problems, "security.login.rate_limit.per_account_total must be at least per_account")
	}
	if err := warning.Validate(c.WarningActions()); err != nil {
		problems = append(problems, "security."+err.Error())
	}
	if _, err := time.LoadLocation(c.Realm.Timezone); err != nil {
		problems = append(problems, fmt.Sprintf("realm.timezone: %v", err))
	}
	for key, r := range map[string]DurationRule{
		"session.absolute_lifetime": c.Security.Session.AbsoluteLifetime,
		"session.idle_timeout":      c.Security.Session.IdleTimeout,
		"session.max_auth_age":      c.Security.Session.MaxAuthAge,
	} {
		if err := r.Rule(key).Validate(); err != nil {
			problems = append(problems, err.Error())
		}
		if r.Min.D() <= 0 {
			problems = append(problems, fmt.Sprintf("security.%s.min must be positive", key))
		}
	}
	if c.Security.Session.ValidityMaxDelay.D() <= 0 {
		problems = append(problems, "security.session.validity_max_delay must be positive")
	}
	if _, ok := id.Generators[c.IDs.Internal]; !ok {
		problems = append(problems, fmt.Sprintf("ids.internal: unknown generator %q", c.IDs.Internal))
	}
	// 外部 ID に時刻の読める方式は使わない。
	if _, ok := id.Generators[c.IDs.External]; !ok || c.IDs.External == "uuidv7" {
		problems = append(problems, fmt.Sprintf("ids.external: %q is not allowed (use random)", c.IDs.External))
	}
	if ss := c.Security.Session; ss.RotationInterval.D() < 0 || ss.RotationGrace.D() <= 0 {
		problems = append(problems, "security.session.rotation_interval must not be negative and rotation_grace must be positive")
	} else if ss.RotationInterval.D() > 0 && ss.RotationInterval.D() <= ss.RotationGrace.D() {
		problems = append(problems, "security.session.rotation_interval must be longer than rotation_grace")
	}
	if c.Outbox.Interval.D() <= 0 {
		problems = append(problems, "outbox.interval must be positive")
	}
	if c.OrgDomains.Recheck.D() < 0 || c.OrgDomains.Grace.D() < 0 {
		problems = append(problems, "org_domains.recheck and org_domains.grace must not be negative")
	}
	problems = append(problems, c.validatePasskey()...)
	problems = append(problems, c.validateHooks()...)
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}
