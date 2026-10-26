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
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/id"
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

	// IDs は採番の方式（ADR 0045）。
	IDs IDs `yaml:"ids"`

	// Passkey は passkey（WebAuthn）の Relying Party（design.md 2.5）。
	Passkey Passkey `yaml:"passkey"`
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
}

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
	// PerAccount はメールアドレスごとの、メールのフローの開始の上限。
	PerAccount int `yaml:"per_account"`
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

// Outbox は outbox の送出の設定。
type Outbox struct {
	Interval Duration `yaml:"interval"`
	Batch    int      `yaml:"batch"`
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
		Realm:       Realm{Slug: "default", Timezone: "UTC", VerifiedVia: []string{"code", "oauth_provider", "sso", "admin"}},
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
			Login: Login{MinResponseTime: Duration(300 * time.Millisecond),
				RateLimit: RateLimit{Window: Duration(10 * time.Minute), PerIP: 100, PerAccount: 5}},
		},
		Outbox: Outbox{Interval: Duration(time.Second), Batch: 100},
		IDs:    IDs{Internal: "uuidv7", External: "random"},
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
	// OWASP の下限（m=19MiB, t=2）。開発用の構成では、テストのために軽くできる。
	if a := c.Security.Password.Argon2; a.MemoryKiB > 1<<21 || a.Iterations > 16 || a.Parallelism < 1 || a.Parallelism > 16 ||
		a.MemoryKiB < 8 || a.Iterations < 1 || (!c.Dev && (a.MemoryKiB < 19*1024 || a.Iterations < 2)) {
		problems = append(problems, "security.password.argon2: memory_kib must be within [19456, 2097152], iterations within [2, 16] and parallelism within [1, 16]")
	}
	if l := c.Security.Login; l.MinResponseTime.D() < 0 || l.MinResponseTime.D() > 5*time.Second {
		problems = append(problems, "security.login.min_response_time must be within [0, 5s]")
	}
	if rl := c.Security.Login.RateLimit; rl.PerIP < 0 || rl.PerAccount < 0 || ((rl.PerIP > 0 || rl.PerAccount > 0) && rl.Window.D() <= 0) {
		problems = append(problems, "security.login.rate_limit: limits must not be negative and window must be positive")
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
	problems = append(problems, c.validatePasskey()...)
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}
