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
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

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

	// Features は有効にするフィーチャー名。省略すると各フィーチャーの既定に従う。
	Features *[]string `yaml:"features"`

	// Realm は最初の realm（複数 realm がオフなら唯一の realm）。
	Realm Realm `yaml:"realm"`

	// Security はホスト先が決める既定値と、realm・Org が設定できる範囲（design.md 2.8）。
	Security Security `yaml:"security"`

	Outbox Outbox `yaml:"outbox"`

	// IDs は採番の方式（ADR 0045）。
	IDs IDs `yaml:"ids"`
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
}

// Security はセキュリティ設定の階層の、ホスト先の段。
type Security struct {
	Session SessionRules `yaml:"session"`
}

// SessionRules はセッションの寿命の規則（design.md 5.4）。短いほど厳しい。
type SessionRules struct {
	AbsoluteLifetime DurationRule `yaml:"absolute_lifetime"`
	IdleTimeout      DurationRule `yaml:"idle_timeout"`
	MaxAuthAge       DurationRule `yaml:"max_auth_age"`
	// ValidityMaxDelay は変更がセッション検証に反映されるまでの遅れの上限（保証値。design.md 5.3）。
	ValidityMaxDelay Duration `yaml:"validity_max_delay"`
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
		Server:    Server{PublicAddr: ":8080", AdminAddr: "127.0.0.1:8081", ClockSkewWarn: Duration(time.Second)},
		Storage:   Adapter{Driver: "sqlite", Options: map[string]string{"path": "iam.db", "auto_migrate": "true"}},
		Ephemeral: Adapter{Driver: "memory"},
		KeyStore:  Adapter{Driver: "file", Options: map[string]string{"path": "keys.json"}},
		EventSink: Adapter{Driver: "stdout"},
		Notifier:  Adapter{Driver: "dev"},
		Realm:     Realm{Slug: "default", Timezone: "UTC"},
		Security: Security{Session: SessionRules{
			AbsoluteLifetime: DurationRule{Default: Duration(30 * day), Min: Duration(time.Hour), Max: Duration(90 * day)},
			IdleTimeout:      DurationRule{Default: Duration(7 * day), Min: Duration(5 * time.Minute), Max: Duration(30 * day)},
			MaxAuthAge:       DurationRule{Default: Duration(15 * time.Minute), Min: Duration(time.Minute), Max: Duration(day)},
			ValidityMaxDelay: Duration(30 * time.Second),
		}},
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

// Validate は設定の矛盾を検出する。危険な構成は起動を拒否する（design.md 2.5）。
func (c Config) Validate() error {
	var problems []string
	if c.Server.PublicAddr == "" || c.Server.AdminAddr == "" {
		problems = append(problems, "server.public_addr and server.admin_addr are required")
	} else if c.Server.PublicAddr == c.Server.AdminAddr {
		problems = append(problems, "server.public_addr and server.admin_addr must differ")
	}
	if c.Notifier.Driver == "dev" && !c.Dev {
		problems = append(problems, "notifier.driver=dev is only allowed with dev: true")
	}
	if c.Realm.Slug == "" {
		problems = append(problems, "realm.slug is required")
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
	if c.Outbox.Interval.D() <= 0 {
		problems = append(problems, "outbox.interval must be positive")
	}
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}
