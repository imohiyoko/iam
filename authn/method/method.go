// Package method は認証方式のプラグイン（port.Authenticator）の登録と、コアが方式に渡す認証情報のストアを持つ
// （ADR 0090、0092）。
//
// 方式は authn/method/<name>/ に置き、features/<name> を import すると Register で登録される（フィーチャーと同じ。ADR 0073）。
// 登録した方式は、宣言したフィーチャーが動いているときだけ使える（Active）。
package method

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"sync"

	"github.com/imohiyoko/iam/shared/port"
)

// コアが互換の欄（/v1/me/methods の totp・password など）で特別に扱う方式の名前（ADR 0101）。
const (
	TOTP     = "totp"
	Password = "password"
)

// nameRE は方式の名前（API のパスと authn_credentials.method に使う）。
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// ValidName は name が方式の名前の形かを返す。
func ValidName(name string) bool { return nameRE.MatchString(name) }

var (
	mu       sync.Mutex
	registry = map[string]port.Authenticator{}
)

// Check は方式の宣言を確かめる。Feature が空（コアの方式）でもよい。
func Check(a port.Authenticator) error {
	i := a.Info()
	switch {
	case !ValidName(i.Name):
		return fmt.Errorf("method: invalid name %q", i.Name)
	case i.Kind != port.FactorKnowledge && i.Kind != port.FactorPossession && i.Kind != port.FactorInherence:
		return fmt.Errorf("method: %s has unknown factor kind %q", i.Name, i.Kind)
	case i.AAL < 1 || i.AAL > 3:
		return fmt.Errorf("method: %s has invalid AAL %d", i.Name, i.AAL)
	case len(i.Usages) == 0 || len(i.AMR) == 0:
		return fmt.Errorf("method: %s declares no usage or amr", i.Name)
	case i.DataVersion < 1:
		return fmt.Errorf("method: %s has invalid data version", i.Name)
	}
	for _, u := range i.Usages {
		if u != port.UsageFirstFactor && u != port.UsageSecondFactor && u != port.UsageRecovery && u != port.UsageStepUp {
			return fmt.Errorf("method: %s has unknown usage %q", i.Name, u)
		}
	}
	return nil
}

// Register は方式を登録する。features/<name> の init から呼ぶ。
func Register(a port.Authenticator) {
	mu.Lock()
	defer mu.Unlock()
	if err := Check(a); err != nil {
		panic(err.Error())
	}
	if a.Info().Feature == "" {
		panic("method: " + a.Info().Name + " has no feature (core methods are passed to Active as built-ins)")
	}
	name := a.Info().Name
	if _, dup := registry[name]; dup {
		panic("method: duplicate registration: " + name)
	}
	registry[name] = a
}

// Registered はバイナリに含まれる方式を名前順に返す。
func Registered() []port.Authenticator {
	mu.Lock()
	defer mu.Unlock()
	out := make([]port.Authenticator, 0, len(registry))
	for _, a := range registry {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}

// Set は動いている方式の組。nil は方式が無いことを表す。
type Set struct {
	m map[string]port.Authenticator
}

// Configurable は設定ファイルの `methods.<name>` を読む方式が実装する（任意。ADR 0103）。
type Configurable interface {
	// Configure は realm（slug）の設定を読んだ方式を返す。decode は `methods.<name>` を v に読む（設定が無ければ何もしない）。
	// nil を返すと、その realm では方式を動かさない（設定が無いなど）。返す方式の名前は登録したものと同じでなければならない。
	Configure(realm string, decode func(v any) error) (port.Authenticator, error)
}

// Active は登録した方式のうち、宣言したフィーチャーが動いているもの（featureActive が true）と、extra（組み込み用。
// フィーチャーを問わない）の組を返す。名前が重なれば extra を優先する。設定を読む方式（Configurable）は設定なしで組み立てる。
func Active(featureActive func(string) bool, extra ...port.Authenticator) (*Set, error) {
	return ActiveIn(featureActive, "", nil, extra...)
}

// ActiveIn は realm（slug）の方式の組を返す。settings は方式の名前ごとの設定の読み手（`methods.<name>`）。
func ActiveIn(featureActive func(string) bool, realm string, settings map[string]func(any) error, extra ...port.Authenticator) (*Set, error) {
	s := &Set{m: map[string]port.Authenticator{}}
	for _, a := range Registered() {
		if !featureActive(a.Info().Feature) {
			continue
		}
		if c, ok := a.(Configurable); ok {
			decode := settings[a.Info().Name]
			if decode == nil {
				decode = func(any) error { return nil }
			}
			ca, err := c.Configure(realm, decode)
			if err != nil {
				return nil, fmt.Errorf("method: %s: %w", a.Info().Name, err)
			}
			if ca == nil {
				continue
			}
			if err := Check(ca); err != nil {
				return nil, err
			}
			if ca.Info().Name != a.Info().Name || ca.Info().Feature != a.Info().Feature {
				return nil, fmt.Errorf("method: %s configured as another method", a.Info().Name)
			}
			a = ca
		}
		s.m[a.Info().Name] = a
	}
	for _, a := range extra {
		if err := Check(a); err != nil {
			return nil, err
		}
		s.m[a.Info().Name] = a
	}
	return s, nil
}

// MaxAAL は動いている方式が宣言する AAL の上限の最大（方式が無ければ 0）。
func (s *Set) MaxAAL() int {
	n := 0
	if s == nil {
		return n
	}
	for _, a := range s.m {
		n = max(n, a.Info().AAL)
	}
	return n
}

// Get は名前の方式を返す。
func (s *Set) Get(name string) (port.Authenticator, bool) {
	if s == nil {
		return nil, false
	}
	a, ok := s.m[name]
	return a, ok
}

// Supports は方式 name が動いていて、用途 u に使えるかを返す。
func (s *Set) Supports(name string, u port.MethodUsage) bool {
	a, ok := s.Get(name)
	return ok && a.Info().Supports(u)
}

// Names は用途 u に使える方式の名前を名前順に返す。u が空なら全部。
func (s *Set) Names(u port.MethodUsage) []string {
	if s == nil {
		return nil
	}
	var out []string
	for n, a := range s.m {
		if u == "" || a.Info().Supports(u) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}
