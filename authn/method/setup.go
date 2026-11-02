package method

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/imohiyoko/iam/shared/port"
)

// eventRE は方式の監査ログの出来事の名前（ADR 0104）。
var eventRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

// EventType は方式 name の出来事 ev の監査ログの種類（method.<方式>.<出来事>）を返す。形が誤っていれば空。
func EventType(name, ev string) string {
	if !ValidName(name) || !eventRE.MatchString(ev) {
		return ""
	}
	return "method." + name + "." + ev
}

// Configure は、設定を持つ方式（port.ConfigurableAuthenticator）に setup を渡して、設定済みの方式を返す。設定を持たない方式は
// そのまま返す。
func Configure(ctx context.Context, a port.Authenticator, setup func(port.MethodInfo) port.MethodSetup) (port.Authenticator, error) {
	c, ok := a.(port.ConfigurableAuthenticator)
	if !ok || setup == nil {
		return a, nil
	}
	out, err := c.Setup(ctx, setup(a.Info()))
	if err != nil {
		return nil, fmt.Errorf("method %s: %w", a.Info().Name, err)
	}
	if out.Info().Name != a.Info().Name {
		return nil, fmt.Errorf("method %s: setup returned another method", a.Info().Name)
	}
	if err := Check(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Without は s から names の方式を除いた組を返す（realm の disabled_methods。ADR 0104）。
func (s *Set) Without(names []string) *Set {
	if s == nil || len(names) == 0 {
		return s
	}
	out := &Set{m: map[string]port.Authenticator{}}
	for n, a := range s.m {
		out.m[n] = a
	}
	for _, n := range names {
		delete(out.m, n)
	}
	return out
}

// ScopedEphemeral は、キーを接頭辞で閉じた EphemeralStore（方式に渡す。コアのキーには届かない。ADR 0104）。
type ScopedEphemeral struct {
	Store  port.EphemeralStore
	Prefix string
}

// Scoped は方式 name と realm に閉じた EphemeralStore を返す。
func Scoped(store port.EphemeralStore, name, realmID string) *ScopedEphemeral {
	return &ScopedEphemeral{Store: store, Prefix: "method:v1:" + name + ":" + realmID + ":"}
}

var _ port.EphemeralStore = (*ScopedEphemeral)(nil)

// Get は前置きしたキーで読む。
func (s *ScopedEphemeral) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return s.Store.Get(ctx, s.Prefix+key)
}

// Set は前置きしたキーで書く。
func (s *ScopedEphemeral) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.Store.Set(ctx, s.Prefix+key, value, ttl)
}

// Delete は前置きしたキーを消す。
func (s *ScopedEphemeral) Delete(ctx context.Context, key string) error {
	return s.Store.Delete(ctx, s.Prefix+key)
}

// Take は前置きしたキーを取り出す。
func (s *ScopedEphemeral) Take(ctx context.Context, key string) ([]byte, bool, error) {
	return s.Store.Take(ctx, s.Prefix+key)
}

// Incr は前置きしたキーのカウンタを進める。
func (s *ScopedEphemeral) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.Store.Incr(ctx, s.Prefix+key, ttl)
}

// Shared は元のストアのまま。
func (s *ScopedEphemeral) Shared() bool { return s.Store.Shared() }
