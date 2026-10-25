// Package memory は EphemeralStore のインメモリのアダプタ。
//
// 期限は Clock で判定するため、偽の時計で時刻の境界をテストできる。
// 複数インスタンスでは共有できない（Shared は false）。
package memory

import (
	"bytes"
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterEphemeral("memory", func(_ context.Context, cfg plugin.Config) (port.EphemeralStore, error) {
		return New(cfg.Clock), nil
	})
}

type entry struct {
	value     []byte
	expiresAt time.Time
}

// Store はインメモリの EphemeralStore。
type Store struct {
	mu    sync.Mutex
	m     map[string]entry
	clock clock.Clock
}

var _ port.EphemeralStore = (*Store)(nil)

// New は Store を返す。
func New(clk clock.Clock) *Store {
	if clk == nil {
		clk = clock.System{}
	}
	return &Store{m: map[string]entry{}, clock: clk}
}

// live は期限内のエントリを返す。期限の時刻ちょうどで失効する（expiresAt は含まない）。
func (s *Store) live(key string, now time.Time) (entry, bool) {
	e, ok := s.m[key]
	if !ok {
		return entry{}, false
	}
	if !now.Before(e.expiresAt) {
		delete(s.m, key)
		return entry{}, false
	}
	return e, true
}

func (s *Store) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(key, s.clock.Now())
	if !ok {
		return nil, false, nil
	}
	return bytes.Clone(e.value), true, nil
}

func (s *Store) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return errs.New(errs.KindInvalid, "ephemeral: ttl is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = entry{value: bytes.Clone(value), expiresAt: s.clock.Now().Add(ttl)}
	return nil
}

func (s *Store) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *Store) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, errs.New(errs.KindInvalid, "ephemeral: ttl is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	e, ok := s.live(key, now)
	var n int64
	if ok {
		var err error
		if n, err = strconv.ParseInt(string(e.value), 10, 64); err != nil {
			return 0, errs.New(errs.KindInvalid, "ephemeral: %q is not a counter", key)
		}
	} else {
		e.expiresAt = now.Add(ttl)
	}
	n++
	e.value = strconv.AppendInt(nil, n, 10)
	s.m[key] = e
	return n, nil
}

func (s *Store) Shared() bool { return false }

// Sweep は期限切れのエントリを消す（メモリの回収用。正しさには影響しない）。
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, n := s.clock.Now(), 0
	for k := range s.m {
		if _, ok := s.live(k, now); !ok {
			n++
		}
	}
	return n
}
