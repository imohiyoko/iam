package botcheck_test

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
)

// store は期限つきの EphemeralStore のテスト用の実装（authn/ からは adapters/ を import しない）。
type store struct {
	clk clock.Clock
	mu  sync.Mutex
	m   map[string]entry
}

type entry struct {
	v   []byte
	exp time.Time
}

func newStore(clk clock.Clock) *store { return &store{clk: clk, m: map[string]entry{}} }

func (s *store) live(key string) (entry, bool) {
	e, ok := s.m[key]
	if !ok || (!e.exp.IsZero() && !s.clk.Now().Before(e.exp)) {
		delete(s.m, key)
		return entry{}, false
	}
	return e, true
}

func (s *store) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(key)
	return e.v, ok, nil
}

func (s *store) Set(_ context.Context, key string, v []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := entry{v: v}
	if ttl > 0 {
		e.exp = s.clk.Now().Add(ttl)
	}
	s.m[key] = e
	return nil
}

func (s *store) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *store) Take(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(key)
	delete(s.m, key)
	return e.v, ok, nil
}

func (s *store) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.live(key)
	n := int64(1)
	if ok {
		p, err := strconv.ParseInt(string(e.v), 10, 64)
		if err != nil {
			return 0, err
		}
		n = p + 1
	} else if ttl > 0 {
		e.exp = s.clk.Now().Add(ttl)
	}
	e.v = strconv.AppendInt(nil, n, 10)
	s.m[key] = e
	return n, nil
}

func (s *store) Shared() bool { return false }
