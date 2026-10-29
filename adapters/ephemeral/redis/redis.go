// Package redis は EphemeralStore の Redis のアダプタ（design.md 2.4）。複数のインスタンスで共有できる（Shared は true）。
//
// 期限は Redis の時計で決まる（PX）。Take は GETDEL（Redis 6.2 以降）、Incr は最初の1回だけ期限を付ける Lua で原子的に行う。
package redis

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterEphemeral("redis", func(ctx context.Context, cfg plugin.Config) (port.EphemeralStore, error) {
		if err := cfg.CheckOptions("url", "prefix"); err != nil {
			return nil, err
		}
		u := cfg.Option("url", "")
		if u == "" {
			return nil, errors.New("ephemeral redis: url is required (redis://... or rediss://...)")
		}
		return Open(ctx, u, cfg.Option("prefix", "iam:"))
	})
}

// Store は Redis の EphemeralStore。
type Store struct {
	c      goredis.UniversalClient
	prefix string
}

var _ port.EphemeralStore = (*Store)(nil)

// Open は url（redis://user:pass@host:6379/0、TLS は rediss://）の Redis に繋ぐ。キーには prefix を付ける。
func Open(ctx context.Context, url, prefix string) (*Store, error) {
	opt, err := goredis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	s := New(goredis.NewClient(opt), prefix)
	if err := s.c.Ping(ctx).Err(); err != nil {
		_ = s.c.Close()
		return nil, mapErr(err)
	}
	return s, nil
}

// New はクライアントから Store を作る。
func New(c goredis.UniversalClient, prefix string) *Store { return &Store{c: c, prefix: prefix} }

// Close は接続を閉じる。
func (s *Store) Close() error { return s.c.Close() }

func (s *Store) key(k string) string { return s.prefix + k }

func ttlErr(ttl time.Duration) error {
	if ttl <= 0 {
		return errs.New(errs.KindInvalid, "ephemeral: ttl is required")
	}
	return nil
}

// ceilMS は ttl をミリ秒に切り上げる（Redis の期限はミリ秒単位。切り捨てると 1ms 未満が 0 になり、Set は拒まれ、
// Incr は PEXPIRE 0 でキーがすぐ消える）。足すと溢れるほど長いときは切り捨てる。
func ceilMS(ttl time.Duration) time.Duration {
	d := ttl.Truncate(time.Millisecond)
	if d < ttl && d <= math.MaxInt64-time.Millisecond {
		d += time.Millisecond
	}
	return d
}

// mapErr は接続の失敗などを KindUnavailable にする（呼び出し側は 503 にする）。
func mapErr(err error) error {
	if _, ok := errors.AsType[*errs.Error](err); err == nil || ok {
		return err
	}
	return errs.Wrap(errs.KindUnavailable, err, "ephemeral redis")
}

func (s *Store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := s.c.Get(ctx, s.key(key)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, mapErr(err)
	}
	return v, true, nil
}

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ttlErr(ttl); err != nil {
		return err
	}
	if value == nil {
		value = []byte{}
	}
	return mapErr(s.c.Set(ctx, s.key(key), value, ceilMS(ttl)).Err())
}

func (s *Store) Delete(ctx context.Context, key string) error {
	return mapErr(s.c.Del(ctx, s.key(key)).Err())
}

func (s *Store) Take(ctx context.Context, key string) ([]byte, bool, error) {
	v, err := s.c.GetDel(ctx, s.key(key)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, mapErr(err)
	}
	return v, true, nil
}

// incrScript は1増やし、新しいキーのときだけ期限を付ける（固定窓。Set した "0" を増やしても期限は変えない）。
var incrScript = goredis.NewScript(`
local fresh = redis.call('EXISTS', KEYS[1]) == 0
local n = redis.call('INCR', KEYS[1])
if fresh then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n`)

func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if err := ttlErr(ttl); err != nil {
		return 0, err
	}
	n, err := incrScript.Run(ctx, s.c, []string{s.key(key)}, ceilMS(ttl).Milliseconds()).Int64()
	if err != nil && strings.Contains(err.Error(), "not an integer") {
		return 0, errs.New(errs.KindInvalid, "ephemeral: %q is not a counter", key)
	}
	return n, mapErr(err)
}

func (s *Store) Shared() bool { return true }
