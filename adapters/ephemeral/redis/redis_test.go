package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/ephemeral/ephemeraltest"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 試験は IAM_TEST_REDIS（redis://...）があるときだけ動く。試験ごとに別の prefix を使う。
func TestContract(t *testing.T) {
	url := os.Getenv("IAM_TEST_REDIS")
	if url == "" {
		t.Skip("IAM_TEST_REDIS is not set")
	}
	ephemeraltest.Run(t, ephemeraltest.Harness{
		New: func(t *testing.T) port.EphemeralStore {
			b := make([]byte, 6)
			_, _ = rand.Read(b)
			s, err := Open(context.Background(), url, "iamtest:"+hex.EncodeToString(b)+":")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
		Wait: func(_ *testing.T, d time.Duration) { time.Sleep(d) },
		TTL:  100 * time.Millisecond,
	})
}

// 期限はミリ秒に切り上げる（1ms 未満を 0 にすると、Incr の PEXPIRE 0 でキーがすぐ消える）。
func TestCeilMS(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		500 * time.Microsecond:             time.Millisecond,
		time.Millisecond:                   time.Millisecond,
		time.Millisecond + time.Nanosecond: 2 * time.Millisecond,
		100 * time.Millisecond:             100 * time.Millisecond,
		time.Second + 999*time.Microsecond: time.Second + time.Millisecond,
		time.Duration(math.MaxInt64):       time.Duration(math.MaxInt64).Truncate(time.Millisecond),
	} {
		if got := ceilMS(in); got != want {
			t.Errorf("ceilMS(%v) = %v, want %v", in, got, want)
		}
	}
}

// 繋がらないときは KindUnavailable（呼び出し側は 503 にする）。
func TestOpenUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Open(ctx, "redis://127.0.0.1:1/0", "")
	if e, ok := errors.AsType[*errs.Error](err); !ok || e.Kind != errs.KindUnavailable {
		t.Fatalf("Open: %v", err)
	}
}

func TestOpenRejectsBadURL(t *testing.T) {
	if _, err := Open(context.Background(), "http://x", ""); err == nil {
		t.Fatal("want error")
	}
}
