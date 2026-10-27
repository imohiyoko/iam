package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/ephemeral/ephemeraltest"
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

func TestOpenRejectsBadURL(t *testing.T) {
	if _, err := Open(context.Background(), "http://x", ""); err == nil {
		t.Fatal("want error")
	}
}
