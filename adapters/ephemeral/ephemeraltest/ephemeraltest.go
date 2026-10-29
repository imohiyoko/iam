// Package ephemeraltest は EphemeralStore の契約テスト（design.md 2.4、12章）。各アダプタのテストから Run を呼ぶ。
package ephemeraltest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/port"
)

// Harness はアダプタごとの用意。
type Harness struct {
	// New は空の EphemeralStore を返す（試験ごとに別のキー空間）。
	New func(t *testing.T) port.EphemeralStore
	// Wait は時刻を d 進める（偽の時計なら Advance、本物の時計なら待つ）。
	Wait func(t *testing.T, d time.Duration)
	// TTL は期限の試験に使う短い期限（本物の時計なら数十ミリ秒）。
	TTL time.Duration
}

// Run は契約テストを動かす。
func Run(t *testing.T, h Harness) {
	if h.TTL <= 0 {
		h.TTL = time.Minute
	}
	ctx := context.Background()
	t.Run("SetGetDelete", func(t *testing.T) {
		s := h.New(t)
		if _, ok, err := s.Get(ctx, "k"); err != nil || ok {
			t.Fatalf("empty Get = %v, %v", ok, err)
		}
		if err := s.Set(ctx, "k", []byte("v1"), time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := s.Set(ctx, "k", []byte("v2"), time.Hour); err != nil {
			t.Fatal(err)
		}
		if v, ok, err := s.Get(ctx, "k"); err != nil || !ok || string(v) != "v2" {
			t.Fatalf("Get = %q, %v, %v", v, ok, err)
		}
		if err := s.Set(ctx, "empty", nil, time.Hour); err != nil {
			t.Fatal(err)
		}
		if v, ok, err := s.Get(ctx, "empty"); err != nil || !ok || len(v) != 0 {
			t.Fatalf("empty value = %q, %v, %v", v, ok, err)
		}
		if err := s.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "missing"); err != nil {
			t.Fatalf("delete missing: %v", err)
		}
		if _, ok, _ := s.Get(ctx, "k"); ok {
			t.Fatal("deleted key present")
		}
	})
	t.Run("TTLRequired", func(t *testing.T) {
		s := h.New(t)
		if err := s.Set(ctx, "k", nil, 0); err == nil {
			t.Fatal("ttl 0 must be rejected")
		}
		if _, err := s.Incr(ctx, "k", -1); err == nil {
			t.Fatal("negative ttl must be rejected")
		}
	})
	t.Run("Expiry", func(t *testing.T) {
		s := h.New(t)
		_ = s.Set(ctx, "k", []byte("v"), h.TTL)
		_, _ = s.Incr(ctx, "n", h.TTL)
		h.Wait(t, h.TTL*2)
		if _, ok, _ := s.Get(ctx, "k"); ok {
			t.Fatal("expired key present")
		}
		if _, ok, _ := s.Take(ctx, "k"); ok {
			t.Fatal("expired key taken")
		}
		if n, err := s.Incr(ctx, "n", time.Hour); err != nil || n != 1 {
			t.Fatalf("counter after expiry = %d, %v", n, err)
		}
	})
	t.Run("TakeOnce", func(t *testing.T) {
		s := h.New(t)
		_ = s.Set(ctx, "k", []byte("v"), time.Hour)
		var wg sync.WaitGroup
		var mu sync.Mutex
		got := 0
		for range 16 {
			wg.Go(func() {
				if v, ok, err := s.Take(ctx, "k"); err == nil && ok && string(v) == "v" {
					mu.Lock()
					got++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if got != 1 {
			t.Fatalf("Take succeeded %d times", got)
		}
	})
	t.Run("IncrConcurrent", func(t *testing.T) {
		s := h.New(t)
		var wg sync.WaitGroup
		seen := make(chan int64, 32)
		for range 32 {
			wg.Go(func() {
				n, err := s.Incr(ctx, "rl", time.Hour)
				if err != nil {
					t.Error(err)
				}
				seen <- n
			})
		}
		wg.Wait()
		close(seen)
		all := map[int64]bool{}
		for n := range seen {
			all[n] = true
		}
		for i := int64(1); i <= 32; i++ {
			if !all[i] {
				t.Fatalf("missing count %d in %v", i, all)
			}
		}
	})
	t.Run("IncrKeepsWindow", func(t *testing.T) {
		s := h.New(t)
		// 窓は最初の Incr から数える（固定窓）。後の Incr で期限は延びない。
		if n, _ := s.Incr(ctx, "rl", h.TTL); n != 1 {
			t.Fatal(n)
		}
		h.Wait(t, h.TTL/2)
		if n, _ := s.Incr(ctx, "rl", h.TTL); n != 2 {
			t.Fatal(n)
		}
		h.Wait(t, h.TTL)
		if n, _ := s.Incr(ctx, "rl", h.TTL); n != 1 {
			t.Fatalf("new window: %d", n)
		}
	})
	t.Run("IncrKeepsSetExpiry", func(t *testing.T) {
		s := h.New(t)
		// Set した値（"0" でも）を増やすときは、Set の期限を変えない。
		if err := s.Set(ctx, "rl", []byte("0"), h.TTL*10); err != nil {
			t.Fatal(err)
		}
		if n, _ := s.Incr(ctx, "rl", h.TTL); n != 1 {
			t.Fatal(n)
		}
		h.Wait(t, h.TTL*2)
		if v, ok, _ := s.Get(ctx, "rl"); !ok || string(v) != "1" {
			t.Fatalf("counter after Set: %q %v", v, ok)
		}
	})
	t.Run("NotACounter", func(t *testing.T) {
		s := h.New(t)
		_ = s.Set(ctx, "k", []byte("abc"), time.Hour)
		if _, err := s.Incr(ctx, "k", time.Hour); err == nil {
			t.Fatal("Incr on a non-counter must fail")
		}
	})
	t.Run("ValueIsCopied", func(t *testing.T) {
		s := h.New(t)
		v := []byte("abc")
		_ = s.Set(ctx, "k", v, time.Hour)
		v[0] = 'x'
		got, _, _ := s.Get(ctx, "k")
		got[1] = 'y'
		again, _, _ := s.Get(ctx, "k")
		if string(again) != "abc" {
			t.Fatalf("stored value mutated: %q", again)
		}
	})
	t.Run("BinaryValues", func(t *testing.T) {
		s := h.New(t)
		v := make([]byte, 256)
		for i := range v {
			v[i] = byte(i)
		}
		_ = s.Set(ctx, "bin", v, time.Hour)
		got, ok, err := s.Get(ctx, "bin")
		if err != nil || !ok || fmt.Sprint(got) != fmt.Sprint(v) {
			t.Fatalf("binary value: %v %v", ok, err)
		}
	})
}
