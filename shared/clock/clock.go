// Package clock は Clock ポートの実装を提供する（design.md 2.4、2.7）。
//
// 時刻の取得はすべて Clock を通す。値は常に UTC。
package clock

import (
	"sync"
	"time"
)

// Clock は現在時刻を返す。
type Clock interface {
	Now() time.Time
}

// System はシステム時計。
type System struct{}

// Now は UTC の現在時刻を返す。
func (System) Now() time.Time { return time.Now().UTC() }

// Fake はテスト用の偽の時計。Advance か Set で進めるまで止まっている。
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake は t から始まる偽の時計を返す。
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC()} }

// Now は偽の現在時刻を返す。
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance は時計を d だけ進める。
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set は時計を t に合わせる。
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}
