// Package stdout は監査イベントを JSON Lines で標準出力に書く EventSink のアダプタ（design.md 6.3）。
package stdout

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterEventSink("stdout", func(_ context.Context, cfg plugin.Config) (port.EventSink, error) {
		if err := cfg.CheckOptions(); err != nil {
			return nil, err
		}
		w := cfg.Stdout
		if w == nil {
			w = os.Stdout
		}
		return New(w), nil
	})
}

// Sink は w に1行1イベントで書く。
type Sink struct {
	mu sync.Mutex
	w  io.Writer
}

// New は Sink を返す。
func New(w io.Writer) *Sink { return &Sink{w: w} }

// Emit はイベントを書く。個人情報は呼び出し側（outbox に積む時点）で外してある。
func (s *Sink) Emit(_ context.Context, events []audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := json.NewEncoder(s.w)
	for _, e := range events {
		if err := enc.Encode(audit.External(e)); err != nil {
			return err
		}
	}
	return nil
}
