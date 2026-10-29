// Package stdout は監査イベントを JSON Lines で標準出力に書く EventSink のアダプタ（design.md 6.3）。
//
// 項目は sinkfmt.Options（format、pii、pseudonym_key_env）。
package stdout

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/imohiyoko/iam/adapters/eventsink/sinkfmt"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

func init() {
	plugin.RegisterEventSink("stdout", func(_ context.Context, cfg plugin.Config) (port.EventSink, error) {
		if err := cfg.CheckOptions(sinkfmt.Options...); err != nil {
			return nil, err
		}
		enc, err := sinkfmt.New(cfg)
		if err != nil {
			return nil, err
		}
		w := cfg.Stdout
		if w == nil {
			w = os.Stdout
		}
		return &Sink{w: w, enc: enc}, nil
	})
}

// Sink は w に1行1イベントで書く。
type Sink struct {
	mu  sync.Mutex
	w   io.Writer
	enc *sinkfmt.Encoder
}

// New は個人情報を出さない（omit）、独自の JSON の Sink を返す。
func New(w io.Writer) *Sink {
	return &Sink{w: w, enc: &sinkfmt.Encoder{Format: sinkfmt.FormatIAM, PII: sinkfmt.PIIOmit}}
}

// Emit はイベントを書く。
func (s *Sink) Emit(_ context.Context, events []audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		b, err := s.enc.Encode(e)
		if err != nil {
			return err
		}
		if _, err := s.w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}
