// Package syslog は監査イベントを syslog（RFC 5424）で送る EventSink のアダプタ（design.md 6.3、ADR 0071）。
//
// 項目：
//   - address：送り先（host:port）。必須
//   - network：tcp（既定）・tls・udp。tcp と tls は RFC 6587 のオクテット数えの枠付けで送る
//   - app_name：APP-NAME（既定 iam）。facility：0〜23（既定 13 = log audit）
//   - sinkfmt.Options（format、pii、pseudonym_key_env）
//
// MSG はイベントの JSON、MSGID はイベントの種類。失敗の結果は notice、それ以外は informational。
package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imohiyoko/iam/adapters/eventsink/sinkfmt"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	severityNotice = 5
	severityInfo   = 6
	dialTimeout    = 5 * time.Second
	writeTimeout   = 10 * time.Second
	maxMsgID       = 32
)

func init() {
	plugin.RegisterEventSink("syslog", func(_ context.Context, cfg plugin.Config) (port.EventSink, error) {
		if err := cfg.CheckOptions(append([]string{"address", "network", "app_name", "facility"}, sinkfmt.Options...)...); err != nil {
			return nil, err
		}
		enc, err := sinkfmt.New(cfg)
		if err != nil {
			return nil, err
		}
		s := &Sink{Address: cfg.Option("address", ""), Network: cfg.Option("network", "tcp"), AppName: cfg.Option("app_name", "iam"), enc: enc}
		if s.Address == "" {
			return nil, errors.New("eventsink syslog: address is required")
		}
		if s.Network != "tcp" && s.Network != "tls" && s.Network != "udp" {
			return nil, fmt.Errorf("eventsink syslog: unknown network %q (known: tcp, tls, udp)", s.Network)
		}
		f, err := strconv.Atoi(cfg.Option("facility", "13"))
		if err != nil || f < 0 || f > 23 {
			return nil, errors.New("eventsink syslog: facility must be 0-23")
		}
		s.Facility = f
		s.Hostname, _ = os.Hostname()
		return s, nil
	})
}

// Sink は syslog の送り先に書く。接続は使い回し、失敗したら次の Emit でつなぎ直す。
type Sink struct {
	Address  string
	Network  string // tcp / tls / udp
	AppName  string
	Facility int
	Hostname string
	// TLS は network が tls のときの設定（nil なら既定）。
	TLS *tls.Config

	enc  *sinkfmt.Encoder
	mu   sync.Mutex
	conn net.Conn
}

// NewSink は送り先と Encoder から Sink を作る（テスト用）。
func NewSink(address, network string, enc *sinkfmt.Encoder) *Sink {
	return &Sink{Address: address, Network: network, AppName: "iam", Facility: 13, Hostname: "iam", enc: enc}
}

func (s *Sink) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout}
	switch s.Network {
	case "tls":
		cfg := s.TLS
		if cfg == nil {
			host, _, _ := net.SplitHostPort(s.Address)
			cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		}
		return (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", s.Address)
	default:
		return d.DialContext(ctx, s.Network, s.Address)
	}
}

// Emit は1件ずつ送る。途中で失敗すればエラーを返し、送出は次回まとめてやり直す（受け取る側はイベント ID で重複を除く）。
func (s *Sink) Emit(ctx context.Context, events []audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		msg, err := s.format(e)
		if err != nil {
			return err
		}
		if err := s.write(ctx, msg); err != nil {
			return fmt.Errorf("eventsink syslog: %w", err)
		}
	}
	return nil
}

func (s *Sink) write(ctx context.Context, msg []byte) error {
	if s.conn == nil {
		c, err := s.dial(ctx)
		if err != nil {
			return err
		}
		s.conn = c
	}
	frame := msg
	if s.Network != "udp" {
		frame = append([]byte(strconv.Itoa(len(msg))+" "), msg...)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := s.conn.Write(frame); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// format は RFC 5424 のメッセージを作る。構造化データは使わない（-）。
func (s *Sink) format(e audit.Event) ([]byte, error) {
	body, err := s.enc.Encode(e)
	if err != nil {
		return nil, err
	}
	sev := severityInfo
	if e.Result == audit.ResultFailure {
		sev = severityNotice
	}
	head := fmt.Sprintf("<%d>1 %s %s %s %d %s - ", s.Facility*8+sev, e.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		field(s.Hostname, 255), field(s.AppName, 48), os.Getpid(), field(e.Type, maxMsgID))
	return append([]byte(head), body...), nil
}

// field は RFC 5424 のヘッダーの項目（表示できる ASCII、空白なし、長さの上限）。空なら -。
func field(v string, limit int) string {
	v = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, v)
	if len(v) > limit {
		v = v[:limit]
	}
	if v == "" {
		return "-"
	}
	return v
}

// Close は接続を閉じる。
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}
