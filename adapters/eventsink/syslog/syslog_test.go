package syslog

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/eventsink/sinkfmt"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
)

func TestSyslogTCPFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var msgs []string
		for range 2 {
			n, err := r.ReadString(' ')
			if err != nil {
				break
			}
			size, _ := strconv.Atoi(strings.TrimSpace(n))
			buf := make([]byte, size)
			if _, err := io.ReadFull(r, buf); err != nil {
				break
			}
			msgs = append(msgs, string(buf))
		}
		got <- msgs
	}()
	s := NewSink(ln.Addr().String(), "tcp", &sinkfmt.Encoder{Format: sinkfmt.FormatIAM, PII: sinkfmt.PIIOmit})
	defer s.Close()
	t0 := time.Date(2026, 10, 27, 1, 2, 3, 0, time.UTC)
	err = s.Emit(context.Background(), []audit.Event{
		{ID: "evt_1", Time: t0, Type: "login.succeeded", Result: audit.ResultSuccess, IP: "203.0.113.0/24"},
		{ID: "evt_2", Time: t0, Type: "login failed", Result: audit.ResultFailure},
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs := <-got
	if len(msgs) != 2 {
		t.Fatalf("messages = %q", msgs)
	}
	// facility 13（log audit）* 8 + informational 6 = 110、失敗は notice 5 = 109。MSGID の空白は除く。
	if !strings.HasPrefix(msgs[0], "<110>1 2026-10-27T01:02:03.000000Z iam iam ") || !strings.Contains(msgs[0], " login.succeeded - {") ||
		strings.Contains(msgs[0], "203.0.113") {
		t.Fatalf("first = %q", msgs[0])
	}
	if !strings.HasPrefix(msgs[1], "<109>1 ") || !strings.Contains(msgs[1], " loginfailed - {") {
		t.Fatalf("second = %q", msgs[1])
	}
}

func TestSyslogReconnects(t *testing.T) {
	s := NewSink("127.0.0.1:1", "tcp", &sinkfmt.Encoder{Format: sinkfmt.FormatIAM, PII: sinkfmt.PIIOmit})
	if err := s.Emit(context.Background(), []audit.Event{{ID: "evt_1", Type: "x"}}); err == nil {
		t.Fatal("unreachable address must fail")
	}
}

func TestSyslogOptions(t *testing.T) {
	f, err := plugin.EventSink("syslog")
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []map[string]string{{}, {"address": "x:514", "network": "sctp"}, {"address": "x:514", "facility": "24"}} {
		if _, err := f(context.Background(), plugin.Config{Options: opts}); err == nil {
			t.Fatalf("%v must be rejected", opts)
		}
	}
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"address": "x:514", "network": "udp", "format": "ocsf"}}); err != nil {
		t.Fatal(err)
	}
}
