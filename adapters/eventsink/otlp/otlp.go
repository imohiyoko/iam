// Package otlp は監査イベントを OpenTelemetry のログ（OTLP/HTTP、JSON）で送る EventSink のアダプタ（design.md 6.3、ADR 0071）。
//
// 項目：
//   - endpoint：送り先の URL（例 https://collector:4318/v1/logs）。必須。開発ビルドと localhost のほかは https
//   - headers_env：送るヘッダー（"Name=value,Name=value"）を持つ環境変数の名前（認証の秘密を設定ファイルに書かない）
//   - service_name：resource の service.name（既定 iam）
//   - sinkfmt.Options（format、pii、pseudonym_key_env）
//
// 各イベントを1つの LogRecord にし、body にイベントの JSON、attributes に種類・ID・結果を入れる。
package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/iam/adapters/eventsink/sinkfmt"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
	"github.com/imohiyoko/iam/shared/port"
)

const (
	timeout          = 10 * time.Second
	severityInfo     = 9  // INFO
	severityWarn     = 13 // WARN
	scopeName        = "iam.audit"
	maxResponseBytes = 1 << 16
)

func init() {
	plugin.RegisterEventSink("otlp", func(_ context.Context, cfg plugin.Config) (port.EventSink, error) {
		if err := cfg.CheckOptions(append([]string{"endpoint", "headers_env", "service_name"}, sinkfmt.Options...)...); err != nil {
			return nil, err
		}
		enc, err := sinkfmt.New(cfg)
		if err != nil {
			return nil, err
		}
		endpoint, err := sinkfmt.CheckURL(cfg, cfg.Option("endpoint", ""))
		if err != nil {
			return nil, fmt.Errorf("eventsink otlp: endpoint: %w", err)
		}
		s := &Sink{Endpoint: endpoint, ServiceName: cfg.Option("service_name", "iam"), Header: http.Header{}, enc: enc}
		if name := cfg.Option("headers_env", ""); name != "" {
			if s.Header, err = parseHeaders(os.Getenv(name)); err != nil {
				return nil, fmt.Errorf("eventsink otlp: %s: %w", name, err)
			}
		}
		return s, nil
	})
}

func parseHeaders(v string) (http.Header, error) {
	h := http.Header{}
	for _, kv := range strings.Split(v, ",") {
		if strings.TrimSpace(kv) == "" {
			continue
		}
		k, val, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, errors.New("headers must be Name=value,Name=value")
		}
		h.Set(strings.TrimSpace(k), strings.TrimSpace(val))
	}
	return h, nil
}

// Sink は OTLP/HTTP の送り先に POST する。
type Sink struct {
	Endpoint    string
	ServiceName string
	Header      http.Header
	HTTP        *http.Client
	enc         *sinkfmt.Encoder
}

// NewSink は送り先と Encoder から Sink を作る（テスト用）。
func NewSink(endpoint string, enc *sinkfmt.Encoder) *Sink {
	return &Sink{Endpoint: endpoint, ServiceName: "iam", Header: http.Header{}, enc: enc}
}

type anyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

func kv(k, v string) keyValue { return keyValue{Key: k, Value: anyValue{StringValue: &v}} }

type logRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 anyValue   `json:"body"`
	Attributes           []keyValue `json:"attributes"`
}

// Emit はまとめて1回の要求で送る。2xx 以外はエラー（送出は次回やり直す。受け取る側はイベント ID で重複を除く）。
func (s *Sink) Emit(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	recs := make([]logRecord, 0, len(events))
	for _, e := range events {
		body, err := s.enc.Encode(e)
		if err != nil {
			return err
		}
		b := string(body)
		sev, text := severityInfo, "INFO"
		if e.Result == audit.ResultFailure {
			sev, text = severityWarn, "WARN"
		}
		recs = append(recs, logRecord{TimeUnixNano: strconv.FormatInt(e.Time.UnixNano(), 10), ObservedTimeUnixNano: now, SeverityNumber: sev,
			SeverityText: text, Body: anyValue{StringValue: &b},
			Attributes: []keyValue{kv("event.name", e.Type), kv("event.id", e.ID), kv("iam.result", string(e.Result)), kv("iam.format", s.enc.Format)}})
	}
	payload := map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  map[string]any{"attributes": []keyValue{kv("service.name", s.ServiceName)}},
		"scopeLogs": []any{map[string]any{"scope": map[string]any{"name": scopeName}, "logRecords": recs}},
	}}}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	for k, v := range s.Header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := sinkfmt.Client(s.HTTP).Do(req) // #nosec G704 -- 送り先は運営者が設定した endpoint
	if err != nil {
		return fmt.Errorf("eventsink otlp: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return fmt.Errorf("eventsink otlp: status %d", resp.StatusCode)
	}
	// 2xx の本文は partialSuccess を確かめるために読み切る。読めない・大きすぎるときは、拒まれた記録を見落とさないよう失敗にする。
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("eventsink otlp: read response: %w", err)
	}
	if len(rb) > maxResponseBytes {
		return fmt.Errorf("eventsink otlp: response exceeds %d bytes", maxResponseBytes)
	}
	return partialFailure(rb)
}

// partialFailure は 2xx の応答の partialSuccess で拒まれた記録があればエラーにする（送出全体をやり直す。OTLP の仕様では
// 拒まれた記録は送り直さないが、監査ログは欠けを残さないことを優先する）。
func partialFailure(body []byte) error {
	var r struct {
		PartialSuccess struct {
			RejectedLogRecords json.Number `json:"rejectedLogRecords"`
			ErrorMessage       string      `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("eventsink otlp: invalid response: %w", err)
	}
	if n, err := r.PartialSuccess.RejectedLogRecords.Int64(); err == nil && n > 0 {
		return fmt.Errorf("eventsink otlp: %d log records rejected: %s", n, r.PartialSuccess.ErrorMessage)
	}
	return nil
}
