package otlp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/plugin"
)

func TestOTLPLogs(t *testing.T) {
	var body []byte
	var auth string
	status := http.StatusOK
	reply := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		auth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	defer srv.Close()
	t.Setenv("IAM_TEST_OTLP_HEADERS", "Authorization=Bearer t0ken, X-Scope = audit")
	f, err := plugin.EventSink("otlp")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := f(context.Background(), plugin.Config{Options: map[string]string{"endpoint": srv.URL + "/v1/logs", "headers_env": "IAM_TEST_OTLP_HEADERS",
		"format": "ocsf"}})
	if err != nil {
		t.Fatal(err)
	}
	e := audit.Event{ID: "evt_1", Time: time.Unix(1700000000, 5).UTC(), Type: "login.failed", Result: audit.ResultFailure}
	if err := sink.Emit(context.Background(), []audit.Event{e}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					TimeUnixNano   string `json:"timeUnixNano"`
					SeverityNumber int    `json:"severityNumber"`
					Body           struct {
						StringValue string `json:"stringValue"`
					} `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	rec := got.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if rec.TimeUnixNano != "1700000000000000005" || rec.SeverityNumber != severityWarn || !strings.Contains(rec.Body.StringValue, `"class_uid":3002`) {
		t.Fatalf("record = %+v", rec)
	}
	if auth != "Bearer t0ken" {
		t.Fatalf("authorization = %q", auth)
	}
	// 2xx でも partialSuccess で拒まれた記録があれば失敗（rejectedLogRecords は int64 で、JSON では文字列にもなる）。
	for _, r := range []string{`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"bad"}}`, `{"partialSuccess":{"rejectedLogRecords":2}}`} {
		reply = r
		if err := sink.Emit(context.Background(), []audit.Event{e}); err == nil {
			t.Fatalf("partial success %s must fail", r)
		}
	}
	reply = `{"partialSuccess":{}}`
	if err := sink.Emit(context.Background(), []audit.Event{e}); err != nil {
		t.Fatal(err)
	}
	status = http.StatusServiceUnavailable
	if err := sink.Emit(context.Background(), []audit.Event{e}); err == nil {
		t.Fatal("5xx must fail")
	}
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"endpoint": "http://collector.example/v1/logs"}}); err == nil {
		t.Fatal("plain http to a remote host must be rejected")
	}
}
