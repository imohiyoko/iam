package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/eventsink/sinkfmt"
	"github.com/imohiyoko/iam/shared/audit"
)

func TestWebhookSigned(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Unix(1700000000, 0)
	var body []byte
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		sig = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := NewSink(srv.URL, secret, &sinkfmt.Encoder{Format: sinkfmt.FormatIAM, PII: sinkfmt.PIIOmit})
	s.Now = func() time.Time { return now }
	events := []audit.Event{{ID: "evt_1", Type: "user.created", IP: "203.0.113.0/24", Client: "sealed"}, {ID: "evt_2", Type: "user.updated"}}
	if err := s.Emit(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if sig != Sign(secret, now, body) || !strings.HasPrefix(sig, "t=1700000000,v1=") {
		t.Fatalf("signature = %q", sig)
	}
	var got struct{ Events []audit.Event }
	if err := json.Unmarshal(body, &got); err != nil || len(got.Events) != 2 || got.Events[0].IP != "" || got.Events[0].Client != "" {
		t.Fatalf("body = %s (%v)", body, err)
	}
}

func TestWebhookFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer srv.Close()
	s := NewSink(srv.URL, nil, &sinkfmt.Encoder{Format: sinkfmt.FormatIAM, PII: sinkfmt.PIIOmit})
	if err := s.Emit(context.Background(), []audit.Event{{ID: "evt_1"}}); err == nil {
		t.Fatal("non-2xx must fail")
	}
}
