package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

func TestNotifySigned(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	clk := clock.NewFake(time.Unix(1_800_000_000, 0))
	var got port.Notification
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-IAM-Signature") != Sign(secret, body, clk.Now()) {
			w.WriteHeader(401)
			return
		}
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	n := New(srv.URL, secret, time.Second, clk)
	x := port.Notification{ID: "ntf_1", Type: "magic_link", RealmID: "rlm_1", HasSecret: true}
	if err := n.Notify(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	if got.ID != "ntf_1" || !got.HasSecret {
		t.Fatalf("received %+v", got)
	}
	// 署名の鍵が違えば受け取る側が拒否し、Notify はエラーにする（再送される）。
	if err := New(srv.URL, []byte("wrong-secret-wrong-secret-wrong!"), time.Second, clk).Notify(context.Background(), x); err == nil {
		t.Fatal("want error for non-2xx")
	}
}

func TestNoRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("redirect followed") }))
	defer target.Close()
	srv := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer srv.Close()
	if err := New(srv.URL, []byte("0123456789abcdef0123456789abcdef"), time.Second, nil).Notify(context.Background(), port.Notification{ID: "ntf_1"}); err == nil {
		t.Fatal("want error")
	}
}
