package hibp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/breachcheck/hibp"
)

func TestBreached(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		if r.URL.Path != "/range/5BAA6" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n" +
			"0000000000000000000000000000000000A:0\r\n"))
	}))
	defer srv.Close()
	c := hibp.New(srv.URL, time.Second)
	ctx := context.Background()
	for _, tc := range []struct {
		hash string
		want bool
	}{
		{"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", true},
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", true},
		{"5BAA60000000000000000000000000000000000A", false}, // 詰め物（回数 0）
		{"5BAA6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", false},
	} {
		b, err := c.Breached(ctx, tc.hash)
		if err != nil || b != tc.want {
			t.Errorf("Breached(%s) = %v, %v; want %v", tc.hash, b, err, tc.want)
		}
	}
	if got.Header.Get("Add-Padding") != "true" {
		t.Error("padding not requested")
	}
	if _, err := c.Breached(ctx, "1234567890123456789012345678901234567890"); err == nil {
		t.Error("non-200 must be an error")
	}
	if _, err := c.Breached(ctx, "short"); err == nil {
		t.Error("bad digest must be an error")
	}
}
