package fidomds_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imohiyoko/iam/adapters/fidomds/file"
	mdshttp "github.com/imohiyoko/iam/adapters/fidomds/http"
	"github.com/imohiyoko/iam/shared/plugin"
)

func TestFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "blob.jwt")
	if err := os.WriteFile(p, []byte("a.b.c"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := file.Source{Path: p}.Fetch(context.Background())
	if err != nil || string(b) != "a.b.c" {
		t.Fatalf("Fetch = %q, %v", b, err)
	}
	if _, err := (file.Source{Path: p + ".missing"}).Fetch(context.Background()); err == nil {
		t.Fatal("missing file: want error")
	}
	f, err := plugin.FIDOMDS("file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f(context.Background(), plugin.Config{}); err == nil {
		t.Fatal("no path: want error")
	}
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"path": p, "x": "y"}}); err == nil {
		t.Fatal("unknown option: want error")
	}
}

func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("blob"))
	}))
	defer srv.Close()
	b, err := mdshttp.New(srv.URL+"/", time.Second).Fetch(context.Background())
	if err != nil || string(b) != "blob" {
		t.Fatalf("Fetch = %q, %v", b, err)
	}
	if _, err := mdshttp.New(srv.URL+"/missing", time.Second).Fetch(context.Background()); err == nil {
		t.Fatal("404: want error")
	}
	f, err := plugin.FIDOMDS("http")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f(context.Background(), plugin.Config{Options: map[string]string{"url": srv.URL}}); err == nil {
		t.Fatal("http outside dev: want error")
	}
	if _, err := f(context.Background(), plugin.Config{Dev: true, Options: map[string]string{"url": srv.URL}}); err != nil {
		t.Fatalf("http in dev: %v", err)
	}
	if _, err := f(context.Background(), plugin.Config{}); err != nil {
		t.Fatalf("default url: %v", err)
	}
}
