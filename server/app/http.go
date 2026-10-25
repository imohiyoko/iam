package app

import (
	"context"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/id"
)

// healthTimeout はヘルスチェックで依存先を確かめるときの上限。
const healthTimeout = 2 * time.Second

func (a *App) healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	return a.deps.Storage.Ping(ctx) == nil
}

type publicServer struct{ a *App }

func (s publicServer) GetHealth(ctx context.Context, _ publicapi.GetHealthRequestObject) (publicapi.GetHealthResponseObject, error) {
	if !s.a.healthy(ctx) {
		return publicapi.GetHealth503JSONResponse{Status: publicapi.Unavailable}, nil
	}
	return publicapi.GetHealth200JSONResponse{Status: publicapi.Ok}, nil
}

func newPublicHandler(a *App) http.Handler {
	return publicapi.Handler(publicapi.NewStrictHandler(publicServer{a}, nil))
}

type adminServer struct{ a *App }

func (s adminServer) GetHealth(ctx context.Context, _ adminapi.GetHealthRequestObject) (adminapi.GetHealthResponseObject, error) {
	if !s.a.healthy(ctx) {
		return adminapi.GetHealth503JSONResponse{Status: adminapi.Unavailable}, nil
	}
	return adminapi.GetHealth200JSONResponse{Status: adminapi.Ok}, nil
}

func newAdminHandler(a *App) http.Handler {
	return adminapi.Handler(adminapi.NewStrictHandler(adminServer{a}, nil))
}

// withCommon はすべての応答に共通のヘッダーを付ける。リクエスト ID はログの相関に使う（design.md 6.4）。
func withCommon(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Request-Id", id.New(id.Request))
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}
