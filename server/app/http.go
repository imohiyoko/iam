package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
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
	return publicapi.Handler(publicapi.NewStrictHandlerWithOptions(publicServer{a}, nil, publicapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  a.requestError,
		ResponseErrorHandlerFunc: a.responseError,
	}))
}

type adminServer struct{ a *App }

func (s adminServer) GetHealth(ctx context.Context, _ adminapi.GetHealthRequestObject) (adminapi.GetHealthResponseObject, error) {
	if !s.a.healthy(ctx) {
		return adminapi.GetHealth503JSONResponse{Status: adminapi.Unavailable}, nil
	}
	return adminapi.GetHealth200JSONResponse{Status: adminapi.Ok}, nil
}

func newAdminHandler(a *App) http.Handler {
	return adminapi.Handler(adminapi.NewStrictHandlerWithOptions(adminServer{a}, nil, adminapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  a.requestError,
		ResponseErrorHandlerFunc: a.responseError,
	}))
}

// requestError は要求の形式の誤りを返す。内部の説明は返さない。
func (a *App) requestError(w http.ResponseWriter, r *http.Request, err error) {
	a.deps.Logger.InfoContext(r.Context(), "bad request", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusBadRequest, "invalid_request")
}

// responseError は処理中のエラーを返す。外部に返すのは errs.Error.Code だけで、
// 内部向けの説明（Msg や DB のエラー）はログにだけ出す。
func (a *App) responseError(w http.ResponseWriter, r *http.Request, err error) {
	a.deps.Logger.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "error", err)
	var e *errs.Error
	code := "internal"
	if errors.As(err, &e) && e.Code != "" {
		code = e.Code
	}
	writeError(w, http.StatusInternalServerError, code)
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
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
