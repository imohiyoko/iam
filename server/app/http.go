package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/session"
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

// newPublicHandler は公開 API。ブラウザからの別オリジンの書き込み（CSRF）は CrossOriginProtection で拒否する（2.5）。
// OIDC Provider のエンドポイントは別のオリジンの連携先から呼ばれる（token は連携先のサーバー、authorize はトップレベルの遷移）ので、
// CrossOriginProtection の外に置く。
func newPublicHandler(a *App, login http.Handler) http.Handler {
	h := publicapi.HandlerWithOptions(publicapi.NewStrictHandlerWithOptions(publicServer{a}, nil, publicapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  a.requestError,
		ResponseErrorHandlerFunc: a.responseError,
	}), publicapi.StdHTTPServerOptions{BaseRouter: newColonMux(), ErrorHandlerFunc: a.requestError})
	api := a.withLoginGuard(a.withSession(h))
	protected := http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHosted(r.URL.Path) {
			login.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	}))
	provider := newOIDCHandler(a)
	if provider == nil {
		return protected
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOIDC(r.URL.Path) {
			provider.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})
}

func (s publicServer) Logout(ctx context.Context, _ publicapi.LogoutRequestObject) (publicapi.LogoutResponseObject, error) {
	if au, ok := authFrom(ctx); ok {
		err := s.a.sessions.Revoke(ctx, s.a.realm.ID, au.SessionID, au.PrincipalID, session.ReasonLogout,
			au.Actor(), requestID(ctx))
		if err != nil {
			return nil, err
		}
	}
	setCookie(ctx, clearSessionCookie())
	return publicapi.Logout204Response{}, nil
}

func unauthenticated() publicapi.UnauthenticatedJSONResponse {
	return publicapi.UnauthenticatedJSONResponse{Error: errs.CodeAuthenticationFailed}
}

func (s publicServer) ListMySessions(ctx context.Context, _ publicapi.ListMySessionsRequestObject) (publicapi.ListMySessionsResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMySessions401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	list, err := s.a.sessions.List(ctx, s.a.realm.ID, au.PrincipalID)
	if err != nil {
		return nil, err
	}
	out := make([]publicapi.Session, 0, len(list))
	for _, x := range list {
		out = append(out, publicapi.Session{Id: x.ID, AuthenticatedAt: x.AuthenticatedAt, LastSeenAt: x.LastSeenAt,
			ExpiresAt: x.ExpiresAt, AuthMethods: x.AuthMethods, Current: x.ID == au.SessionID})
	}
	return publicapi.ListMySessions200JSONResponse{Sessions: out}, nil
}

func (s publicServer) RevokeMySession(ctx context.Context, req publicapi.RevokeMySessionRequestObject) (publicapi.RevokeMySessionResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.RevokeMySession401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	err := s.a.sessions.Revoke(ctx, s.a.realm.ID, req.Id, au.PrincipalID, session.ReasonUser,
		au.Actor(), requestID(ctx))
	if errors.Is(err, errs.NotFound) {
		return publicapi.RevokeMySession404JSONResponse{NotFoundJSONResponse: publicapi.NotFoundJSONResponse{Error: "not_found"}}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RevokeMySession204Response{}, nil
}

type adminServer struct{ a *App }

func (s adminServer) GetHealth(ctx context.Context, _ adminapi.GetHealthRequestObject) (adminapi.GetHealthResponseObject, error) {
	if !s.a.healthy(ctx) {
		return adminapi.GetHealth503JSONResponse{Status: adminapi.Unavailable}, nil
	}
	return adminapi.GetHealth200JSONResponse{Status: adminapi.Ok}, nil
}

func newAdminHandler(a *App) http.Handler {
	h := adminapi.HandlerWithOptions(adminapi.NewStrictHandlerWithOptions(adminServer{a}, nil, adminapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  a.requestError,
		ResponseErrorHandlerFunc: a.responseError,
	}), adminapi.StdHTTPServerOptions{BaseRouter: newColonMux(), ErrorHandlerFunc: a.requestError})
	return a.withAdminAuth(h)
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

// unavailable は依存先の障害を 503 で返す。認証の判定ができないときに使う（未ログインとして扱わない）。
func (a *App) unavailable(w http.ResponseWriter, r *http.Request, err error) {
	a.deps.Logger.ErrorContext(r.Context(), "dependency unavailable", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusServiceUnavailable, "unavailable")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// maxBodyBytes はリクエスト本文の上限。超えると本文の読み取りが失敗し、400 invalid_request になる。
const maxBodyBytes = 1 << 20

// withCommon はすべての応答に共通のヘッダーを付ける。リクエスト ID はログの相関に使う（design.md 6.4）。
// 本文の大きさもここで制限する（未認証で呼べる操作があるため）。
func withCommon(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		hdr := w.Header()
		rid := id.NewExternal(id.Request)
		ctx := context.WithValue(r.Context(), requestIDKey{}, rid)
		ctx = context.WithValue(ctx, clientKey{}, clientOf(r))
		// 生成されたハンドラ（strict server）は *http.Request と ResponseWriter を受け取らないため、
		// Cookie の読み書きに使えるよう context に載せる。
		ctx = context.WithValue(ctx, httpKey{}, httpPair{w: w, r: r})
		r = r.WithContext(ctx)
		hdr.Set("X-Request-Id", rid)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

type httpKey struct{}

type httpPair struct {
	w http.ResponseWriter
	r *http.Request
}

func httpFrom(ctx context.Context) httpPair {
	p, _ := ctx.Value(httpKey{}).(httpPair)
	return p
}

// setCookie は応答に Cookie を足す。ハンドラが応答を書く前に呼ぶ。
func setCookie(ctx context.Context, c *http.Cookie) {
	if p := httpFrom(ctx); p.w != nil {
		http.SetCookie(p.w, c)
	}
}

func cookie(ctx context.Context, name string) string {
	if p := httpFrom(ctx); p.r != nil {
		if c, err := p.r.Cookie(name); err == nil {
			return c.Value
		}
	}
	return ""
}
