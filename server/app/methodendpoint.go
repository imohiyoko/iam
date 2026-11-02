package app

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// 方式のエンドポイント（port.EndpointAuthenticator。ADR 0108）。HTTP の形を外部の仕様が決める方式（OpenID4VP のウォレットの
// request_uri・response_uri）のために、GET・POST /v1/login/methods/{method}/endpoints/{endpoint} を方式に渡す。
// セッションを要さず、CrossOriginProtection の外に置く（呼び出し元はブラウザでない）。/v1/login/ の下なので、POST には
// withLoginGuard の接続元ごとのレートリミットと応答時間の下限が効く。

const methodEndpointPrefix = "/v1/login/methods/"

// maxEndpointBody は方式のエンドポイントの本文の上限（OpenID4VP の vp_token を受ける大きさ）。
const maxEndpointBody = 256 << 10

// methodEndpointPath はパスが方式のエンドポイントなら、方式とエンドポイントの名前を返す。
func methodEndpointPath(path string) (string, string, bool) {
	rest, ok := strings.CutPrefix(path, methodEndpointPrefix)
	if !ok {
		return "", "", false
	}
	name, rest, ok := strings.Cut(rest, "/endpoints/")
	if !ok || !method.ValidName(name) || !method.ValidName(rest) {
		return "", "", false
	}
	return name, rest, true
}

// isMethodEndpoint は方式のエンドポイントへの要求かを返す。
func isMethodEndpoint(r *http.Request) bool {
	_, _, ok := methodEndpointPath(r.URL.Path)
	return ok
}

// methodEndpoint は方式のエンドポイントを呼ぶ。
func (a *App) methodEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name, ep, _ := methodEndpointPath(r.URL.Path)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	req := port.MethodHTTPRequest{Endpoint: ep, HTTPMethod: r.Method, Query: r.URL.Query(), Form: url.Values{}}
	if r.Method == http.MethodPost {
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxEndpointBody)
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		req.Form = r.PostForm
	}
	c := a.clientOf(r.Context())
	out, err := a.credentials.Endpoint(r.Context(), a.realm.ID, name, req, credential.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID})
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		writeRateLimited(w, ex)
		return
	}
	switch {
	case errors.Is(err, credential.ErrUnknownMethod):
		writeError(w, http.StatusNotFound, "not_found")
		return
	case errors.Is(err, credential.ErrEndpointRejected):
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	case err != nil:
		a.responseError(w, r, err)
		return
	}
	if out.Status == 0 {
		out.Status = http.StatusOK
	}
	if out.ContentType != "" {
		w.Header().Set("Content-Type", out.ContentType)
	}
	w.WriteHeader(out.Status)
	_, _ = w.Write(out.Body)
}
