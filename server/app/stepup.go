package app

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/shared/acr"
)

// step-up（RFC 9470、ADR 0093）。フィーチャー acr が動いていれば、公開 API の本人の重要な操作で直近の認証や要件が足りず
// 401 を返すときに、`WWW-Authenticate: Bearer error="insufficient_user_authentication"` に求める acr_values・max_age を
// 載せる。応答の本文（`reauthentication_required` など）は変えない（追加の情報だけ）。

// stepUpNote は1つの要求の中で、足りなかった認証を集める。
type stepUpNote struct{ want check.StepUp }

type stepUpKey struct{}

// noteStepUp は足りなかった認証を記録する。withStepUp の外（フィーチャー acr がオフ）なら何もしない。
func noteStepUp(ctx context.Context, s check.StepUp) {
	if n, ok := ctx.Value(stepUpKey{}).(*stepUpNote); ok {
		n.want.AAL = max(n.want.AAL, s.AAL)
		if s.MaxAge > 0 && (n.want.MaxAge == 0 || s.MaxAge < n.want.MaxAge) {
			n.want.MaxAge = s.MaxAge
		}
	}
}

// withStepUp は、記録した足りない認証を 401 の応答の WWW-Authenticate に載せる。記録が無いか、ほかの 401（未ログインなど）
// では何もしない。
func withStepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := &stepUpNote{}
		next.ServeHTTP(&stepUpWriter{ResponseWriter: w, note: n}, r.WithContext(context.WithValue(r.Context(), stepUpKey{}, n)))
	})
}

type stepUpWriter struct {
	http.ResponseWriter
	note    *stepUpNote
	written bool
}

func (w *stepUpWriter) WriteHeader(code int) {
	if !w.written {
		w.written = true
		if code == http.StatusUnauthorized && !w.note.want.Empty() && w.Header().Get("WWW-Authenticate") == "" {
			w.Header().Set("WWW-Authenticate", stepUpChallenge(w.note.want))
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *stepUpWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap は http.ResponseController のため。
func (w *stepUpWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// stepUpChallenge は RFC 9470 3 の WWW-Authenticate の値。値は IAM が決めたもの（acr の値と整数）だけで、引用符を含まない。
func stepUpChallenge(s check.StepUp) string {
	var b strings.Builder
	b.WriteString(`Bearer error="insufficient_user_authentication", error_description="a stronger or more recent authentication is required"`)
	if s.AAL > 0 {
		b.WriteString(`, acr_values="` + acr.Level(s.AAL) + `"`)
	}
	if s.MaxAge > 0 {
		b.WriteString(`, max_age="` + strconv.Itoa(s.MaxAge) + `"`)
	}
	return b.String()
}

// stepUpValues は判定の API の step_up の中身（acr_values と max_age）。求めるものが無ければ ok は false。
func stepUpValues(s check.StepUp) (acrValues *string, maxAge *int, ok bool) {
	if s.Empty() {
		return nil, nil, false
	}
	if s.AAL > 0 {
		v := acr.Level(s.AAL)
		acrValues = &v
	}
	if s.MaxAge > 0 {
		m := s.MaxAge
		maxAge = &m
	}
	return acrValues, maxAge, true
}
