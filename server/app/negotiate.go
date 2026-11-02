package app

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"

	"github.com/imohiyoko/iam/authn/credential"
)

// HTTP の Negotiate の認証（RFC 4559。Kerberos / SPNEGO。ADR 0107）。
//
// `Authorization: Negotiate <Base64>` は、汎用のログインの完了と登録のパスでだけ読み、トークンを ctx に載せて方式に
// MethodEnv.Negotiate で渡す（確かめるのは方式）。ヘッダーはどのパスでも読んだら消す。Authorization を Bearer のセッションと
// 取り違えないため（登録はブラウザの Cookie のセッションと一緒に届く）。方式がトークンを求めたら（port.ErrNegotiate）、
// 401 と `WWW-Authenticate: Negotiate` を返し、ブラウザにトークンを付けて送り直させる。

// maxNegotiateHeader は受け付ける Negotiate のトークンの大きさ（Base64 の文字数）。AD の PAC を含むチケットでも 48 KiB 程度。
const maxNegotiateHeader = 64 << 10

// negotiatePath は Negotiate のトークンを読むパス。
var negotiatePath = regexp.MustCompile(`^/v1/(?:login/methods/[a-z][a-z0-9_]{0,31}:complete|me/credentials/[a-z][a-z0-9_]{0,31}:(?:enroll-begin|enroll-complete))$`)

// negotiateToken は Authorization の値が Negotiate の方式なら、Base64 を戻したトークンを返す（ok は Negotiate の方式か）。
// 形の誤り・大きすぎるものは空のトークン（方式が拒む）。
func negotiateToken(h string) (token []byte, ok bool) {
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Negotiate") {
		return nil, false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || len(rest) > maxNegotiateHeader {
		return nil, true
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil || len(b) == 0 {
		return nil, true
	}
	return b, true
}

// withNegotiate は Negotiate のトークンを読み、ヘッダーを消す。
func withNegotiate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs := r.Header.Values("Authorization")
		if len(vs) == 0 {
			h.ServeHTTP(w, r)
			return
		}
		tok, ok := negotiateToken(vs[0])
		if !ok {
			h.ServeHTTP(w, r)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Del("Authorization")
		if len(vs) == 1 && r.Method == http.MethodPost && negotiatePath.MatchString(r.URL.Path) {
			if tok == nil {
				// 形の誤りは、トークンが無いのと区別して方式に拒ませる（チャレンジを繰り返させない）。
				tok = []byte{}
			}
			r = r.WithContext(credential.WithNegotiateToken(r.Context(), tok))
		}
		h.ServeHTTP(w, r)
	})
}

// challengeNegotiate は応答に `WWW-Authenticate: Negotiate` を足す。ハンドラが応答を書く前に呼ぶ。
func challengeNegotiate(ctx context.Context) {
	if p := httpFrom(ctx); p.w != nil {
		p.w.Header().Set("WWW-Authenticate", "Negotiate")
	}
}
