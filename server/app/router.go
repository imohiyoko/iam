package app

import (
	"net/http"
	"strings"
)

// colonMux は `/v1/me/sessions/{id}:revoke` のような、最後の区切りに動詞を付けたパス（design.md 4.13）を
// http.ServeMux で扱う。ServeMux の `{id}` は区切り全体にしか一致しないため、登録時のパターンと
// リクエストのパスの両方で `{id}:verb` を `{id}/:verb` に置き換える。
// ID（UUIDv7 の Crockford Base32）に `:` は含まれない。
type colonMux struct{ *http.ServeMux }

func newColonMux() colonMux { return colonMux{http.NewServeMux()} }

func (m colonMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.ServeMux.HandleFunc(splitVerb(pattern), h)
}

func (m colonMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := splitVerb(r.URL.Path); p != r.URL.Path {
		r2 := r.Clone(r.Context())
		r2.URL.Path, r2.URL.RawPath = p, ""
		r = r2
	}
	m.ServeMux.ServeHTTP(w, r)
}

// splitVerb は最後の区切りの `x:verb` を `x/:verb` にする。
func splitVerb(path string) string {
	i := strings.LastIndexByte(path, '/')
	j := strings.LastIndexByte(path, ':')
	if j <= i+1 || j == len(path)-1 {
		return path
	}
	return path[:j] + "/" + path[j:]
}
