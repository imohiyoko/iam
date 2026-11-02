package app

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/imohiyoko/iam/authn/credential"
	"github.com/imohiyoko/iam/server/config"
)

// クライアント証明書の受け取り（ADR 0103）。証明書は2つの経路でだけ受け取り、方式に MethodEnv.ClientCertificates で渡す。
//
//   - mTLS の専用の待ち受け（server.client_certificates.mtls_addr）：TLS のハンドシェイクでクライアントに証明書を求める。
//     秘密鍵の所持は TLS（CertificateVerify）で確かめてある。連鎖は確かめない（realm ごとのトラストアンカーで方式が確かめる）。
//     認証方式のログインと登録のパスだけを通す
//   - TLS を終端するプロキシのヘッダー（server.client_certificates.header）：直接の接続元（RemoteAddr）が設定の proxies に
//     含まれるときだけ読む。それ以外の要求のヘッダーは読まない（利用者が書いた値を信じない）

// 受け取る連鎖の数と大きさの上限（方式も確かめる）。
const (
	maxClientCerts     = 8
	maxClientCertBytes = 16 << 10
)

// mtlsPath は mTLS の専用の待ち受けで通すパス（realm の接頭辞を許す）。
var mtlsPath = regexp.MustCompile(`^(?:/realms/[a-z0-9][a-z0-9-]{0,62})?/v1/(?:login/methods/[a-z][a-z0-9_]{0,31}:(?:begin|complete)|` +
	`login/second-factor/[a-z][a-z0-9_]{0,31}:(?:begin|complete)|me/credentials/[a-z][a-z0-9_]{0,31}:(?:enroll-begin|enroll-complete))$`)

// mtlsOAuthPath は、フィーチャー mtls_client_auth が動いているときに mTLS の専用の待ち受けで通す OAuth のエンドポイント
// （RFC 8705 の連携先の認証と、証明書に結び付けたトークンの提示。ADR 0113）。
var mtlsOAuthPath = regexp.MustCompile(`^(?:/realms/[a-z0-9][a-z0-9-]{0,62})?/oauth2/(?:token|introspect|revoke|userinfo|device_authorization|bc-authorize|par)$`)

// withClientCertHeader は、信じたプロキシからの要求のヘッダーの証明書を ctx に載せる。ヘッダーは読んだら消す。
// TLS で受けた要求（mTLS の専用の待ち受け）のヘッダーは読まない。
func withClientCertHeader(h http.Handler, name, format string, proxies []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs := r.Header.Values(name)
		if len(vs) == 0 {
			h.ServeHTTP(w, r)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Del(name)
		if r.TLS == nil && len(vs) == 1 && fromProxy(r.RemoteAddr, proxies) {
			if chain, err := parseCertHeader(vs[0], format); err == nil {
				r = r.WithContext(credential.WithClientCertificates(r.Context(), chain))
			}
		}
		h.ServeHTTP(w, r)
	})
}

func fromProxy(remote string, proxies []netip.Prefix) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	a := ap.Addr().Unmap()
	for _, p := range proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var errCertHeader = errors.New("malformed client certificate header")

// parseCertHeader はプロキシのヘッダーの値を DER の連鎖にする（先頭が本人の証明書）。
//
//	pem：URL エンコードした PEM（1つ以上の CERTIFICATE）。nginx の $ssl_client_escaped_cert、AWS ALB の X-Amzn-Mtls-Clientcert
//	der_base64：DER の Base64 をカンマで区切ったもの。Traefik の X-Forwarded-Tls-Client-Cert
func parseCertHeader(v, format string) ([][]byte, error) {
	var out [][]byte
	add := func(der []byte) error {
		if len(der) == 0 || len(der) > maxClientCertBytes || len(out) >= maxClientCerts {
			return errCertHeader
		}
		out = append(out, der)
		return nil
	}
	switch format {
	case "", "pem":
		s, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, errCertHeader
		}
		rest := []byte(s)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				return nil, errCertHeader
			}
			if err := add(blk.Bytes); err != nil {
				return nil, err
			}
		}
		if strings.TrimSpace(string(rest)) != "" {
			return nil, errCertHeader
		}
	case "der_base64":
		for part := range strings.SplitSeq(v, ",") {
			der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part))
			if err != nil {
				return nil, errCertHeader
			}
			if err := add(der); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errCertHeader
	}
	if len(out) == 0 {
		return nil, errCertHeader
	}
	return out, nil
}

// mtlsHandler は mTLS の専用の待ち受けのハンドラ。認証方式のパス（oauth なら OAuth のエンドポイントも）だけを通し、
// TLS で受け取った証明書を ctx に載せる。
func mtlsHandler(public http.Handler, oauth bool) http.Handler {
	notFound := withCommon(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found")
	}), nil)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || !(mtlsPath.MatchString(r.URL.Path) || oauth && mtlsOAuthPath.MatchString(r.URL.Path)) {
			notFound.ServeHTTP(w, r)
			return
		}
		var chain [][]byte
		for _, c := range r.TLS.PeerCertificates {
			chain = append(chain, c.Raw)
		}
		if len(chain) > maxClientCerts {
			chain = nil // 方式は証明書が無いものとして拒む
		}
		public.ServeHTTP(w, r.WithContext(credential.WithClientCertificates(r.Context(), chain)))
	})
}

// mtlsConfig は mTLS の専用の待ち受けの TLS の設定。証明書は求めるが、TLS では連鎖を確かめない（realm ごとのトラストアンカーで
// 方式が確かめる。証明書を送ったクライアントの CertificateVerify は Go の TLS が必ず確かめる）。
func mtlsConfig(c config.ClientCertificates) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
		// 再ネゴシエーションは使わない（Go のサーバーは受けない）。
	}, nil
}
