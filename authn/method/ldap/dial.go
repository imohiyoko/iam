package ldap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/shared/errs"
)

// ErrUnavailable は、ディレクトリにつながらない・TLS を確かめられない・サービスアカウントで bind できないこと。
// 本人の入力に依らないので、理由（コード）を返してよい。
var ErrUnavailable = errs.WithCode(errs.KindUnavailable, "directory_unavailable", "the directory is unavailable")

const (
	dialTimeout = 5 * time.Second
	opTimeout   = 10 * time.Second
)

// tlsConfig はサーバーの証明書の確かめ方。ホスト名と信頼の起点は必ず確かめ、ピンがあれば確かめた連なりの中に一致を求める。
func tlsConfig(cfg Config, host string) (*tls.Config, error) {
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if cfg.CAPEM != "" {
		pool, err := certPool(cfg.CAPEM)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	if len(cfg.Pins) > 0 {
		pins := make([][]byte, 0, len(cfg.Pins))
		for _, p := range cfg.Pins {
			b, err := base64.StdEncoding.DecodeString(p)
			if err != nil {
				return nil, err
			}
			pins = append(pins, b)
		}
		// VerifyConnection は通常の検証（連なりとホスト名）の後に呼ばれる。
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, chain := range cs.VerifiedChains {
				for _, c := range chain {
					if pinned(c, pins) {
						return nil
					}
				}
			}
			return errors.New("ldap: server certificate does not match the pins")
		}
	}
	return tc, nil
}

func pinned(c *x509.Certificate, pins [][]byte) bool {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	for _, p := range pins {
		if subtle.ConstantTimeCompare(h[:], p) == 1 {
			return true
		}
	}
	return false
}

// publicOnly は、つなぐ先が公開のアドレスでなければ断る（Org の connection の SSRF を防ぐ）。解決の後の実際のアドレスで確かめるので、
// DNS rebinding でも内部につながらない。
func publicOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if !oauth.PublicAddr(ap.Addr()) {
		return fmt.Errorf("ldap: %s is not a public address", ap.Addr())
	}
	return nil
}

// dirConn はディレクトリとの接続。close で閉じる。
type dirConn struct {
	conn *ldap.Conn
	stop func() bool
}

func (s *dirConn) close() {
	s.stop()
	_ = s.conn.Close()
}

// open はディレクトリに TLS でつなぎ、サービスアカウントで bind する。guarded なら公開のアドレスに限る。
// 失敗は ErrUnavailable（理由は包んだ誤りに残す）。
func (s *Service) open(ctx context.Context, cfg Config, guarded bool) (*dirConn, error) {
	sess, err := s.dial(ctx, cfg, guarded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	pw, err := s.Crypter.Open(ctx, passwordPurpose, cfg.BindPassword)
	if err != nil {
		sess.close()
		return nil, err
	}
	if len(pw) == 0 {
		sess.close()
		return nil, fmt.Errorf("%w: empty bind password", ErrUnavailable)
	}
	if err := sess.conn.Bind(cfg.BindDN, string(pw)); err != nil {
		sess.close()
		return nil, fmt.Errorf("%w: service bind: %v", ErrUnavailable, err)
	}
	return sess, nil
}

func (s *Service) dial(ctx context.Context, cfg Config, guarded bool) (*dirConn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	host, port := u.Hostname(), u.Port()
	switch {
	case port != "":
	case u.Scheme == "ldaps":
		port = "636"
	case u.Scheme == "ldap":
		port = "389"
	default:
		return nil, errors.New("unsupported scheme")
	}
	tc, err := tlsConfig(cfg, host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: dialTimeout}
	if guarded {
		d.Control = publicOnly
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	raw, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	var conn *ldap.Conn
	if u.Scheme == "ldaps" {
		tlsConn := tls.Client(raw, tc)
		if err := tlsConn.HandshakeContext(dctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		conn = ldap.NewConn(tlsConn, true)
		conn.Start()
	} else {
		conn = ldap.NewConn(raw, false)
		conn.Start()
		conn.SetTimeout(opTimeout)
		// 平文のまま何も送らない：StartTLS に失敗すれば切る。
		if err := conn.StartTLS(tc); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	conn.SetTimeout(opTimeout)
	// 要求の取り消し（ctx）で接続を閉じ、止まっている操作を終わらせる。
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return &dirConn{conn: conn, stop: stop}, nil
}
