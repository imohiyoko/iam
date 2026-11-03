package x509

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/imohiyoko/iam/authn/oauth"
)

// 失効の確認（OCSP（RFC 6960）と CRL（RFC 5280））。ネットワークを使うので、コアは Storage のトランザクションの外
// （Complete・EnrollBegin。ADR 0101）で呼ぶ。結果は応答の nextUpdate か cache_max の早い方まで持つ。

// errRevoked は失効している。fail_open でも拒む。
var errRevoked = errors.New("certificate revoked")

// errUnknown は失効が分からない（応答が無い・古い・読めない・署名が合わない）。fail_open なら通す。
var errUnknown = errors.New("revocation status unavailable")

// clockSkew は応答の thisUpdate・nextUpdate に許す時刻のずれ。
const clockSkew = 5 * time.Minute

// maxOCSPBytes は OCSP の応答の大きさの上限。
const maxOCSPBytes = 64 << 10

// maxCacheEntries は持つ結果の数の上限。超えたら期限切れを捨て、それでも多ければ全部捨てる。
const maxCacheEntries = 10000

type ocspEntry struct {
	status  int
	expires time.Time
}

type crlEntry struct {
	list    *x509.RevocationList
	expires time.Time
}

// revoker は失効の確認と、その結果のキャッシュ。realm の方式ごとに1つ（複数の要求から同時に使う）。
type revoker struct {
	p      revocationPolicy
	client *http.Client
	// certClient は証明書の AIA・CRL 配布点が指す URL に使う。既定では公開のアドレスにだけつなぐ。
	certClient *http.Client

	mu   sync.Mutex
	ocsp map[string]ocspEntry
	crl  map[string]crlEntry
}

func newRevoker(p revocationPolicy, client *http.Client) *revoker {
	certClient := client
	if client == nil {
		client = &http.Client{}
		certClient = client
		if !p.allowPrivate {
			certClient = publicOnlyClient(p.timeout)
		}
	}
	return &revoker{p: p, client: noRedirect(client, p.timeout), certClient: noRedirect(certClient, p.timeout),
		ocsp: map[string]ocspEntry{}, crl: map[string]crlEntry{}}
}

// noRedirect は client の写しに打ち切りを付け、リダイレクトを追わない（証明書が指す先から別の場所へ連れて行かれない）。
func noRedirect(client *http.Client, timeout time.Duration) *http.Client {
	c := *client
	c.Timeout = timeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

var errNotPublic = errors.New("not a public address")

// publicOnlyClient は、名前の解決の後に実際につなぐアドレスが公開のアドレスでなければ断るクライアント
// （解決とつなぐ間に向き先を変えられても通らない）。プロキシは使わない。
func publicOnlyClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errNotPublic
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !oauth.PublicAddr(a) {
			return fmt.Errorf("%w: %s", errNotPublic, host)
		}
		return nil
	}}
	t := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: t}
}

// checkChain は連鎖（先頭が本人、末尾がトラストアンカー）の失効を確かめる。トラストアンカーは確かめない。
func (r *revoker) checkChain(ctx context.Context, chain []*x509.Certificate, now time.Time) error {
	if r.p.mode == RevocationNone {
		return nil
	}
	n := len(chain) - 1
	if r.p.leafOnly {
		n = min(n, 1)
	}
	for i := 0; i < n; i++ {
		err := r.check(ctx, chain[i], chain[i+1], now)
		if errors.Is(err, errUnknown) && r.p.failOpen {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// check は1つの証明書の失効を確かめる。ocsp_crl では、OCSP で分からなければ CRL を見る。
func (r *revoker) check(ctx context.Context, cert, issuer *x509.Certificate, now time.Time) error {
	var ocspErr error
	if r.p.mode == RevocationOCSP || r.p.mode == RevocationOCSPCRL {
		ocspErr = r.checkOCSP(ctx, cert, issuer, now)
		if !errors.Is(ocspErr, errUnknown) || r.p.mode == RevocationOCSP {
			return ocspErr
		}
	}
	err := r.checkCRL(ctx, cert, issuer, now)
	if errors.Is(err, errUnknown) && ocspErr != nil {
		return fmt.Errorf("%w (%v; %v)", errUnknown, ocspErr, err)
	}
	return err
}

func certKey(cert, issuer *x509.Certificate) string {
	h := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:]) + ":" + cert.SerialNumber.Text(16)
}

func (r *revoker) cacheOCSP(key string, e ocspEntry, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ocsp) >= maxCacheEntries {
		for k, v := range r.ocsp {
			if !now.Before(v.expires) {
				delete(r.ocsp, k)
			}
		}
		if len(r.ocsp) >= maxCacheEntries {
			clear(r.ocsp)
		}
	}
	r.ocsp[key] = e
}

// expiry は応答を持つ期限（nextUpdate と cache_max の早い方）。
func (r *revoker) expiry(next, now time.Time) time.Time {
	exp := now.Add(r.p.cacheMax)
	if !next.IsZero() && next.Before(exp) {
		exp = next
	}
	return exp
}

func (r *revoker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate, now time.Time) error {
	key := certKey(cert, issuer)
	r.mu.Lock()
	e, ok := r.ocsp[key]
	r.mu.Unlock()
	if ok && now.Before(e.expires) {
		return ocspResult(e.status)
	}
	urls := cert.OCSPServer
	if r.p.ocspURL != "" {
		urls = []string{r.p.ocspURL}
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", errUnknown, err)
	}
	last := errors.New("no OCSP responder")
	for _, u := range urls {
		if !validURL(u) {
			continue
		}
		body, err := r.fetch(ctx, http.MethodPost, u, req, maxOCSPBytes)
		if err != nil {
			last = err
			continue
		}
		// 署名は発行者か、発行者が OCSP の署名を委ねた証明書で確かめる（x/crypto/ocsp）。
		resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
		if err != nil {
			last = err
			continue
		}
		// x/crypto/ocsp は委ねた署名者の拡張鍵用途を確かめないので、ここで確かめる（RFC 6960 4.2.2.2）。同じ CA が発行した
		// 別の証明書の鍵で作った応答（経路を書き換えた攻撃者の Good）を通さない。有効期間は応答を作った時刻で見る。
		if err := ocspSignerAuthorized(resp, issuer); err != nil {
			last = err
			continue
		}
		if resp.ThisUpdate.After(now.Add(clockSkew)) || (!resp.NextUpdate.IsZero() && now.After(resp.NextUpdate.Add(clockSkew))) {
			last = errors.New("stale OCSP response")
			continue
		}
		if resp.SerialNumber == nil || resp.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			last = errors.New("OCSP response for another certificate")
			continue
		}
		if resp.Status != ocsp.Unknown {
			r.cacheOCSP(key, ocspEntry{status: resp.Status, expires: r.expiry(resp.NextUpdate, now)}, now)
		}
		return ocspResult(resp.Status)
	}
	return fmt.Errorf("%w: ocsp: %v", errUnknown, last)
}

// ocspSignerAuthorized は応答の署名者が発行者自身か、発行者が id-kp-OCSPSigning で委ねた有効な証明書かを確かめる。
func ocspSignerAuthorized(resp *ocsp.Response, issuer *x509.Certificate) error {
	rc := resp.Certificate
	if rc == nil || bytes.Equal(rc.Raw, issuer.Raw) {
		return nil
	}
	if !slices.Contains(rc.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return errors.New("OCSP responder not authorized")
	}
	if resp.ProducedAt.Before(rc.NotBefore) || resp.ProducedAt.After(rc.NotAfter) {
		return errors.New("OCSP responder certificate expired")
	}
	return nil
}

func ocspResult(status int) error {
	switch status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		return errRevoked
	}
	return fmt.Errorf("%w: OCSP status unknown", errUnknown)
}

func (r *revoker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate, now time.Time) error {
	urls := append(append([]string{}, r.p.crlURLs...), cert.CRLDistributionPoints...)
	last := errors.New("no CRL distribution point")
	for _, u := range urls {
		if !validURL(u) {
			continue
		}
		rl, err := r.loadCRL(ctx, u, now)
		if err != nil {
			last = err
			continue
		}
		// 別の CA の CRL（設定の crl_urls は複数の CA に共通）は当てはまらないので次を見る。
		if !bytes.Equal(rl.RawIssuer, issuer.RawSubject) || rl.CheckSignatureFrom(issuer) != nil {
			last = errors.New("CRL not issued by the certificate's issuer")
			continue
		}
		if rl.ThisUpdate.After(now.Add(clockSkew)) || rl.NextUpdate.IsZero() || now.After(rl.NextUpdate.Add(clockSkew)) {
			last = errors.New("stale CRL")
			continue
		}
		for _, e := range rl.RevokedCertificateEntries {
			if e.SerialNumber != nil && e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errRevoked
			}
		}
		return nil
	}
	return fmt.Errorf("%w: crl: %v", errUnknown, last)
}

func (r *revoker) loadCRL(ctx context.Context, u string, now time.Time) (*x509.RevocationList, error) {
	r.mu.Lock()
	e, ok := r.crl[u]
	r.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.list, nil
	}
	body, err := r.fetch(ctx, http.MethodGet, u, nil, r.p.maxCRL)
	if err != nil {
		return nil, err
	}
	if blk, _ := pem.Decode(body); blk != nil && blk.Type == "X509 CRL" {
		body = blk.Bytes
	}
	rl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.crl) >= maxCacheEntries {
		clear(r.crl)
	}
	r.crl[u] = crlEntry{list: rl, expires: r.expiry(rl.NextUpdate, now)}
	return rl, nil
}

// fetch は OCSP・CRL を取得する。2xx 以外・上限を超える大きさは失敗にする。
func (r *revoker) fetch(ctx context.Context, method, u string, body []byte, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.p.timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/ocsp-request")
	}
	// 運営者が設定した URL はそのまま、証明書が指す URL は公開のアドレスにだけつなぐ（allow_private_networks でなければ）。
	client := r.certClient
	if u == r.p.ocspURL || slices.Contains(r.p.crlURLs, u) {
		client = r.client
	}
	resp, err := client.Do(req) // #nosec G704 -- 連鎖を確かめた証明書（か運営者の設定）が指す OCSP・CRL の URL
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, u)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response from %s too large", u)
	}
	return b, nil
}
