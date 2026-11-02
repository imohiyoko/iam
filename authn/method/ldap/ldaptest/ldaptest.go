// Package ldaptest は LDAP のディレクトリのテスト用の偽物（同じプロセスで動く）。テストだけで使う。
//
// LDAPS か StartTLS で待ち受け、simple bind・検索（and・or・not・等しい・存在の絞り込み、ページング）・StartTLS だけを扱う。
// 本物のサーバーと同じく、空のパスワードの bind は認証しない bind（RFC 4513 5.1.2）として通す。
package ldaptest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Entry はディレクトリの項目。属性の名前は大文字と小文字を区別しない。userPassword は bind の照合に使い、検索では返さない。
type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

// Server は偽物のディレクトリ。
type Server struct {
	// URL は ldaps://127.0.0.1:port か ldap://127.0.0.1:port（StartTLS）。
	URL string
	// CAPEM はサーバーの証明書（自己署名。信頼の起点に使う）。Pin はその SPKI の SHA-256（base64）。
	CAPEM string
	Pin   string

	ln  net.Listener
	tls *tls.Config

	mu      sync.Mutex
	entries map[string]Entry // キーは正規化した DN
	// Binds は成功した bind の DN（空の DN と空のパスワードの bind も含む）。
	Binds []string
	// Searches は受けた検索の絞り込み（文字列に戻したもの）。
	Searches []string
	// Plain は TLS の前に受けた bind・検索の数（StartTLS を使わない接続）。
	Plain int
	// Down が立っている間は接続を受けてすぐ閉じる（障害）。
	Down bool
}

// Mode は待ち受けの形。
type Mode int

const (
	LDAPS Mode = iota
	StartTLS
)

// New はサーバーを立てる。テストの終わりに止める。
func New(t testing.TB, mode Mode) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ldap.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	s := &Server{CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Pin: base64.StdEncoding.EncodeToString(pin[:]),
		tls:     &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12},
		entries: map[string]Entry{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if mode == LDAPS {
		s.URL = "ldaps://" + ln.Addr().String()
		ln = tls.NewListener(ln, s.tls)
	} else {
		s.URL = "ldap://" + ln.Addr().String()
	}
	s.ln = ln
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Add は項目を足す（同じ DN なら置き換える）。値は文字列で渡す。
func (s *Server) Add(dn string, attrs map[string][]string) {
	e := Entry{DN: dn, Attrs: map[string][][]byte{}}
	for k, vs := range attrs {
		for _, v := range vs {
			e.Attrs[strings.ToLower(k)] = append(e.Attrs[strings.ToLower(k)], []byte(v))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[norm(dn)] = e
}

// SetRaw は項目の属性の値をバイト列で置き換える（objectGUID など）。
func (s *Server) SetRaw(dn, attr string, vals ...[]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[norm(dn)]
	e.Attrs[strings.ToLower(attr)] = vals
}

// Remove は項目を消す。
func (s *Server) Remove(dn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, norm(dn))
}

// SetDown は障害を起こす・直す。
func (s *Server) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Down = down
}

// Stats は bind と検索の記録の写しを返す。
func (s *Server) Stats() (binds, searches []string, plain int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.Binds), slices.Clone(s.Searches), s.Plain
}

func norm(dn string) string {
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(dn)
	}
	return strings.ToLower(d.String())
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		down := s.Down
		s.mu.Unlock()
		if down {
			_ = c.Close()
			continue
		}
		_, isTLS := c.(*tls.Conn)
		go s.handle(c, isTLS)
	}
}

const (
	appBindRequest     = 0
	appBindResponse    = 1
	appUnbind          = 2
	appSearchRequest   = 3
	appSearchEntry     = 4
	appSearchDone      = 5
	appExtendedRequest = 23
	appExtendedResp    = 24
	oidStartTLS        = "1.3.6.1.4.1.1466.20037"
)

func (s *Server) handle(c net.Conn, isTLS bool) {
	defer func() { _ = c.Close() }()
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		msgID, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		var controls []*ber.Packet
		if len(p.Children) > 2 {
			controls = p.Children[2].Children
		}
		switch op.Tag {
		case appUnbind:
			return
		case appExtendedRequest:
			if len(op.Children) == 0 || op.Children[0].Data.String() != oidStartTLS || isTLS {
				_ = write(c, msgID, result(appExtendedResp, 2, "unsupported"))
				continue
			}
			if write(c, msgID, result(appExtendedResp, 0, "")) != nil {
				return
			}
			tc := tls.Server(c, s.tls)
			if tc.Handshake() != nil {
				return
			}
			c, isTLS = tc, true
		case appBindRequest:
			if !isTLS {
				s.count()
			}
			_ = write(c, msgID, result(appBindResponse, s.bind(op), ""))
		case appSearchRequest:
			if !isTLS {
				s.count()
			}
			if s.search(c, msgID, op, controls) != nil {
				return
			}
		default:
			return
		}
	}
}

func (s *Server) count() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Plain++
}

// bind は結果のコードを返す（0 成功、49 資格情報の誤り）。
func (s *Server) bind(op *ber.Packet) int64 {
	if len(op.Children) < 3 {
		return 2
	}
	dn, pw := op.Children[1].Data.String(), op.Children[2].Data.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if pw == "" {
		// 認証しない bind（RFC 4513 5.1.2）。本物のサーバーの多くは既定で通す。
		s.Binds = append(s.Binds, dn)
		return 0
	}
	e, ok := s.entries[norm(dn)]
	if !ok {
		return 49
	}
	for _, v := range e.Attrs["userpassword"] {
		if bytes.Equal(v, []byte(pw)) {
			s.Binds = append(s.Binds, dn)
			return 0
		}
	}
	return 49
}

func (s *Server) search(c net.Conn, msgID int64, op *ber.Packet, controls []*ber.Packet) error {
	if len(op.Children) < 8 {
		return write(c, msgID, result(appSearchDone, 2, "malformed"))
	}
	base := op.Children[0].Data.String()
	scope, _ := op.Children[1].Value.(int64)
	sizeLimit, _ := op.Children[3].Value.(int64)
	filter := op.Children[6]
	f, _ := ldap.DecompileFilter(filter)
	var wantAttrs []string
	for _, a := range op.Children[7].Children {
		wantAttrs = append(wantAttrs, strings.ToLower(a.Data.String()))
	}
	baseDN, err := ldap.ParseDN(base)
	if err != nil {
		return write(c, msgID, result(appSearchDone, 34, "invalid dn"))
	}
	s.mu.Lock()
	s.Searches = append(s.Searches, f)
	var matched []Entry
	for _, e := range s.entries {
		d, err := ldap.ParseDN(e.DN)
		if err != nil {
			continue
		}
		in := d.EqualFold(baseDN) || (scope == ldap.ScopeWholeSubtree && baseDN.AncestorOfFold(d)) ||
			(scope == ldap.ScopeSingleLevel && len(d.RDNs) == len(baseDN.RDNs)+1 && baseDN.AncestorOfFold(d))
		if scope == ldap.ScopeBaseObject {
			in = d.EqualFold(baseDN)
		}
		if in && match(filter, e) {
			matched = append(matched, e)
		}
	}
	s.mu.Unlock()
	sort.Slice(matched, func(i, j int) bool { return norm(matched[i].DN) < norm(matched[j].DN) })

	// ページング（RFC 2696）。クッキーは次の位置。
	var paging *ber.Packet
	start, size := 0, len(matched)
	for _, ctl := range controls {
		if len(ctl.Children) == 0 || ctl.Children[0].Data.String() != ldap.ControlTypePaging {
			continue
		}
		v := ctl.Children[len(ctl.Children)-1]
		pp, err := ber.DecodePacketErr(v.Data.Bytes())
		if err != nil || len(pp.Children) < 2 {
			return write(c, msgID, result(appSearchDone, 2, "bad paging"))
		}
		n, _ := pp.Children[0].Value.(int64)
		if ck := pp.Children[1].Data.String(); ck != "" {
			if start, err = strconv.Atoi(ck); err != nil || start < 0 {
				return write(c, msgID, result(appSearchDone, 2, "bad cookie"))
			}
		}
		size = int(n)
		paging = ctl
	}
	if start > len(matched) {
		start = len(matched)
	}
	end := min(start+size, len(matched))
	page := matched[start:end]
	code := int64(0)
	if sizeLimit > 0 && int64(len(page)) > sizeLimit {
		page, code = page[:sizeLimit], 4
	}
	for _, e := range page {
		if err := write(c, msgID, entryPacket(e, wantAttrs)); err != nil {
			return err
		}
	}
	done := result(appSearchDone, code, "")
	msg := envelope(msgID, done)
	if paging != nil {
		cookie := ""
		if end < len(matched) {
			cookie = strconv.Itoa(end)
		}
		val := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		val.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(len(matched)), ""))
		val.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, ""))
		ctl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		ctl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ldap.ControlTypePaging, ""))
		ctl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(val.Bytes()), ""))
		ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
		ctls.AppendChild(ctl)
		msg.AppendChild(ctls)
	}
	_, err = c.Write(msg.Bytes())
	return err
}

func entryPacket(e Entry, want []string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchEntry, nil, "")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, ""))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	names := make([]string, 0, len(e.Attrs))
	for k := range e.Attrs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if k == "userpassword" || (len(want) > 0 && !slices.Contains(want, k)) {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, v := range e.Attrs[k] {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), ""))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	p.AppendChild(attrs)
	return p
}

// match は絞り込みを評価する（and・or・not・等しい（大文字と小文字を区別しない）・存在）。
func match(f *ber.Packet, e Entry) bool {
	switch f.Tag {
	case ldap.FilterAnd:
		for _, c := range f.Children {
			if !match(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range f.Children {
			if match(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(f.Children) == 1 && !match(f.Children[0], e)
	case ldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return false
		}
		want := f.Children[1].Data.Bytes()
		for _, v := range e.Attrs[strings.ToLower(f.Children[0].Data.String())] {
			if bytes.EqualFold(v, want) {
				return true
			}
		}
		return false
	case ldap.FilterPresent:
		return len(e.Attrs[strings.ToLower(f.Data.String())]) > 0
	}
	return false
}

func envelope(msgID int64, op *ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, ""))
	p.AppendChild(op)
	return p
}

func result(app ber.Tag, code int64, msg string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, ""))
	return p
}

func write(w io.Writer, msgID int64, op *ber.Packet) error {
	_, err := w.Write(envelope(msgID, op).Bytes())
	return err
}
