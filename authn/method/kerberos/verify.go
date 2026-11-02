package kerberos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/imohiyoko/iam/shared/port"
)

// SPNEGO（RFC 4178）と Kerberos の AP-REQ（RFC 4120、4121）の確かめ。gokrb5 の SPNEGO の受け手（AcceptSecContext）は使わず、
// トークンの解析と AP-REQ の検証（service.VerifyAPREQ）だけを使う。受け手は、空の MechTypes で panic し、KRB-ERROR のトークンを
// 「成功」として返すため。解析は自分の薄い層で、AP-REQ だけを受け付ける（ファジングの対象。fuzz_test.go）。

var (
	errNoAPReq = errors.New("token is not a Kerberos AP-REQ")
	oidKRB5    = gssapi.OIDKRB5.OID()
	oidMSKRB5  = gssapi.OIDMSLegacyKRB5.OID()
)

// parseAPReq は SPNEGO の NegTokenInit（Kerberos の楽観的なトークン付き）か、SPNEGO で包まない GSS-API の Kerberos のトークン
// （RFC 4121 4.1）から AP-REQ を取り出す。それ以外（NTLM、NegTokenResp、AP-REP、KRB-ERROR）は拒む。
func parseAPReq(tok []byte) (ap messages.APReq, err error) {
	defer func() {
		// 解析は信頼できない入力に対する外部のコード。panic は拒否にする（fail-closed）。
		if r := recover(); r != nil {
			ap, err = messages.APReq{}, fmt.Errorf("%w: malformed token", errNoAPReq)
		}
	}()
	if len(tok) == 0 || len(tok) > maxToken {
		return messages.APReq{}, fmt.Errorf("%w: empty or too large", errNoAPReq)
	}
	mech := tok
	var st spnego.SPNEGOToken
	if err := st.Unmarshal(tok); err == nil {
		if !st.Init || st.Resp {
			return messages.APReq{}, fmt.Errorf("%w: not a NegTokenInit", errNoAPReq)
		}
		// 楽観的なトークンは MechTypes の先頭の方式のもの（RFC 4178 4.2.1）。先頭が Kerberos のときだけ受け付ける。
		mt := st.NegTokenInit.MechTypes
		if len(mt) == 0 || !(mt[0].Equal(oidKRB5) || mt[0].Equal(oidMSKRB5)) {
			return messages.APReq{}, fmt.Errorf("%w: first mechanism is not Kerberos", errNoAPReq)
		}
		mech = st.NegTokenInit.MechTokenBytes
		if len(mech) == 0 {
			return messages.APReq{}, fmt.Errorf("%w: no mechanism token", errNoAPReq)
		}
	}
	var kt spnego.KRB5Token
	if err := kt.Unmarshal(mech); err != nil {
		return messages.APReq{}, fmt.Errorf("%w: %v", errNoAPReq, err)
	}
	if !kt.IsAPReq() || !kt.OID.Equal(oidKRB5) {
		return messages.APReq{}, fmt.Errorf("%w: not an AP-REQ", errNoAPReq)
	}
	return kt.APReq, nil
}

// principal は確かめた本人。
type principal struct {
	// Name は名前（1 つの要素）、Realm は Kerberos の realm。
	Name, Realm string
}

func (p principal) String() string { return p.Name + "@" + p.Realm }

// verify は AP-REQ を確かめ、本人を返す。暗号の種類・宛先・期限・認証子・時刻のずれ・再送（プロセスの中と、EphemeralStore で
// インスタンスをまたいで）・本人の realm と名前の形を確かめる。時刻は gokrb5 がシステムの時計で確かめる（Kerberos は時計に頼る）。
func (m *Method) verify(ctx context.Context, env port.MethodEnv) (principal, error) {
	if env.Negotiate == nil {
		return principal{}, port.ErrNegotiate
	}
	ap, err := parseAPReq(env.Negotiate)
	if err != nil {
		return principal{}, rejected(err.Error())
	}
	t := &ap.Ticket
	if !slices.Contains(m.p.etypes, t.EncPart.EType) {
		return principal{}, rejected(fmt.Sprintf("ticket encryption type %d is not allowed", t.EncPart.EType))
	}
	if t.Realm != m.p.srealm || !slices.Equal(t.SName.NameString, m.p.sname.NameString) {
		return principal{}, rejected("ticket is for another service")
	}
	opts := []func(*service.Settings){service.MaxClockSkew(m.p.skew), service.DecodePAC(false)}
	// アドレスに結び付いたチケットは、接続元が合うときだけ通す（gokrb5 が確かめる）。
	if ip := net.ParseIP(env.ClientIP); ip != nil {
		opts = append(opts, service.ClientAddress(types.HostAddressFromNetIP(ip)))
	}
	ok, err := verifyAPReq(&ap, service.NewSettings(m.p.kt, opts...))
	if err != nil || !ok {
		return principal{}, rejected(fmt.Sprintf("AP-REQ: %v", err))
	}
	enc := &t.DecryptedEncPart
	if !slices.Contains(m.p.etypes, enc.Key.KeyType) {
		return principal{}, rejected(fmt.Sprintf("session key type %d is not allowed", enc.Key.KeyType))
	}
	if types.IsFlagSet(&enc.Flags, flags.Invalid) {
		return principal{}, rejected("ticket is invalid")
	}
	p, err := m.principalOf(ap.Authenticator.CName, ap.Authenticator.CRealm)
	if err != nil {
		return principal{}, rejected(err.Error())
	}
	if err := m.replayed(ctx, ap); err != nil {
		return principal{}, err
	}
	return p, nil
}

// verifyAPReq は gokrb5 の検証を呼ぶ。panic は拒否にする。
func verifyAPReq(ap *messages.APReq, s *service.Settings) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok, err = false, errors.New("malformed AP-REQ")
		}
	}()
	ok, _, err = service.VerifyAPREQ(ap, s)
	return ok, err
}

// principalOf は本人の名前を確かめる。受け付ける realm の、1 つの要素の名前（サービスのプリンシパル `a/b` や、企業の名前
// `a@b` を拒む）だけ。AD の名前は空白を含みうるので、空白は前後のものだけを拒む。
func (m *Method) principalOf(cname types.PrincipalName, crealm string) (principal, error) {
	if !slices.Contains(m.p.realms, crealm) {
		return principal{}, fmt.Errorf("realm %q is not accepted", crealm)
	}
	if len(cname.NameString) != 1 {
		return principal{}, errors.New("principal must have a single component")
	}
	name := cname.NameString[0]
	if !validName(name) {
		return principal{}, errors.New("invalid principal name")
	}
	if m.p.foldCase {
		name = strings.ToLower(name)
	}
	return principal{Name: name, Realm: crealm}, nil
}

func validName(n string) bool {
	return n != "" && len(n) <= maxNameLen && utf8.ValidString(n) && !strings.ContainsAny(n, "@/\\") && strings.TrimSpace(n) == n &&
		!strings.ContainsFunc(n, func(r rune) bool { return unicode.IsControl(r) || r == utf8.RuneError })
}

// replayed は、同じ認証子（本人・時刻）が別のインスタンスで使われていないかを EphemeralStore で確かめる（RFC 4120 3.2.3。
// プロセスの中の再送は gokrb5 の再送のキャッシュも拒む）。キーは時刻のずれの 2 倍で消える。
func (m *Method) replayed(ctx context.Context, ap messages.APReq) error {
	if m.eph == nil {
		return nil
	}
	a := ap.Authenticator
	var b bytes.Buffer
	for _, s := range []string{ap.Ticket.Realm, strings.Join(ap.Ticket.SName.NameString, "/"), a.CRealm, strings.Join(a.CName.NameString, "/")} {
		_ = binary.Write(&b, binary.BigEndian, int64(len(s)))
		b.WriteString(s)
	}
	_ = binary.Write(&b, binary.BigEndian, a.CTime.UnixNano())
	_ = binary.Write(&b, binary.BigEndian, int64(a.Cusec))
	h := sha256.Sum256(b.Bytes())
	n, err := m.eph.Incr(ctx, "replay:"+base64.RawURLEncoding.EncodeToString(h[:]), 2*m.p.skew)
	if err != nil {
		return err
	}
	if n > 1 {
		return rejected("replayed authenticator")
	}
	return nil
}
