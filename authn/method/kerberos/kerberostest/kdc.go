// Package kerberostest は Kerberos / SPNEGO の方式（ADR 0107）のテストのための、同じプロセスの KDC の代わり。
package kerberostest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// 同じプロセスの KDC の代わり。KDC が行うのは、サービスの鍵（keytab）でチケットを暗号化して渡すことなので、テストでは
// keytab から直接チケットを作り（messages.NewTicket）、クライアントの代わりに認証子と AP-REQ を組み立てる。方式から見ると、
// 本物の KDC が発行したチケットと区別できない。

// 既定の realm とサービスのプリンシパル。
const (
	Realm     = "CORP.EXAMPLE.COM"
	SPN       = "HTTP/login.example.com"
	servicePW = "service-secret" // #nosec G101 -- テストの keytab の鍵を作るための値
)

// KDC はテストの KDC（サービスの鍵を持つ）。Path は keytab のファイル。
type KDC struct {
	kt   *keytab.Keytab
	Path string
}

// New は Entry ごとの鍵を持つ keytab を作り、ファイルに書く。無ければ SPN@Realm の AES256 の鍵。
func New(t testing.TB, entries ...Entry) *KDC {
	t.Helper()
	if len(entries) == 0 {
		entries = []Entry{{SPN: SPN, Realm: Realm, EType: etypeID.AES256_CTS_HMAC_SHA1_96}}
	}
	kt := keytab.New()
	for _, e := range entries {
		pw := e.Password
		if pw == "" {
			pw = servicePW
		}
		if err := kt.AddEntry(e.SPN, e.Realm, pw, time.Now(), 1, e.EType); err != nil {
			t.Fatal(err)
		}
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "http.keytab")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return &KDC{kt: kt, Path: p}
}

// Entry は keytab の 1 つの鍵（Password から作る。空なら既定の値）。
type Entry struct {
	SPN, Realm, Password string
	EType                int32
}

// Opts はチケットと認証子の作り方。空の値は既定（alice@Realm、SPN、AES256、今から 10 時間）。
type Opts struct {
	CName  []string
	CRealm string
	SPN    string
	SRealm string
	EType  int32
	Start  time.Time
	End    time.Time
	// AuthName と AuthRealm は認証子の本人（既定はチケットと同じ）。
	AuthName  []string
	AuthRealm string
	// AuthTime は認証子の時刻（既定は今）。
	AuthTime time.Time
	// Raw は SPNEGO で包まない GSS-API のトークンにする。
	Raw bool
	// MechTypes は NegTokenInit の MechTypes（既定は MS の Kerberos と Kerberos）。
	MechTypes []asn1.ObjectIdentifier
}

// Token は Negotiate のトークン（SPNEGO の NegTokenInit か、GSS-API の Kerberos のトークン）を作る。
func (k *KDC) Token(t testing.TB, o Opts) []byte {
	t.Helper()
	if o.CName == nil {
		o.CName = []string{"alice"}
	}
	if o.CRealm == "" {
		o.CRealm = Realm
	}
	if o.SPN == "" {
		o.SPN = SPN
	}
	if o.SRealm == "" {
		o.SRealm = Realm
	}
	if o.EType == 0 {
		o.EType = etypeID.AES256_CTS_HMAC_SHA1_96
	}
	now := time.Now().UTC()
	if o.Start.IsZero() {
		o.Start = now.Add(-time.Minute)
	}
	if o.End.IsZero() {
		o.End = now.Add(10 * time.Hour)
	}
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: o.CName}
	sname, _ := types.ParseSPNString(o.SPN)
	sname.NameType = nametype.KRB_NT_SRV_INST
	tkt, key, err := messages.NewTicket(cname, o.CRealm, sname, o.SRealm, types.NewKrbFlags(), k.kt, o.EType, 1, o.Start, o.Start, o.End, o.End)
	if err != nil {
		t.Fatal(err)
	}
	if o.AuthName == nil {
		o.AuthName = o.CName
	}
	if o.AuthRealm == "" {
		o.AuthRealm = o.CRealm
	}
	auth, err := types.NewAuthenticator(o.AuthRealm, types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: o.AuthName})
	if err != nil {
		t.Fatal(err)
	}
	if !o.AuthTime.IsZero() {
		auth.CTime = o.AuthTime
	}
	ap, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		t.Fatal(err)
	}
	apb, err := ap.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mech := KRB5Token(t, gssapi.OIDKRB5.OID(), []byte{0x01, 0x00}, apb)
	if o.Raw {
		return mech
	}
	if o.MechTypes == nil {
		o.MechTypes = []asn1.ObjectIdentifier{gssapi.OIDMSLegacyKRB5.OID(), gssapi.OIDKRB5.OID()}
	}
	return SPNEGOInit(t, o.MechTypes, mech)
}

// KRB5Token は GSS-API の Kerberos のトークン（RFC 4121 4.1：OID、TOK_ID、本体）を作る。
func KRB5Token(t testing.TB, oid asn1.ObjectIdentifier, tokID, body []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, tokID...)
	b = append(b, body...)
	return asn1tools.AddASNAppTag(b, 0)
}

// SPNEGOInit は NegTokenInit の SPNEGO のトークンを作る。
func SPNEGOInit(t testing.TB, mechTypes []asn1.ObjectIdentifier, mech []byte) []byte {
	t.Helper()
	st := spnego.SPNEGOToken{Init: true, NegTokenInit: spnego.NegTokenInit{MechTypes: mechTypes, MechTokenBytes: mech}}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
