package kerberos

import (
	"context"
	"errors"
	"testing"

	kt "github.com/imohiyoko/iam/authn/method/kerberos/kerberostest"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// FuzzVerify は信頼できない Negotiate のトークンの解析と確かめ（SPNEGO・GSS-API・AP-REQ）が、panic せず、鍵を知らない入力を
// 通さないことを確かめる。種には本物の形のトークン（別の鍵で作ったもの）を入れる。
func FuzzVerify(f *testing.F) {
	other := kt.New(f, kt.Entry{SPN: kt.SPN, Realm: kt.Realm, Password: "fuzz", EType: 18})
	for _, o := range []kt.Opts{{}, {Raw: true}, {CName: []string{"host", "x"}}} {
		f.Add(other.Token(f, o))
	}
	f.Add([]byte{0x60, 0x03, 0x06, 0x01, 0x00})
	f.Add([]byte{0xa1, 0x00})
	f.Add([]byte("NTLMSSP\x00\x01\x00\x00\x00"))
	k := kt.New(f)
	m, err := New(RealmConfig{Keytab: k.Path, ServicePrincipal: kt.SPN}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tok []byte) {
		if tok == nil {
			tok = []byte{} // nil はトークンが無いこと（チャレンジ）で、別に確かめる
		}
		if ap, err := parseAPReq(tok); err == nil && len(ap.Ticket.SName.NameString) > 64 {
			t.Logf("large sname: %d", len(ap.Ticket.SName.NameString))
		}
		_, err := m.verify(context.Background(), port.MethodEnv{Usage: port.UsageFirstFactor, Negotiate: tok})
		if err == nil {
			t.Fatal("a token made without the service key was accepted")
		}
		if !errors.Is(err, errs.AuthenticationFailed) {
			t.Fatalf("err = %v, want authentication failed", err)
		}
	})
}
