package provider

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"

	"github.com/imohiyoko/iam/shared/port"
)

func TestMatchTLSAuth(t *testing.T) {
	u, _ := url.Parse("spiffe://example.com/svc")
	c := &x509.Certificate{Subject: pkix.Name{CommonName: "svc", Organization: []string{"Example"}}, DNSNames: []string{"Svc.Example.com"},
		URIs: []*url.URL{u}, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}, EmailAddresses: []string{"svc@example.com"}}
	for _, tc := range []struct {
		field, value string
		want         bool
	}{
		{port.TLSAuthSubjectDN, "CN=svc,O=Example", true},
		{port.TLSAuthSubjectDN, "CN=svc", false},
		{port.TLSAuthSANDNS, "svc.example.com", true},
		{port.TLSAuthSANDNS, "other.example.com", false},
		{port.TLSAuthSANURI, "spiffe://example.com/svc", true},
		{port.TLSAuthSANURI, "spiffe://example.com/other", false},
		{port.TLSAuthSANIP, "192.0.2.1", true},
		{port.TLSAuthSANIP, "::ffff:192.0.2.1", true},
		{port.TLSAuthSANIP, "192.0.2.2", false},
		{port.TLSAuthSANIP, "not-an-ip", false},
		{port.TLSAuthSANEmail, "SVC@example.com", true},
		{"unknown", "svc", false},
		{port.TLSAuthSANDNS, "", false},
	} {
		if got := MatchTLSAuth(c, tc.field, tc.value); got != tc.want {
			t.Errorf("MatchTLSAuth(%s, %q) = %v", tc.field, tc.value, got)
		}
	}
	if validTLSAuth(port.TLSAuthSANIP, "x") || validTLSAuth("unknown", "x") || validTLSAuth(port.TLSAuthSANDNS, " a") || !validTLSAuth(port.TLSAuthSANDNS, "a") {
		t.Fatal("validTLSAuth")
	}
}

func TestBindingSatisfies(t *testing.T) {
	b := Binding{JKT: "k", X5T: "c"}
	if !b.Satisfies(Binding{JKT: "k", X5T: "c"}) || b.Satisfies(Binding{JKT: "k"}) || b.Satisfies(Binding{X5T: "c"}) || !(Binding{}).Satisfies(Binding{JKT: "x"}) {
		t.Fatal("Satisfies")
	}
	if refreshBinding(port.Client{AuthMethod: port.ClientAuthSecret}, b).Bound() || !refreshBinding(port.Client{AuthMethod: port.ClientAuthNone}, b).Bound() {
		t.Fatal("refreshBinding")
	}
}
