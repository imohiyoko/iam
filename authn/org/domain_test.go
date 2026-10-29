package org

import (
	"errors"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":           "example.com",
		" sub.example.com. ":    "sub.example.com",
		"xn--r8jz45g.jp":        "xn--r8jz45g.jp",
		"a-b.example":           "a-b.example",
		"1.example":             "1.example",
		"example.xn--zckzah":    "example.xn--zckzah",
		"a.b.c.d.e.example.org": "a.b.c.d.e.example.org",
	} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "com", "example..com", "-a.com", "a-.com", "a_b.com", "10.0.0.1", "例え.jp", "a.com/x",
		"*.example.com", string(make([]byte, 254))} {
		if got, err := NormalizeDomain(in); !errors.Is(err, ErrDomainInvalid) {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want invalid", in, got, err)
		}
	}
}
