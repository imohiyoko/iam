package provider_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/internal/testkit"
)

func challengeOf(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestFlowRequestAndCode(t *testing.T) {
	k := testkit.New(t)
	f := &provider.Flow{Cache: k.Cache, Crypter: k.Crypter, Clock: k.Clock}
	ctx := context.Background()
	verifier := strings.Repeat("v", 43)
	req := provider.AuthRequest{RealmID: k.RealmID, ClientID: "cli_a", RedirectURI: "https://a.example.com/cb", Scopes: []string{"openid"},
		State: "s", Nonce: "n", CodeChallenge: challengeOf(verifier)}

	rid, err := f.Hold(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.Resume(ctx, k.RealmID, rid)
	if err != nil || got.ClientID != "cli_a" || got.Nonce != "n" {
		t.Fatalf("resume = %+v, %v", got, err)
	}
	// 何度でも読める（ログインのやり直し）。別の realm・知らない ID・消した後は読めない。
	if _, err := f.Resume(ctx, k.RealmID, rid); err != nil {
		t.Fatal(err)
	}
	for name, try := range map[string]func() error{
		"other realm": func() error { _, err := f.Resume(ctx, "rlm_other", rid); return err },
		"unknown":     func() error { _, err := f.Resume(ctx, k.RealmID, "nope"); return err },
		"empty":       func() error { _, err := f.Resume(ctx, k.RealmID, ""); return err },
	} {
		if err := try(); !errors.Is(err, provider.ErrRequestExpired) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := f.Drop(ctx, rid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Resume(ctx, k.RealmID, rid); !errors.Is(err, provider.ErrRequestExpired) {
		t.Fatalf("after drop: %v", err)
	}
	rid, _ = f.Hold(ctx, req)
	k.Clock.Advance(provider.DefaultRequestTTL + time.Second)
	if _, err := f.Resume(ctx, k.RealmID, rid); !errors.Is(err, provider.ErrRequestExpired) {
		t.Fatalf("expired request: %v", err)
	}

	issue := func() string {
		code, err := f.IssueCode(ctx, provider.Code{AuthRequest: req, UserID: "usr_1", SID: "ses_1", AuthTime: k.Clock.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	code := issue()
	c, err := f.Redeem(ctx, k.RealmID, "cli_a", code, req.RedirectURI, verifier)
	if err != nil || c.UserID != "usr_1" || c.SID != "ses_1" || c.Nonce != "n" {
		t.Fatalf("redeem = %+v, %v", c, err)
	}
	if _, err := f.Redeem(ctx, k.RealmID, "cli_a", code, req.RedirectURI, verifier); !errors.Is(err, provider.ErrInvalidGrant) {
		t.Fatalf("reuse: %v", err)
	}
	// 取り違えは拒み、そのコードはもう使えない。
	for name, try := range map[string]func(code string) error{
		"client": func(code string) error {
			_, err := f.Redeem(ctx, k.RealmID, "cli_b", code, req.RedirectURI, verifier)
			return err
		},
		"redirect": func(code string) error {
			_, err := f.Redeem(ctx, k.RealmID, "cli_a", code, "https://a.example.com/x", verifier)
			return err
		},
		"verifier": func(code string) error {
			_, err := f.Redeem(ctx, k.RealmID, "cli_a", code, req.RedirectURI, strings.Repeat("w", 43))
			return err
		},
		"realm": func(code string) error {
			_, err := f.Redeem(ctx, "rlm_other", "cli_a", code, req.RedirectURI, verifier)
			return err
		},
	} {
		code := issue()
		if err := try(code); !errors.Is(err, provider.ErrInvalidGrant) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := f.Redeem(ctx, k.RealmID, "cli_a", code, req.RedirectURI, verifier); !errors.Is(err, provider.ErrInvalidGrant) {
			t.Fatalf("%s: code usable after failure: %v", name, err)
		}
	}
	code = issue()
	k.Clock.Advance(provider.DefaultCodeTTL + time.Second)
	if _, err := f.Redeem(ctx, k.RealmID, "cli_a", code, req.RedirectURI, verifier); !errors.Is(err, provider.ErrInvalidGrant) {
		t.Fatalf("expired code: %v", err)
	}
}

func TestPKCEAndFreshness(t *testing.T) {
	v := strings.Repeat("a", 43)
	if !provider.VerifyPKCE(challengeOf(v), v) || provider.VerifyPKCE(challengeOf(v), v+"b") || provider.VerifyPKCE(v, v) {
		t.Fatal("VerifyPKCE")
	}
	for _, bad := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+", ""} {
		if provider.ValidPKCEValue(bad) {
			t.Fatalf("ValidPKCEValue(%q)", bad)
		}
	}
	now := testkit.T0
	maxAge := uint(60)
	r := provider.AuthRequest{MaxAge: &maxAge}
	if !r.Fresh(now.Add(-time.Minute), now) || r.Fresh(now.Add(-time.Minute-time.Second), now) {
		t.Fatal("max_age")
	}
	r = provider.AuthRequest{LoginAfter: &now}
	if r.Fresh(now.Add(-time.Second), now.Add(time.Minute)) || !r.Fresh(now, now.Add(time.Minute)) {
		t.Fatal("prompt=login")
	}
	if !(provider.AuthRequest{}).Fresh(now.Add(-24*time.Hour), now) {
		t.Fatal("no constraint")
	}
}
