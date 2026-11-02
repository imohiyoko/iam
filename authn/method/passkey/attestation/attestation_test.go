package attestation_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/authn/method/passkey/passkeytest"
	"github.com/imohiyoko/iam/shared/clock"
)

var (
	yubi    = uuid.MustParse("cb69481e-8ff7-4039-93ec-0a2729a154a8")
	other   = uuid.MustParse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
	revoked = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	unknown = uuid.MustParse("99999999-2222-3333-4444-555555555555")
	now     = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
)

func newMetadata(t *testing.T, root *passkeytest.CA, trusted ...attestation.Trusted) *attestation.Metadata {
	t.Helper()
	return attestation.New(attestation.Config{Root: root.DER, Trusted: trusted, Clock: clock.NewFake(now)})
}

func TestLoad(t *testing.T) {
	mds, vendor := passkeytest.NewCA("MDS Root"), passkeytest.NewCA("Vendor Root")
	m := newMetadata(t, mds)
	if _, _, _, ok := m.Status(); ok {
		t.Fatal("status before load: want not ok")
	}
	if err := m.Load(mds.MDSBlob(5, "2026-12-01", passkeytest.MDSEntry(yubi.String(), "YubiKey 5", [][]byte{vendor.DER}, "FIDO_CERTIFIED_L2"))); err != nil {
		t.Fatal(err)
	}
	if n, next, entries, ok := m.Status(); !ok || n != 5 || entries != 1 || next.Format(time.DateOnly) != "2026-12-01" {
		t.Fatalf("Status = %d %v %d %v", n, next, entries, ok)
	}
	if got := m.Name(yubi[:]); got != "YubiKey 5" {
		t.Fatalf("Name = %q", got)
	}
	// 別のルートで署名した BLOB は受けない。
	if err := m.Load(passkeytest.NewCA("Other Root").MDSBlob(6, "2026-12-01")); err == nil {
		t.Fatal("blob signed by another root: want error")
	}
	// 署名を変えた BLOB は受けない。
	blob := mds.MDSBlob(7, "2026-12-01")
	blob[len(blob)-5] ^= 1
	if err := m.Load(blob); err == nil {
		t.Fatal("tampered blob: want error")
	}
	// 番号が戻った BLOB は受けない（巻き戻しの拒否）。同じ番号なら何もしない。
	if err := m.Load(mds.MDSBlob(4, "2026-12-01")); !errors.Is(err, attestation.ErrStale) {
		t.Fatalf("older blob = %v, want ErrStale", err)
	}
	if err := m.Load(mds.MDSBlob(5, "2026-12-01")); err != nil {
		t.Fatalf("same number: %v", err)
	}
	if got := m.Name(yubi[:]); got != "YubiKey 5" {
		t.Fatalf("Name after same number = %q", got)
	}
	if err := m.Load(mds.MDSBlob(6, "2027-01-01")); err != nil {
		t.Fatal(err)
	}
	if got := m.Name(yubi[:]); got != "" {
		t.Fatalf("Name after newer blob without the entry = %q", got)
	}
	if err := m.Load([]byte("not a jwt")); err == nil {
		t.Fatal("garbage: want error")
	}
}

func TestNormalize(t *testing.T) {
	p, err := attestation.Normalize(&attestation.Policy{AllowedAAGUIDs: []string{" CB69481E-8FF7-4039-93EC-0A2729A154A8", yubi.String()},
		MinCertificationLevel: "L2"})
	if err != nil || len(p.AllowedAAGUIDs) != 1 || p.AllowedAAGUIDs[0] != yubi.String() {
		t.Fatalf("Normalize = %+v, %v", p, err)
	}
	if p, err := attestation.Normalize(&attestation.Policy{}); p != nil || err != nil {
		t.Fatalf("empty = %+v, %v", p, err)
	}
	for _, bad := range []attestation.Policy{
		{AllowedAAGUIDs: []string{"not-a-uuid"}},
		{DeniedAAGUIDs: []string{"{cb69481e-8ff7-4039-93ec-0a2729a154a8}"}},
		{MinCertificationLevel: "L4"},
		{DeniedAAGUIDs: make([]string, attestation.MaxPolicyAAGUIDs+1)},
	} {
		if _, err := attestation.Normalize(&bad); err == nil {
			t.Errorf("Normalize(%+v): want error", bad)
		}
	}
}

func TestEvaluate(t *testing.T) {
	mds := passkeytest.NewCA("MDS Root")
	m := newMetadata(t, mds)
	if err := m.Load(mds.MDSBlob(1, "2026-12-01",
		passkeytest.MDSEntry(yubi.String(), "YubiKey 5", nil, "FIDO_CERTIFIED_L1", "FIDO_CERTIFIED_L2"),
		passkeytest.MDSEntry(other.String(), "Other", nil, "FIDO_CERTIFIED_L1"),
		passkeytest.MDSEntry(revoked.String(), "Revoked", nil, "FIDO_CERTIFIED_L1", "REVOKED"),
	)); err != nil {
		t.Fatal(err)
	}
	attested := attestation.Authenticator{AAGUID: yubi[:], Format: "packed", Attested: true}
	legacy := attestation.Authenticator{AAGUID: yubi[:]} // フィーチャーの前に登録した行
	tier := func(p attestation.Policy) attestation.Tiered { return attestation.Tiered{Tier: "realm", Policy: &p} }
	for _, tc := range []struct {
		name     string
		a        attestation.Authenticator
		policies []attestation.Tiered
		reason   string
	}{
		{"no policy", legacy, nil, ""},
		{"revoked status denies without policy", attestation.Authenticator{AAGUID: revoked[:]}, nil, attestation.ReasonStatus},
		{"require attestation", legacy, []attestation.Tiered{tier(attestation.Policy{RequireAttestation: true})}, attestation.ReasonAttestationRequired},
		{"require attestation ok", attested, []attestation.Tiered{tier(attestation.Policy{RequireAttestation: true})}, ""},
		{"allowlist", attested, []attestation.Tiered{tier(attestation.Policy{AllowedAAGUIDs: []string{other.String()}})}, attestation.ReasonNotAllowed},
		{"allowlist ok", attested, []attestation.Tiered{tier(attestation.Policy{AllowedAAGUIDs: []string{yubi.String()}})}, ""},
		{"allowlist without aaguid", attestation.Authenticator{}, []attestation.Tiered{tier(attestation.Policy{AllowedAAGUIDs: []string{yubi.String()}})}, attestation.ReasonNotAllowed},
		{"denylist", attested, []attestation.Tiered{tier(attestation.Policy{DeniedAAGUIDs: []string{yubi.String()}})}, attestation.ReasonDenied},
		{"level ok", attested, []attestation.Tiered{tier(attestation.Policy{MinCertificationLevel: "L2"})}, ""},
		{"level too low", attestation.Authenticator{AAGUID: other[:]}, []attestation.Tiered{tier(attestation.Policy{MinCertificationLevel: "L1plus"})}, attestation.ReasonCertification},
		{"level unknown", attestation.Authenticator{AAGUID: unknown[:]}, []attestation.Tiered{tier(attestation.Policy{MinCertificationLevel: "L1"})}, attestation.ReasonCertification},
		{"second tier", attested, []attestation.Tiered{tier(attestation.Policy{}), {Tier: "org", Policy: &attestation.Policy{DeniedAAGUIDs: []string{yubi.String()}}}}, attestation.ReasonDenied},
	} {
		d := m.Evaluate(now, tc.a, tc.policies...)
		if d.Allowed != (tc.reason == "") || d.Reason != tc.reason {
			t.Errorf("%s: Evaluate = %+v, want reason %q", tc.name, d, tc.reason)
		}
	}
	d := m.Evaluate(now, attested)
	if d.Name != "YubiKey 5" || d.Level != "L2" || d.AAGUID != yubi.String() {
		t.Fatalf("decision = %+v", d)
	}
	if a := d.Audit(); a["aaguid"] != yubi.String() || a["decision"] != "allowed" || a["authenticator_name"] != "YubiKey 5" {
		t.Fatalf("Audit = %v", a)
	}
	d = m.Evaluate(now, attested, attestation.Tiered{Tier: "org", Policy: &attestation.Policy{DeniedAAGUIDs: []string{yubi.String()}}})
	if a := d.Audit(); a["decision"] != "denied" || a["reason"] != attestation.ReasonDenied || a["tier"] != "org" {
		t.Fatalf("Audit = %v", a)
	}
	// メタデータが無くてもポリシーで判定する。
	var none *attestation.Metadata
	if d := none.Evaluate(now, legacy, tier(attestation.Policy{RequireAttestation: true})); d.Allowed {
		t.Fatalf("nil metadata: %+v", d)
	}
}

// register は擬似の認証器で登録の応答を作り、ライブラリの形式ごとの検証（署名）を済ませた attestation を返す。
func register(t *testing.T, a *passkeytest.Authenticator) *protocol.AttestationObject {
	t.Helper()
	challenge := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	opts, _ := json.Marshal(map[string]any{"publicKey": map[string]any{"challenge": challenge, "rp": map[string]any{"id": "example.com"},
		"user": map[string]any{"id": base64.RawURLEncoding.EncodeToString([]byte("user"))}}})
	resp, err := a.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(parsed.Raw.AttestationResponse.ClientDataJSON)
	obj := &parsed.Response.AttestationObject
	if err := obj.VerifyAttestation(h[:], nil, protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestVerify(t *testing.T) {
	mds, vendor, corp, rogue := passkeytest.NewCA("MDS Root"), passkeytest.NewCA("Vendor Root"), passkeytest.NewCA("Corp Root"), passkeytest.NewCA("Rogue")
	corpKey := uuid.MustParse("0d9b2e56-566b-c393-2940-f821b7f15d6d")
	m := newMetadata(t, mds, attestation.Trusted{AAGUID: corpKey, Name: "社内のキー", Roots: []*x509.Certificate{corp.Cert}})
	if err := m.Load(mds.MDSBlob(1, "2026-12-01", passkeytest.MDSEntry(yubi.String(), "YubiKey 5", [][]byte{vendor.DER}, "FIDO_CERTIFIED_L2"))); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	auth := func(aaguid uuid.UUID, ca *passkeytest.CA) *passkeytest.Authenticator {
		a := passkeytest.New("https://example.com")
		a.AAGUID = aaguid[:]
		if ca != nil {
			a.Attestation = ca.PackedAttestation(aaguid[:])
		}
		return a
	}
	for _, tc := range []struct {
		name     string
		a        *passkeytest.Authenticator
		format   string
		attested bool
	}{
		{"none", auth(yubi, nil), "none", false},
		{"chain to MDS root", auth(yubi, vendor), "packed", true},
		{"chain to another root", auth(yubi, rogue), "packed", false},
		{"not in MDS", auth(other, vendor), "packed", false},
		{"configured trust", auth(corpKey, corp), "packed", true},
		{"configured trust, wrong root", auth(corpKey, vendor), "packed", false},
	} {
		r := m.Verify(ctx, register(t, tc.a))
		if r.Format != tc.format || r.Attested != tc.attested {
			t.Errorf("%s: Verify = %+v", tc.name, r)
		}
	}
	if got := m.Name(corpKey[:]); got != "社内のキー" {
		t.Fatalf("Name(configured) = %q", got)
	}
}
