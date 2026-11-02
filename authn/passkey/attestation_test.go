package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/imohiyoko/iam/authn/passkey"
	"github.com/imohiyoko/iam/authn/passkey/attestation"
	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

var (
	yubiKey  = uuid.MustParse("cb69481e-8ff7-4039-93ec-0a2729a154a8")
	otherKey = uuid.MustParse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
)

// attested はフィーチャー passkey_attestation を動かした env。vendor が yubiKey の attestation のルート（MDS に載せる）。
func attested(t *testing.T, policy *attestation.Policy) (*env, *passkeytest.CA) {
	t.Helper()
	e := setup(t)
	mds, vendor := passkeytest.NewCA("MDS Root"), passkeytest.NewCA("Vendor Root")
	m := attestation.New(attestation.Config{Root: mds.DER, Clock: e.k.Clock})
	if err := m.Load(mds.MDSBlob(1, "2027-01-01", passkeytest.MDSEntry(yubiKey.String(), "YubiKey 5", [][]byte{vendor.DER}, "FIDO_CERTIFIED_L2"))); err != nil {
		t.Fatal(err)
	}
	e.svc.Attestation = &passkey.Attestation{Metadata: m, Conveyance: protocol.PreferDirectAttestation, Policy: policy}
	return e, vendor
}

// lastEvent は種類 typ の最後の監査ログの詳細を返す。
func (e *env) lastEvent(t *testing.T, typ string) map[string]any {
	t.Helper()
	var out map[string]any
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		recs, err := tx.Audit().Scan(ctx, 1, 1000)
		for _, r := range recs {
			var ev struct {
				Type    string         `json:"type"`
				Details map[string]any `json:"details"`
			}
			if json.Unmarshal(r.Payload, &ev) == nil && ev.Type == typ {
				out = ev.Details
			}
		}
		return err
	})
	if out == nil {
		t.Fatalf("no %s event", typ)
	}
	return out
}

func key(aaguid uuid.UUID, ca *passkeytest.CA) *passkeytest.Authenticator {
	a := passkeytest.New(origin)
	a.AAGUID = aaguid[:]
	if ca != nil {
		a.Attestation = ca.PackedAttestation(aaguid[:])
	}
	return a
}

func TestAttestationRegister(t *testing.T) {
	e, vendor := attested(t, &attestation.Policy{RequireAttestation: true, AllowedAAGUIDs: []string{yubiKey.String()}})
	u := e.user(t, "alice@example.com")
	ctx := context.Background()

	st, err := e.svc.BeginRegister(ctx, e.k.RealmID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(st.Options), `"attestation":"direct"`) {
		t.Fatalf("options do not ask for attestation: %s", st.Options)
	}

	// 信頼の起点に連なる attestation で、許可した AAGUID なら登録できる。
	p, err := e.register(t, u, key(yubiKey, vendor))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Attested || p.AttestationFormat != "packed" || attestation.FormatAAGUID(p.AAGUID) != yubiKey.String() {
		t.Fatalf("registered = %+v", p)
	}
	ev := e.lastEvent(t, "passkey.registered")
	if ev["aaguid"] != yubiKey.String() || ev["attested"] != true || ev["decision"] != "allowed" || ev["authenticator_name"] != "YubiKey 5" {
		t.Fatalf("passkey.registered details = %v", ev)
	}

	for _, tc := range []struct {
		name   string
		a      *passkeytest.Authenticator
		reason string
	}{
		{"no attestation", key(yubiKey, nil), attestation.ReasonAttestationRequired},
		{"untrusted chain", key(yubiKey, passkeytest.NewCA("Rogue")), attestation.ReasonAttestationRequired},
		{"not allowed", key(otherKey, nil), attestation.ReasonAttestationRequired},
	} {
		_, err := e.register(t, u, tc.a)
		if !errors.Is(err, passkey.ErrNotAllowed) {
			t.Fatalf("%s: err = %v, want ErrNotAllowed", tc.name, err)
		}
		if code := err.(*errs.Error).Code; code != passkey.CodeNotAllowed {
			t.Fatalf("%s: code = %q", tc.name, code)
		}
		ev := e.lastEvent(t, "passkey.registration_failed")
		if ev["decision"] != "denied" || ev["reason"] != tc.reason || ev["tier"] != "realm" {
			t.Fatalf("%s: passkey.registration_failed details = %v", tc.name, ev)
		}
	}

	// attestation を求めない段では、自己申告の AAGUID で許可の一覧を判定する。
	e.svc.Attestation.Policy = &attestation.Policy{AllowedAAGUIDs: []string{yubiKey.String()}}
	if _, err := e.register(t, u, key(otherKey, nil)); !errors.Is(err, passkey.ErrNotAllowed) {
		t.Fatalf("other aaguid: err = %v", err)
	}
	if ev := e.lastEvent(t, "passkey.registration_failed"); ev["reason"] != attestation.ReasonNotAllowed || ev["aaguid"] != otherKey.String() {
		t.Fatalf("details = %v", ev)
	}
	if p, err := e.register(t, u, key(yubiKey, nil)); err != nil || p.Attested || p.AttestationFormat != "none" {
		t.Fatalf("self-declared aaguid = %+v, %v", p, err)
	}
}

func TestAttestationLogin(t *testing.T) {
	e := setup(t)
	alice := e.user(t, "alice@example.com")
	// フィーチャーを動かす前に登録した passkey（attestation を確かめていない既存の行）。
	legacy := key(yubiKey, nil)
	if _, err := e.register(t, alice, legacy); err != nil {
		t.Fatal(err)
	}
	bob := e.user(t, "bob@example.com")
	ae, vendor := attested(t, nil)
	e.svc.Attestation = ae.svc.Attestation
	good := key(yubiKey, vendor)
	if _, err := e.register(t, bob, good); err != nil {
		t.Fatal(err)
	}
	// ポリシーが無ければ、既存の行もログインできる。
	if _, err := e.login(t, legacy); err != nil {
		t.Fatalf("legacy login: %v", err)
	}
	if ev := e.lastEvent(t, "login.succeeded"); ev["aaguid"] != yubiKey.String() || ev["decision"] != "allowed" {
		t.Fatalf("login.succeeded details = %v", ev)
	}

	// attestation を必須にすると、既存の行ではログインできない（登録し直す）。
	e.svc.Attestation.Policy = &attestation.Policy{RequireAttestation: true}
	_, err := e.login(t, legacy)
	var na *passkey.NotAllowedError
	if !errors.As(err, &na) {
		t.Fatalf("legacy login with require_attestation: err = %v", err)
	}
	if d, ok := errors.AsType[errs.Denial](err); !ok || d.Reasons()[0] != passkey.CodeNotAllowed {
		t.Fatalf("denial = %v", err)
	}
	if ev := e.lastEvent(t, "login.failed"); ev["reason"] != attestation.ReasonAttestationRequired || ev["aaguid"] != yubiKey.String() {
		t.Fatalf("login.failed details = %v", ev)
	}
	if _, err := e.login(t, good); err != nil {
		t.Fatalf("attested login: %v", err)
	}

	// 拒否の一覧に入れた認証器は、登録済みでもログインできない。2要素目でも同じ。
	e.svc.Attestation.Policy = &attestation.Policy{DeniedAAGUIDs: []string{yubiKey.String()}}
	if _, err := e.login(t, good); !errors.As(err, &na) || na.Decision.Reason != attestation.ReasonDenied {
		t.Fatalf("denied login: err = %v", err)
	}
	ctx := context.Background()
	st, err := e.svc.BeginVerify(ctx, e.k.RealmID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := good.Get(st.Options)
	if err != nil {
		t.Fatal(err)
	}
	e.k.Tx(t, func(ctx context.Context, tx port.Tx) error {
		_, err := e.svc.Verify(ctx, tx, e.k.RealmID, bob.ID, st.FlowID, resp)
		if !errors.As(err, &na) {
			t.Fatalf("second factor: err = %v", err)
		}
		return nil
	})
	// フィーチャーが止まっていれば判定しない。
	e.svc.Attestation = nil
	if _, err := e.login(t, good); err != nil {
		t.Fatalf("login without the feature: %v", err)
	}
}
