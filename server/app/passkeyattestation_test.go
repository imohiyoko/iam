package app

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authn/passkey/attestation"
	"github.com/imohiyoko/iam/authn/passkey/passkeytest"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// passkey の attestation と認証器のポリシー（フィーチャー passkey_attestation、ADR 0096）を HTTP で確かめる。

var (
	attYubi  = uuid.MustParse("cb69481e-8ff7-4039-93ec-0a2729a154a8")
	attOther = uuid.MustParse("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4")
)

// staticMDS は決まった BLOB を返す FIDOMetadataSource。
type staticMDS struct{ blob []byte }

func (s staticMDS) Fetch(context.Context) ([]byte, error) { return s.blob, nil }

// newAttestationEnv は passkey_attestation（と org、org_login_policy）を動かした env を作る。vendor は attYubi の
// attestation のルート（MDS に載せる）。
func newAttestationEnv(t *testing.T, on bool, edit func(*config.Config)) (*loginEnv, *passkeytest.CA) {
	t.Helper()
	mds, vendor := passkeytest.NewCA("MDS Root"), passkeytest.NewCA("Vendor Root")
	root := filepath.Join(t.TempDir(), "mds-root.pem")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mds.DER}), 0o600); err != nil {
		t.Fatal(err)
	}
	blob := mds.MDSBlob(1, "2099-01-01", passkeytest.MDSEntry(attYubi.String(), "YubiKey 5", [][]byte{vendor.DER}, "FIDO_CERTIFIED_L2"))
	l := newLoginEnvDeps(t, func(c *config.Config) {
		c.Server.PublicURL = passkeyOrigin
		c.Passkey.Origins = []string{passkeyOrigin}
		c.Passkey.Attestation = config.PasskeyAttestation{Conveyance: "direct", MetadataRootFile: root}
		c.Realm.PasskeyPolicy = &attestation.Policy{AllowedAAGUIDs: []string{attYubi.String()}}
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.OrgLoginPolicy)
		if on {
			names = append(names, feature.PasskeyAttestation)
		}
		c.Features = &names
		if edit != nil {
			edit(c)
		}
	}, feature.Registered(), func(d *Deps) { d.FIDOMDS = staticMDS{blob: blob} })
	return l, vendor
}

func attKey(aaguid uuid.UUID, ca *passkeytest.CA) *passkeytest.Authenticator {
	a := passkeytest.New(passkeyOrigin)
	a.AAGUID = aaguid[:]
	if ca != nil {
		a.Attestation = ca.PackedAttestation(aaguid[:])
	}
	return a
}

func TestPasskeyAttestation(t *testing.T) {
	l, vendor := newAttestationEnv(t, true, nil)
	res, cookie := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)

	// 登録の開始で attestation を求める。
	status, start := l.mePost(t, cookie, "/v1/me/passkeys:start", nil)
	if _, opts := ceremony(t, status, start); !strings.Contains(string(opts), `"attestation":"direct"`) {
		t.Fatalf("options = %s", opts)
	}
	// realm の段の許可の一覧に無い認証器は登録できない（理由はコードだけ）。
	if status, out := l.registerPasskey(t, cookie, attKey(attOther, nil), "Other"); status != 409 || out["error"] != "passkey_not_allowed" {
		t.Fatalf("register other: %d %v", status, out)
	}
	key := attKey(attYubi, vendor)
	if status, out := l.registerPasskey(t, cookie, key, "Yubi"); status != 200 {
		t.Fatalf("register yubi: %d %v", status, out)
	}
	var registered, failed map[string]any
	for _, e := range l.auditTypes(t) {
		switch e.Type {
		case "passkey.registered":
			registered = e.Details
		case "passkey.registration_failed":
			failed = e.Details
		}
	}
	if registered["aaguid"] != attYubi.String() || registered["attested"] != true || registered["authenticator_name"] != "YubiKey 5" {
		t.Fatalf("passkey.registered = %v", registered)
	}
	if failed["aaguid"] != attOther.String() || failed["reason"] != attestation.ReasonNotAllowed || failed["decision"] != "denied" {
		t.Fatalf("passkey.registration_failed = %v", failed)
	}

	// 管理 API の passkey の一覧に AAGUID と認証器の名前を出す。
	_, sec := l.operator(t, "sec@example.com", role.RealmSecurity)
	var creds struct {
		Passkeys []struct {
			AAGUID            string `json:"aaguid"`
			AuthenticatorName string `json:"authenticator_name"`
			AttestationFormat string `json:"attestation_format"`
			Attested          bool   `json:"attested"`
		} `json:"passkeys"`
	}
	if status := l.adminGet(t, "/v1/admin/users/"+uid+"/credentials", sec, &creds); status != 200 || len(creds.Passkeys) != 1 {
		t.Fatalf("credentials: %d %+v", status, creds)
	}
	if p := creds.Passkeys[0]; p.AAGUID != attYubi.String() || p.AuthenticatorName != "YubiKey 5" || p.AttestationFormat != "packed" || !p.Attested {
		t.Fatalf("credential = %+v", p)
	}

	// Org の段：ログインポリシーの passkey で、この認証器を拒否する。
	status, _, pk := l.passkeyLogin(t, key)
	if status != 200 {
		t.Fatalf("passkey login: %d", status)
	}
	acme := l.sharedOrg(t, pk, "Acme")
	bad := map[string]any{"login_policy": map[string]any{"passkey": map[string]any{"min_certification_level": "L9"}}}
	if code, out := l.putSettings(t, pk, acme, bad); code != 400 {
		t.Fatalf("put invalid level: %d %v", code, out)
	}
	deny := map[string]any{"login_policy": map[string]any{"passkey": map[string]any{"denied_aaguids": []string{attYubi.String()}}}}
	code, out := l.putSettings(t, pk, acme, deny)
	if code != 200 {
		t.Fatalf("put passkey policy: %d %v", code, out)
	}
	pol := out["settings"].(map[string]any)["login_policy"].(map[string]any)["passkey"].(map[string]any)
	if ds := pol["denied_aaguids"].([]any); len(ds) != 1 || ds[0] != attYubi.String() {
		t.Fatalf("stored policy = %v", pol)
	}
	if code, body, _ := l.post(t, pk, "/v1/me/orgs/"+acme+":switch", nil); code != 403 || reasonsOf(body) != "policy.passkey_authenticator" {
		t.Fatalf("switch with denied passkey: %d %v", code, body)
	}
	if !slices.ContainsFunc(l.auditTypes(t), func(e audit.Event) bool {
		return e.Type == "org.passkey_policy_denied" && e.Details["aaguid"] == attYubi.String() && e.Details["tier"] == "org"
	}) {
		t.Fatal("org.passkey_policy_denied is not recorded")
	}
	// メールのコードのログイン（passkey を使っていない）には効かない。
	if code, body, _ := l.post(t, cookie, "/v1/me/orgs/"+acme+":switch", nil); code != 200 {
		t.Fatalf("switch with email login: %d %v", code, body)
	}

	// realm の段：拒否の一覧に入れれば、登録済みの passkey でもログインできない（本人確認の後なので理由を返す）。
	l.a.passkeys.Attestation.Policy = &attestation.Policy{DeniedAAGUIDs: []string{attYubi.String()}}
	if status, out, _ := l.passkeyLogin(t, key); status != 403 || out["error"] != "passkey_not_allowed" {
		t.Fatalf("login with denied passkey: %d %v", status, out)
	}
	if !slices.ContainsFunc(l.auditTypes(t), func(e audit.Event) bool {
		return e.Type == "login.failed" && e.Details["aaguid"] == attYubi.String() && e.Details["reason"] == attestation.ReasonDenied &&
			e.Details["tier"] == "realm"
	}) {
		t.Fatal("login.failed does not record the passkey policy decision")
	}

	// フィーチャーの無効化で、Org のログインポリシーの passkey を外す。
	r, err := l.a.DisableFeature(context.Background(), feature.PasskeyAttestation, true)
	if err != nil || !r.Done || r.Purged != 1 {
		t.Fatalf("disable = %+v, %v", r, err)
	}
	if err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		o, err := tx.Orgs().GetByPublicID(ctx, l.a.realm.ID, acme)
		if err != nil {
			return err
		}
		has, err := org.HasPasskeyPolicy(o)
		if has {
			t.Fatalf("org still has the passkey policy: %s", o.Settings)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyAttestationFeatureOff(t *testing.T) {
	l, vendor := newAttestationEnv(t, false, nil)
	if l.a.metadata != nil || l.a.passkeys.Attestation != nil {
		t.Fatal("attestation must not be wired without the feature")
	}
	_, cookie := l.login(t, "pat@example.com")
	status, start := l.mePost(t, cookie, "/v1/me/passkeys:start", nil)
	if _, opts := ceremony(t, status, start); strings.Contains(string(opts), `"attestation":"direct"`) {
		t.Fatalf("options ask for attestation without the feature: %s", opts)
	}
	// ポリシーは判定しない（許可の一覧に無い認証器も登録できる）。
	if status, out := l.registerPasskey(t, cookie, attKey(attOther, vendor), "Other"); status != 200 {
		t.Fatalf("register: %d %v", status, out)
	}
	acme := l.sharedOrg(t, cookie, "Acme")
	deny := map[string]any{"login_policy": map[string]any{"passkey": map[string]any{"denied_aaguids": []string{attYubi.String()}}}}
	if code, out := l.putSettings(t, cookie, acme, deny); code != 400 || out["error"] != "setting_invalid" {
		t.Fatalf("put passkey policy without the feature: %d %v", code, out)
	}
}
