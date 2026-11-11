package app

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/imohiyoko/iam/authn/saml"
	"github.com/imohiyoko/iam/authn/samlidp"
	"github.com/imohiyoko/iam/authn/samlxml"
	"github.com/imohiyoko/iam/authn/wsfed"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// SAML の IdP と WS-Federation の RSA-SHA256 の署名（フィーチャー rs256。ADR 0125）を HTTP で確かめる。

func newRSAXMLEnv(t *testing.T, rs256 bool) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.SAMLIdP, feature.WSFed)
		if rs256 {
			names = append(names, feature.RS256)
		}
		c.Features = &names
	}, feature.Registered())
}

// metadataCerts はメタデータの KeyDescriptor の証明書を返す。
func (l *loginEnv) metadataCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	w := l.oidcDo(t, "GET", path, nil, "")
	if w.Code != 200 {
		t.Fatalf("metadata %s: %d", path, w.Code)
	}
	md := etree.NewDocument()
	if err := md.ReadFromBytes(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	// メタデータ自体の署名は ES256 のまま。
	if m := md.FindElement("/EntityDescriptor/Signature/SignedInfo/SignatureMethod"); m == nil || m.SelectAttrValue("Algorithm", "") != samlxml.AlgECDSA256 {
		t.Fatalf("metadata signature: %s", w.Body)
	}
	var out []*x509.Certificate
	for _, e := range md.FindElements("//KeyDescriptor//X509Certificate") {
		der, _ := base64.StdEncoding.DecodeString(e.Text())
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func rsaCert(t *testing.T, cs []*x509.Certificate) *x509.Certificate {
	t.Helper()
	for _, c := range cs {
		if _, ok := c.PublicKey.(*rsa.PublicKey); ok {
			return c
		}
	}
	t.Fatalf("no rsa certificate in %d certificates", len(cs))
	return nil
}

func TestRSAXMLOff(t *testing.T) {
	l := newRSAXMLEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	body := map[string]any{"entity_id": samlSP, "name": "App", "acs": []map[string]any{{"url": samlACS}}, "signing_alg": "RS256"}
	if code, out := l.admin(t, "/v1/admin/saml/service-providers", owner, body); code != 400 || out["error"] != "invalid_service_provider" {
		t.Fatalf("saml sp RS256 while off: %d %v", code, out)
	}
	if code, out := l.admin(t, "/v1/admin/wsfed/relying-parties", owner, map[string]any{"realm": wsfedRealm, "name": "Portal",
		"reply_urls": []string{wsfedReply}, "signing_alg": "RS256"}); code != 400 || out["error"] != "invalid_relying_party" {
		t.Fatalf("wsfed rp RS256 while off: %d %v", code, out)
	}
	// 既定は ES256 で、メタデータに RSA の証明書は無い。
	sp := l.registerSAMLSP(t, owner, nil)
	rp := l.registerWSFed(t, owner, map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply}})
	if sp["signing_alg"] != "ES256" || rp["signing_alg"] != "ES256" {
		t.Fatalf("defaults: %v %v", sp["signing_alg"], rp["signing_alg"])
	}
	for _, p := range []string{samlidp.MetadataPath, wsfed.MetadataPath} {
		for _, c := range l.metadataCerts(t, p) {
			if _, ok := c.PublicKey.(*rsa.PublicKey); ok {
				t.Fatalf("rsa certificate in %s while off", p)
			}
		}
	}
}

func TestSAMLIdPRSA(t *testing.T) {
	l := newRSAXMLEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	sp := l.registerSAMLSP(t, owner, map[string]any{"signing_alg": "RS256", "sign_response": true})
	if sp["signing_alg"] != "RS256" {
		t.Fatalf("register: %v", sp)
	}
	// 更新で signing_alg を省けば今の値（RS256）を保つ。
	if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/saml/service-providers/"+sp["id"].(string), map[string]any{"entity_id": samlSP,
		"name": "App 2", "acs": []map[string]any{{"url": samlACS}}, "sign_response": true,
		"slo":                  []map[string]any{{"url": samlSPSLO, "binding": samlidp.BindingRedirect}},
		"signing_certificates": []string{base64.StdEncoding.EncodeToString(samlTestSP.cert)},
		"attributes":           []map[string]any{{"source": "email", "name": "urn:oid:0.9.2342.19200300.100.1.3"}}}); code != 200 || out["signing_alg"] != "RS256" {
		t.Fatalf("update without signing_alg: %d %v", code, out)
	}
	certs := l.metadataCerts(t, samlidp.MetadataPath)
	if len(certs) != 2 {
		t.Fatalf("metadata certificates = %d", len(certs))
	}
	rc := rsaCert(t, certs)
	_, cookie := l.login(t, "alice@example.com")
	now := l.a.deps.Clock.Now()
	w := l.oidcDo(t, "GET", samlidp.SSOPath+"?"+samlRedirect(samlAuthnRequest("_rs1", now, ""), "", true), nil, cookie)
	_, vals := samlPosted(t, w.Body.String())
	raw, _ := base64.StdEncoding.DecodeString(vals.Get("SAMLResponse"))
	// Response と Assertion の両方が RSA-SHA256。
	if n := strings.Count(string(raw), `Algorithm="`+samlxml.AlgRSASHA256+`"`); n != 2 || strings.Contains(string(raw), samlxml.AlgECDSA256) {
		t.Fatalf("signature methods (%d): %s", n, raw)
	}
	// SP の側の検証（authn/saml）は RSA の証明書だけで通る。
	a, err := saml.Verify(raw, saml.Expect{IdPEntityID: testIssuer, Certs: []*x509.Certificate{rc}, SPEntityID: samlSP, ACSURL: samlACS,
		RequestID: "_rs1", Now: now})
	if err != nil || a.NameID != l.userID(t, "alice@example.com") {
		t.Fatalf("verify: %+v %v", a, err)
	}
	// HTTP-Redirect の LogoutResponse も RSA-SHA256（PKCS #1 v1.5）で署名する。
	u := location(t, l.oidcDo(t, "GET", samlidp.SLOPath+"?"+samlRedirect(samlLogoutRequest("_rsl", l.userID(t, "alice@example.com"), now), "", true), nil, cookie))
	if u.Query().Get("SigAlg") != samlxml.AlgRSASHA256 {
		t.Fatalf("logout SigAlg: %s", u)
	}
	signed, sig, _ := strings.Cut(u.RawQuery, "&Signature=")
	sig, _ = url.QueryUnescape(sig)
	sb, _ := base64.StdEncoding.DecodeString(sig)
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(rc.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sb); err != nil {
		t.Fatalf("logout signature: %v", err)
	}
}

func TestWSFedRSA(t *testing.T) {
	l := newRSAXMLEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, tt := range []string{"saml11", "saml20"} {
		realm := wsfedRealm + ":" + tt
		rp := l.registerWSFed(t, owner, map[string]any{"realm": realm, "name": "Portal", "reply_urls": []string{wsfedReply}, "token_type": tt,
			"signing_alg": "RS256"})
		if rp["signing_alg"] != "RS256" {
			t.Fatalf("register: %v", rp)
		}
		// 更新で signing_alg を省けば今の値（RS256）を保つ。
		if code, out := l.adminDo(t, "PUT", owner, "/v1/admin/wsfed/relying-parties/"+rp["id"].(string), map[string]any{"realm": realm,
			"name": "Portal 2", "reply_urls": []string{wsfedReply}, "token_type": tt}); code != 200 || out["signing_alg"] != "RS256" {
			t.Fatalf("update without signing_alg: %d %v", code, out)
		}
	}
	rc := rsaCert(t, l.metadataCerts(t, wsfed.MetadataPath))
	_, cookie := l.login(t, "alice@example.com")
	for _, tt := range []string{"saml11", "saml20"} {
		w := l.oidcDo(t, "GET", signinURL(url.Values{"wtrealm": {wsfedRealm + ":" + tt}}), nil, cookie)
		_, vals := wsfedPosted(t, w.Body.String())
		doc := etree.NewDocument()
		if err := doc.ReadFromString(vals.Get("wresult")); err != nil {
			t.Fatal(err)
		}
		a := doc.FindElement("//RequestedSecurityToken/Assertion")
		if m := a.FindElement(".//SignatureMethod"); m == nil || m.SelectAttrValue("Algorithm", "") != samlxml.AlgRSASHA256 {
			t.Fatalf("%s signature method: %s", tt, vals.Get("wresult"))
		}
		// 標準の XML 署名の検証（goxmldsig）が RSA の証明書で通る。
		vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{rc}})
		if tt == "saml11" {
			vc.IdAttribute = "AssertionID"
		}
		if _, err := vc.Validate(a.Copy()); err != nil {
			t.Fatalf("%s validate: %v", tt, err)
		}
	}
}

func TestDisableRS256WithFederation(t *testing.T) {
	l := newRSAXMLEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerSAMLSP(t, owner, map[string]any{"signing_alg": "RS256"})
	l.registerWSFed(t, owner, map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply}, "signing_alg": "RS256"})
	// 片付けるのは SP 1 つ、RP 1 つ、使っている RS256 の鍵 1 つ（鍵は起動のときに作る）。
	l.metadataCerts(t, samlidp.MetadataPath)
	ctx := context.Background()
	res, err := l.a.DisableFeature(ctx, feature.RS256, true)
	if err != nil || !res.Done || res.Purged != 3 {
		t.Fatalf("disable: %+v %v", res, err)
	}
	err = l.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		sps, err := tx.SAMLIdP().ListServiceProviders(ctx, l.a.realm.ID)
		if err != nil {
			return err
		}
		c, err := samlidp.ConfigOf(sps[0])
		if err != nil || c.SigningAlg != port.AlgES256 {
			t.Fatalf("sp after disable: %+v %v", c, err)
		}
		rps, err := tx.WSFed().ListRelyingParties(ctx, l.a.realm.ID)
		if err != nil || rps[0].SigningAlg != port.AlgES256 {
			t.Fatalf("rp after disable: %+v %v", rps, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 起動し直す前（フィーチャーがまだ動いているインスタンス）でも、メタデータの取得で RS256 の鍵を作り直さない。
	l.metadataCerts(t, samlidp.MetadataPath)
	l.metadataCerts(t, wsfed.MetadataPath)
	err = l.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		ok, err := l.a.keys.HasActive(ctx, tx, l.a.realm.ID, port.AlgRS256)
		if err == nil && ok {
			t.Fatal("rs256 key recreated by metadata after disable")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRSAXMLMetadataWhileDisabling は、フィーチャーを止めて起動し直した後、片付けの前（RS256 の鍵と RS256 の連携先が残る）は、
// メタデータに RS256 の鍵の証明書を載せ続ける（その間は RS256 で署名する）ことを確かめる。
func TestRSAXMLMetadataWhileDisabling(t *testing.T) {
	l := newRSAXMLEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	l.registerSAMLSP(t, owner, map[string]any{"signing_alg": "RS256"})
	l.registerWSFed(t, owner, map[string]any{"realm": wsfedRealm, "name": "Portal", "reply_urls": []string{wsfedReply}, "signing_alg": "RS256"})
	enabled := slices.DeleteFunc(slices.Clone(*l.e.cfg.Features), func(n string) bool { return n == feature.RS256 })
	if _, err := l.restart(t, enabled, feature.Registered()); err != nil || l.a.keys.RS256 {
		t.Fatalf("restart without rs256: %v", err)
	}
	for _, p := range []string{samlidp.MetadataPath, wsfed.MetadataPath} {
		rsaCert(t, l.metadataCerts(t, p))
	}
}
