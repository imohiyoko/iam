package app

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt/sdjwttest"
	"github.com/imohiyoko/iam/authn/vci"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/config"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// OpenID4VCI の発行者（ADR 0119）を HTTP で確かめる。

func newVCIEnv(t *testing.T, on bool, extra ...string) *loginEnv {
	t.Helper()
	return newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		if on {
			names = append(names, feature.OpenID4VCI)
		}
		names = append(names, extra...)
		c.Features = &names
	}, feature.Registered())
}

// vciConfig は社員証の定義（email は選択的に開示、user_id と const は平文）。
func vciConfig(id string, extra map[string]any) map[string]any {
	off := false
	body := map[string]any{"configuration_id": id, "format": "dc+sd-jwt", "vct": "https://credentials.example.com/" + id,
		"display": []map[string]any{{"name": "Employee ID", "locale": "en"}},
		"claims": []map[string]any{
			{"name": "email", "source": "email", "mandatory": true},
			{"name": "email_verified", "source": "email_verified"},
			{"name": "user", "source": "user_id", "selectively_disclosable": off},
			{"name": "org", "source": "const", "value": "Example Corp", "selectively_disclosable": off},
		}}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func (l *loginEnv) vciPost(t *testing.T, path string, body any, hdr ...string) (int, map[string]any) {
	t.Helper()
	w := l.do(t, l.a.PublicHandler(), "POST", path, body, hdr...)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// vciOffer は本人の申し出を作り、pre-authorized_code と tx_code を返す。
func (l *loginEnv) vciOffer(t *testing.T, cookie string, body map[string]any) (code, tx string, out map[string]any) {
	t.Helper()
	status, out := l.mePost(t, cookie, "/v1/me/verifiable-credentials/offers", body)
	if status != 201 {
		t.Fatalf("offer: %d %v", status, out)
	}
	grant := out["credential_offer"].(map[string]any)["grants"].(map[string]any)[vci.GrantTypePreAuthorized].(map[string]any)
	tx, _ = out["tx_code"].(string)
	return grant["pre-authorized_code"].(string), tx, out
}

func (l *loginEnv) vciToken(t *testing.T, form url.Values, hdr ...string) (int, map[string]any) {
	t.Helper()
	f := url.Values{"grant_type": {vci.GrantTypePreAuthorized}}
	for k, v := range form {
		f[k] = v
	}
	w := l.oidcDo(t, "POST", oidcToken, f, "", hdr...)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (l *loginEnv) vciNonce(t *testing.T) string {
	t.Helper()
	status, out := l.vciPost(t, vci.NoncePath, nil)
	if status != 200 || out["c_nonce"] == "" {
		t.Fatalf("nonce: %d %v", status, out)
	}
	return out["c_nonce"].(string)
}

// vciProof はウォレットの鍵の proof を作る。claims は既定（aud・iat・nonce）に重ねる。
func (l *loginEnv) vciProof(h *sdjwttest.Holder, nonce string, claims map[string]any) string {
	c := map[string]any{"aud": testIssuer, "iat": l.e.deps.Clock.Now().Unix(), "nonce": nonce}
	for k, v := range claims {
		c[k] = v
	}
	return sdjwttest.Sign(h.Key, vci.ProofType, map[jose.HeaderKey]any{"jwk": h.JWK()}, c)
}

func (l *loginEnv) vciCredential(t *testing.T, token, cid, proof string) (int, map[string]any) {
	t.Helper()
	body := map[string]any{"credential_configuration_id": cid, "proofs": map[string]any{"jwt": []string{proof}}}
	return l.vciPost(t, vci.CredentialPath, body, "Authorization", "Bearer "+token)
}

// vciVerify は発行した資格情報に holder の key binding を付け、発行者の公開鍵（/.well-known/jwt-vc-issuer）で確かめる。
func (l *loginEnv) vciVerify(t *testing.T, h *sdjwttest.Holder, credential string) *sdjwt.Credential {
	t.Helper()
	w := l.oidcDo(t, "GET", wellKnownJWTVCIssuer, nil, "")
	var meta struct {
		Issuer string             `json:"issuer"`
		JWKS   jose.JSONWebKeySet `json:"jwks"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &meta) != nil || meta.Issuer != testIssuer || len(meta.JWKS.Keys) == 0 {
		t.Fatalf("jwt-vc-issuer: %d %s", w.Code, w.Body)
	}
	now := l.e.deps.Clock.Now()
	kb := sdjwttest.Sign(h.Key, sdjwt.TypeKB, nil, map[string]any{"aud": "https://verifier.example", "nonce": "vn", "iat": now.Unix(),
		"sd_hash": sdjwt.SDHash(credential)})
	c, err := sdjwt.Verify(credential+kb, sdjwt.Options{Now: now, Skew: time.Minute, KBMaxAge: 5 * time.Minute, Audience: "https://verifier.example",
		Nonce: "vn", IssuerKey: func(iss string, hd jose.Header) (any, error) {
			if iss != meta.Issuer {
				return nil, errors.New("unknown issuer")
			}
			for _, k := range meta.JWKS.Key(hd.KeyID) {
				return k.Key, nil
			}
			return nil, errors.New("unknown key")
		}})
	if err != nil {
		t.Fatalf("verify credential: %v", err)
	}
	return c
}

// vciStatus は status list token を realm の鍵で確かめ、番号 idx の値を返す。
func (l *loginEnv) vciStatus(t *testing.T, idx int) byte {
	t.Helper()
	w := l.oidcDo(t, "GET", vci.StatusListPath, nil, "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/statuslist+jwt" {
		t.Fatalf("status list: %d %v", w.Code, w.Header())
	}
	var payload []byte
	err := l.a.deps.Storage.Tx(context.Background(), func(ctx context.Context, tx port.Tx) error {
		var err error
		payload, err = l.a.keys.Verify(ctx, tx, l.a.realm.ID, w.Body.String())
		return err
	})
	if err != nil {
		t.Fatalf("verify status list: %v", err)
	}
	var tok struct {
		Sub        string `json:"sub"`
		StatusList struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(payload, &tok); err != nil || tok.Sub != testIssuer+vci.StatusListPath || tok.StatusList.Bits != 1 {
		t.Fatalf("status list token: %s %v", payload, err)
	}
	z, err := base64.RawURLEncoding.DecodeString(tok.StatusList.Lst)
	if err != nil {
		t.Fatal(err)
	}
	r, err := zlib.NewReader(bytes.NewReader(z))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil || idx/8 >= len(b) {
		t.Fatalf("status list: %d bytes, %v", len(b), err)
	}
	return b[idx/8] >> (idx % 8) & 1
}

func TestVCIDisabled(t *testing.T) {
	l := newVCIEnv(t, false)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	for _, p := range []string{wellKnownCredentialIssuer, wellKnownJWTVCIssuer, vci.StatusListPath, vci.OfferPath + "x"} {
		if w := l.oidcDo(t, "GET", p, nil, ""); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := l.oidcDo(t, "POST", vci.NoncePath, nil, ""); w.Code != 404 {
		t.Errorf("nonce: %d", w.Code)
	}
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {"x"}}); status != 400 || out["error"] != "unsupported_grant_type" {
		t.Errorf("token: %d %v", status, out)
	}
	w := l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if strings.Contains(w.Body.String(), vci.GrantTypePreAuthorized) {
		t.Errorf("discovery advertises the pre-authorized grant: %s", w.Body)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/vci/credential-configurations", nil); code != 404 || out["error"] != "openid4vci_disabled" {
		t.Fatalf("admin: %d %v", code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me/verifiable-credentials", nil); code != 404 {
		t.Fatalf("me: %d", code)
	}
}

func TestVCIConfigurationsAdmin(t *testing.T) {
	l := newVCIEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	const base = "/v1/admin/vci/credential-configurations"
	code, created := l.adminDo(t, "POST", owner, base, vciConfig("employee", map[string]any{"scope": "employee_credential"}))
	if code != 201 || created["id"] == "" || created["validity"] != float64(90*24*3600) {
		t.Fatalf("create: %d %v", code, created)
	}
	id := created["id"].(string)
	// email の既定は選択的に開示、明示した偽は平文。
	for _, c := range created["claims"].([]any) {
		c := c.(map[string]any)
		if want := c["name"] == "email" || c["name"] == "email_verified"; c["selectively_disclosable"] != want {
			t.Fatalf("claim %v", c)
		}
	}
	for _, tc := range []struct {
		body       map[string]any
		code       int
		errorValue string
	}{
		{vciConfig("employee", nil), 409, "configuration_exists"},
		{vciConfig("other", map[string]any{"scope": "employee_credential"}), 409, "scope_exists"},
		{vciConfig("other", map[string]any{"scope": "openid"}), 400, "invalid_credential_configuration"},
		{vciConfig("mdl", map[string]any{"format": "mso_mdoc"}), 400, "unsupported_format"},
		{vciConfig("x", map[string]any{"claims": []map[string]any{{"name": "cnf", "source": "email"}}}), 400, "invalid_credential_configuration"},
		{vciConfig("x", map[string]any{"claims": []map[string]any{{"name": "a", "source": "password"}}}), 400, "invalid_credential_configuration"},
	} {
		if code, out := l.adminDo(t, "POST", owner, base, tc.body); code != tc.code || out["error"] != tc.errorValue {
			t.Errorf("create %v: %d %v", tc.body["configuration_id"], code, out)
		}
	}
	body := vciConfig("employee", map[string]any{"require_tx_code": true, "validity": 3600})
	if code, out := l.adminDo(t, "PUT", owner, base+"/"+id, body); code != 200 || out["require_tx_code"] != true || out["scope"] != nil {
		t.Fatalf("update: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, base, nil); code != 200 || len(out["configurations"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	// 管理者でなければ触れない。
	_, cookie := l.login(t, "alice@example.com")
	if code, _ := l.meDo(t, "GET", cookie, "/v1/me/verifiable-credentials/configurations", nil); code != 200 {
		t.Fatalf("me configurations: %d", code)
	}
	_, support := l.operator(t, "support@example.com", role.RealmSupport)
	if code, _ := l.adminDo(t, "POST", support, base, vciConfig("y", nil)); code != 403 {
		t.Fatalf("support create: %d", code)
	}
	if code, _ := l.admin(t, base+"/"+id+":delete", owner, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.adminDo(t, "GET", owner, base+"/"+id, nil); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
	es := l.auditTypes(t)
	for _, typ := range []string{"vci.configuration_created", "vci.configuration_updated", "vci.configuration_deleted"} {
		if countType(es, typ) != 1 {
			t.Errorf("audit %s: %d", typ, countType(es, typ))
		}
	}
}

func TestVCIPreAuthorizedFlow(t *testing.T) {
	l := newVCIEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("employee", nil)); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}

	// 発行者のメタデータ。
	w := l.oidcDo(t, "GET", wellKnownCredentialIssuer, nil, "", "Origin", "https://wallet.example")
	var meta map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &meta) != nil || meta["credential_issuer"] != testIssuer ||
		meta["credential_endpoint"] != testIssuer+vci.CredentialPath || meta["nonce_endpoint"] != testIssuer+vci.NoncePath ||
		w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatalf("metadata: %d %v %s", w.Code, w.Header(), w.Body)
	}
	emp := meta["credential_configurations_supported"].(map[string]any)["employee"].(map[string]any)
	if emp["format"] != "dc+sd-jwt" || emp["vct"] != "https://credentials.example.com/employee" ||
		!slices.Contains(emp["cryptographic_binding_methods_supported"].([]any), any("jwk")) {
		t.Fatalf("configuration metadata: %v", emp)
	}
	w = l.oidcDo(t, "GET", "/.well-known/openid-configuration", nil, "")
	if !strings.Contains(w.Body.String(), vci.GrantTypePreAuthorized) {
		t.Fatalf("discovery: %s", w.Body)
	}

	_, cookie := l.login(t, "alice@example.com")
	// 知らない定義の申し出は作らない。
	if status, out := l.mePost(t, cookie, "/v1/me/verifiable-credentials/offers", map[string]any{"credential_configuration_ids": []string{"nope"}}); status != 400 ||
		out["error"] != "unknown_credential_configuration" {
		t.Fatalf("unknown offer: %d %v", status, out)
	}
	code, tx, offer := l.vciOffer(t, cookie, map[string]any{"credential_configuration_ids": []string{"employee"}})
	if tx != "" || !strings.HasPrefix(offer["credential_offer_uri"].(string), vci.OfferScheme+"?credential_offer=") {
		t.Fatalf("offer: %v", offer)
	}
	// 参照で渡した申し出は同じ値を返す。
	ref, err := url.Parse(offer["credential_offer_reference_uri"].(string))
	if err != nil {
		t.Fatal(err)
	}
	refURL := ref.Query().Get("credential_offer_uri")
	if !strings.HasPrefix(refURL, testIssuer+vci.OfferPath) {
		t.Fatalf("reference uri: %s", refURL)
	}
	w = l.oidcDo(t, "GET", strings.TrimPrefix(refURL, testIssuer), nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), code) {
		t.Fatalf("offer by reference: %d %s", w.Code, w.Body)
	}

	// ウォレットの認証は受けない。
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "client_secret": {"s"}}); status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("token with client auth: %d %v", status, out)
	}
	// tx_code を求めない申し出に tx_code を付ければ拒む。
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "tx_code": {"123456"}}); status != 400 || out["error"] != "invalid_request" {
		t.Fatalf("unexpected tx_code: %d %v", status, out)
	}
	status, tok := l.vciToken(t, url.Values{"pre-authorized_code": {code}})
	if status != 200 || tok["token_type"] != "Bearer" || !strings.HasPrefix(tok["access_token"].(string), "vci_") {
		t.Fatalf("token: %d %v", status, tok)
	}
	access := tok["access_token"].(string)
	// 引き換えは1回だけ。申し出も消える。
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("replayed code: %d %v", status, out)
	}
	if w := l.oidcDo(t, "GET", strings.TrimPrefix(refURL, testIssuer), nil, ""); w.Code != 404 {
		t.Fatalf("offer after redeem: %d", w.Code)
	}

	h := sdjwttest.NewHolder()
	// nonce の誤り。
	for name, n := range map[string]string{"forged": "AAAA", "empty": ""} {
		if status, out := l.vciCredential(t, access, "employee", l.vciProof(h, n, nil)); status != 400 || out["error"] != vci.CodeInvalidNonce {
			t.Fatalf("%s nonce: %d %v", name, status, out)
		}
	}
	// aud の誤り、古い iat。
	if status, out := l.vciCredential(t, access, "employee", l.vciProof(h, l.vciNonce(t), map[string]any{"aud": "https://other.example"})); status != 400 ||
		out["error"] != vci.CodeInvalidProof {
		t.Fatalf("wrong aud: %d %v", status, out)
	}
	stale := l.e.deps.Clock.Now().Add(-10 * time.Minute).Unix()
	if status, out := l.vciCredential(t, access, "employee", l.vciProof(h, l.vciNonce(t), map[string]any{"iat": stale})); status != 400 ||
		out["error"] != vci.CodeInvalidProof {
		t.Fatalf("stale iat: %d %v", status, out)
	}
	// 申し出に無い定義。
	if status, out := l.vciCredential(t, access, "missing", l.vciProof(h, l.vciNonce(t), nil)); status != 400 || out["error"] != vci.CodeUnknownCredentialConfiguration {
		t.Fatalf("unknown configuration: %d %v", status, out)
	}
	// アクセストークンが無い・知らない。
	if status, out := l.vciCredential(t, "vci_bogus", "employee", l.vciProof(h, l.vciNonce(t), nil)); status != 401 || out["error"] != "invalid_token" {
		t.Fatalf("bogus token: %d %v", status, out)
	}

	nonce := l.vciNonce(t)
	status, res := l.vciCredential(t, access, "employee", l.vciProof(h, nonce, nil))
	if status != 200 {
		t.Fatalf("credential: %d %v", status, res)
	}
	credential := res["credentials"].([]any)[0].(map[string]any)["credential"].(string)
	vc := l.vciVerify(t, h, credential)
	alice := l.userID(t, "alice@example.com")
	if vc.Issuer != testIssuer || vc.VCT != "https://credentials.example.com/employee" || !vc.HasStatus || vc.Claims["email"] != "alice@example.com" ||
		vc.Claims["email_verified"] != true || vc.Claims["user"] != alice || vc.Claims["org"] != "Example Corp" {
		t.Fatalf("credential claims: %+v", vc)
	}
	// 選択的に開示するのは email と email_verified だけ。
	if parts := strings.Split(credential, "~"); len(parts) != 4 {
		t.Fatalf("disclosures: %d", len(parts)-2)
	}
	// 内部 ID は出さない（ADR 0045）。
	if strings.Contains(credential, l.internalUserID(t, alice)) {
		t.Fatal("internal user id leaked")
	}
	// 同じ nonce は2度使えない。
	if status, out := l.vciCredential(t, access, "employee", l.vciProof(h, nonce, nil)); status != 400 || out["error"] != vci.CodeInvalidNonce {
		t.Fatalf("reused nonce: %d %v", status, out)
	}

	// 本人の一覧と失効。status list に出る。
	_, list := l.meDo(t, "GET", cookie, "/v1/me/verifiable-credentials", nil)
	creds := list["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("my credentials: %v", list)
	}
	cid := creds[0].(map[string]any)["id"].(string)
	_, adminList := l.adminDo(t, "GET", owner, "/v1/admin/vci/credentials?user_id="+url.QueryEscape(alice), nil)
	idx := int(adminList["credentials"].([]any)[0].(map[string]any)["status_index"].(float64))
	if l.vciStatus(t, idx) != 0 {
		t.Fatal("valid credential shows as revoked")
	}
	_, bobCookie := l.login(t, "bob@example.com")
	if code, _ := l.mePost(t, bobCookie, "/v1/me/verifiable-credentials/"+cid+":revoke", nil); code != 404 {
		t.Fatalf("revoke someone else's: %d", code)
	}
	if code, _ := l.mePost(t, cookie, "/v1/me/verifiable-credentials/"+cid+":revoke", nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if l.vciStatus(t, idx) != 1 {
		t.Fatal("revoked credential not in the status list")
	}

	es := l.auditTypes(t)
	for typ, n := range map[string]int{"vci.offer_created": 1, "vci.token_issued": 1, "vci.credential_issued": 1, "vci.credential_revoked": 1} {
		if countType(es, typ) != n {
			t.Errorf("audit %s: %d", typ, countType(es, typ))
		}
	}
	if countType(es, "vci.token_rejected") == 0 || countType(es, "vci.credential_rejected") == 0 {
		t.Error("rejections not audited")
	}
}

func TestVCITxCode(t *testing.T) {
	l := newVCIEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("employee", map[string]any{"require_tx_code": true})); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	code, tx, offer := l.vciOffer(t, cookie, map[string]any{"credential_configuration_ids": []string{"employee"}})
	grant := offer["credential_offer"].(map[string]any)["grants"].(map[string]any)[vci.GrantTypePreAuthorized].(map[string]any)
	if len(tx) != vci.TxCodeLength || grant["tx_code"] == nil || strings.Contains(offer["credential_offer_uri"].(string), tx) {
		t.Fatalf("tx_code offer: %q %v", tx, offer)
	}
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}}); status != 400 || out["error"] != "invalid_request" {
		t.Fatalf("missing tx_code: %d %v", status, out)
	}
	wrong := "000000"
	if tx == wrong {
		wrong = "111111"
	}
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "tx_code": {wrong}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("wrong tx_code: %d %v", status, out)
	}
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "tx_code": {tx}}); status != 200 {
		t.Fatalf("right tx_code: %d %v", status, out)
	}

	// 誤りが続けば申し出を消す（正しい tx_code でも引き換えられない）。
	code, tx, _ = l.vciOffer(t, cookie, map[string]any{"credential_configuration_ids": []string{"employee"}})
	wrong = "000000"
	if tx == wrong {
		wrong = "111111"
	}
	for range vci.MaxTxCodeAttempts {
		if status, _ := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "tx_code": {wrong}}); status != 400 {
			t.Fatalf("wrong tx_code: %d", status)
		}
	}
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "tx_code": {tx}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("tx_code after lockout: %d %v", status, out)
	}

	// 期限の過ぎた申し出は引き換えられない。
	code, tx, _ = l.vciOffer(t, cookie, map[string]any{"credential_configuration_ids": []string{"employee"}})
	l.advance(vci.OfferTTL + time.Second)
	if status, out := l.vciToken(t, url.Values{"pre-authorized_code": {code}, "tx_code": {tx}}); status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("expired offer: %d %v", status, out)
	}
}

// TestVCIOfferNeedsRecentAuth は申し出に直近の本人確認が要ることと、ログアウトで系列が終われば発行しないことを確かめる。
func TestVCIOfferNeedsRecentAuth(t *testing.T) {
	l := newVCIEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("employee", nil)); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	code, _, _ := l.vciOffer(t, cookie, map[string]any{"credential_configuration_ids": []string{"employee"}})
	status, tok := l.vciToken(t, url.Values{"pre-authorized_code": {code}})
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	if code, _ := l.mePost(t, cookie, "/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	h := sdjwttest.NewHolder()
	if status, out := l.vciCredential(t, tok["access_token"].(string), "employee", l.vciProof(h, l.vciNonce(t), nil)); status != 401 && status != 400 {
		t.Fatalf("credential after logout: %d %v", status, out)
	}

	_, cookie = l.login(t, "alice@example.com")
	l.advance(16 * time.Minute)
	if status, out := l.mePost(t, cookie, "/v1/me/verifiable-credentials/offers", map[string]any{"credential_configuration_ids": []string{"employee"}}); status != 401 ||
		out["error"] != "reauthentication_required" {
		t.Fatalf("stale session: %d %v", status, out)
	}
}

// TestVCIAuthorizationCodeFlow は既存の OIDC Provider の認可（scope）で発行することを確かめる。ウォレットは openid を求めない。
func TestVCIAuthorizationCodeFlow(t *testing.T) {
	l := newVCIEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("employee", map[string]any{"scope": "employee_credential"})); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("badge", map[string]any{"scope": "badge_credential"})); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	p := l.registerRP(t, owner, map[string]any{"token_endpoint_auth_method": "none", "redirect_uris": []string{"https://wallet.example/cb"}})
	code, _ := p.login(t, "alice@example.com", url.Values{"scope": {"employee_credential"}, "nonce": nil})
	status, tok := p.exchange(t, code, nil)
	if status != 200 || tok["scope"] != "employee_credential" || tok["id_token"] != nil {
		t.Fatalf("token: %d %v", status, tok)
	}
	access := tok["access_token"].(string)
	h := sdjwttest.NewHolder()
	// 認可していない定義は出さない。
	if status, out := l.vciCredential(t, access, "badge", l.vciProof(h, l.vciNonce(t), nil)); status != 400 || out["error"] != vci.CodeCredentialRequestDenied {
		t.Fatalf("unauthorized configuration: %d %v", status, out)
	}
	status, res := l.vciCredential(t, access, "employee", l.vciProof(h, l.vciNonce(t), map[string]any{"iss": p.clientID}))
	if status != 200 {
		t.Fatalf("credential: %d %v", status, res)
	}
	vc := l.vciVerify(t, h, res["credentials"].([]any)[0].(map[string]any)["credential"].(string))
	if vc.Claims["email"] != "alice@example.com" {
		t.Fatalf("claims: %v", vc.Claims)
	}
	// proof の iss はクライアント ID と合わなければ拒む。
	if status, out := l.vciCredential(t, access, "employee", l.vciProof(h, l.vciNonce(t), map[string]any{"iss": "someone-else"})); status != 400 ||
		out["error"] != vci.CodeInvalidProof {
		t.Fatalf("wrong proof iss: %d %v", status, out)
	}
	// 要求の誤り。proof が無ければ invalid_proof、credential_identifier は出していない。
	for _, tc := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"credential_configuration_id": "employee"}, vci.CodeInvalidProof},
		{map[string]any{"credential_identifier": "x", "proofs": map[string]any{"jwt": []string{l.vciProof(h, l.vciNonce(t), nil)}}}, vci.CodeUnknownCredentialIdentifier},
		{map[string]any{"credential_configuration_id": "employee", "proof": map[string]any{"proof_type": "jwt"}}, vci.CodeInvalidCredentialRequest},
	} {
		if status, out := l.vciPost(t, vci.CredentialPath, tc.body, "Authorization", "Bearer "+access); status != 400 || out["error"] != tc.code {
			t.Errorf("request %v: %d %v", tc.body, status, out)
		}
	}
}

// TestVCIAccountDeletionRevokes はアカウントの削除で発行済みの資格情報を失効させることを確かめる。
func TestVCIAccountDeletionRevokes(t *testing.T) {
	l := newVCIEnv(t, true)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("employee", nil)); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	_, cookie := l.login(t, "alice@example.com")
	code, _, _ := l.vciOffer(t, cookie, map[string]any{"credential_configuration_ids": []string{"employee"}})
	_, tok := l.vciToken(t, url.Values{"pre-authorized_code": {code}})
	h := sdjwttest.NewHolder()
	if status, out := l.vciCredential(t, tok["access_token"].(string), "employee", l.vciProof(h, l.vciNonce(t), nil)); status != 200 {
		t.Fatalf("credential: %d %v", status, out)
	}
	alice := l.userID(t, "alice@example.com")
	_, list := l.adminDo(t, "GET", owner, "/v1/admin/vci/credentials?user_id="+url.QueryEscape(alice), nil)
	idx := int(list["credentials"].([]any)[0].(map[string]any)["status_index"].(float64))
	if status, out := l.admin(t, "/v1/admin/users/"+alice+":delete", owner, map[string]bool{"immediate": true}); status != 200 {
		t.Fatalf("delete user: %d %v", status, out)
	}
	if l.vciStatus(t, idx) != 1 {
		t.Fatal("deleted user's credential is still valid")
	}
}

// TestVCIRealmPathMetadata は realm がパスで分かれるとき、RFC 8414 と同じ形の既知の場所でもメタデータを返すことを確かめる。
func TestVCIRealmPathMetadata(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		c.Server.PublicURL = multiRealmURL
		var names []string
		for _, f := range feature.Registered() {
			if f.DefaultEnabled {
				names = append(names, f.Name)
			}
		}
		names = append(names, feature.MultiRealm, feature.OpenID4VCI)
		c.Features = &names
	}, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	acme, _ := l.newRealm(t, owner, map[string]any{"slug": "acme", "name": "Acme"})
	want := multiRealmURL + "/realms/acme"
	for _, path := range []string{wellKnownCredentialIssuer + "/realms/acme", "/realms/acme" + wellKnownCredentialIssuer} {
		w := realmClient{l: l}.do(t, false, "GET", path, nil)
		if out := decode(t, w); w.Code != 200 || out["credential_issuer"] != want || out["credential_endpoint"] != want+vci.CredentialPath {
			t.Fatalf("%s: %d %v", path, w.Code, out)
		}
	}
	if w := acme.do(t, false, "GET", wellKnownJWTVCIssuer, nil); w.Code != 200 || decode(t, w)["issuer"] != want {
		t.Fatalf("jwt-vc-issuer: %d %s", w.Code, w.Body)
	}
}

func TestDisableOpenID4VCIWithData(t *testing.T) {
	l := newLoginEnvWith(t, func(c *config.Config) {
		withIssuer(c)
		names := []string{}
		for _, f := range feature.Registered() {
			names = append(names, f.Name)
		}
		c.Features = &names
	}, feature.Registered())
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, out := l.adminDo(t, "POST", owner, "/v1/admin/vci/credential-configurations", vciConfig("employee", nil)); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	disableWithData(t, l, feature.OpenID4VCI, 1)
}
