package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/shared/feature"
)

// SSF の送信側・受信側を HTTP で確かめる（ADR 0118）。

func (l *loginEnv) ssfDo(t *testing.T, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var hdr []string
	if bearer != "" {
		hdr = []string{"Authorization", "Bearer " + bearer}
	}
	w := l.do(t, l.a.PublicHandler(), method, path, body, hdr...)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// setPayload は署名を確かめずに SET のペイロードを読む（送信側の SET の中身の確認用。署名は authn/ssf で確かめる）。
func setPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", compact)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSSFOff(t *testing.T) {
	l := featureEnv(t, nil)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	if code, _ := l.ssfDo(t, "GET", wellKnownSSF, "", nil); code != 404 {
		t.Fatalf("configuration while off: %d", code)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/ssf/transmitters", nil); code != 404 || out["error"] != "ssf_receiver_disabled" {
		t.Fatalf("transmitters while off: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/ssf/streams", nil); code != 404 || out["error"] != "ssf_transmitter_disabled" {
		t.Fatalf("streams while off: %d %v", code, out)
	}
}

func TestSSFTransmitter(t *testing.T) {
	l := featureEnv(t, nil, feature.ServiceAccounts, feature.ResourceIndicators, feature.SSFTransmitter)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	res, _ := l.login(t, "pat@example.com")
	uid := res["user_id"].(string)

	code, conf := l.ssfDo(t, "GET", wellKnownSSF, "", nil)
	if code != 200 || conf["issuer"] != testIssuer || conf["configuration_endpoint"] != testIssuer+ssfStreamsPath || conf["jwks_uri"] != testIssuer+oidcKeys {
		t.Fatalf("configuration: %d %v", code, conf)
	}

	// 受信側は、<issuer>/ssf に向けた ssf スコープのトークンで呼ぶ。
	sa, secret := l.serviceAccountSecret(t, owner, "receiver")
	if code, out := l.admin(t, "/v1/admin/oauth/resources", owner, map[string]any{"uri": testIssuer + "/ssf", "name": "SSF",
		"scopes": []string{"ssf", "other"}, "service_accounts": []string{sa}}); code != 201 {
		t.Fatalf("resource: %d %v", code, out)
	}
	tokenFor := func(scope string) string {
		code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}, "resource": {testIssuer + "/ssf"}, "scope": {scope}}, sa+":"+secret)
		if code != 200 {
			t.Fatalf("token: %d %v", code, out)
		}
		return out["access_token"].(string)
	}
	tok := tokenFor("ssf")
	if code, _ := l.ssfDo(t, "GET", ssfStreamsPath, "", nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := l.ssfDo(t, "GET", ssfStreamsPath, "bogus", nil); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	if code, _ := l.ssfDo(t, "GET", ssfStreamsPath, tokenFor("other"), nil); code != 403 {
		t.Fatalf("token without ssf scope: %d", code)
	}
	// 管理 API のトークン（aud が違う）は使えない。
	if code, out := l.token(t, url.Values{"grant_type": {"client_credentials"}}, sa+":"+secret); code == 200 {
		if code, _ := l.ssfDo(t, "GET", ssfStreamsPath, out["access_token"].(string), nil); code != 401 {
			t.Fatalf("admin token: %d", code)
		}
	}

	code, st := l.ssfDo(t, "POST", ssfStreamsPath, tok, map[string]any{"delivery": map[string]any{"method": ssf.DeliveryPollURN},
		"events_requested": []string{ssf.EventAccountDisabled, ssf.EventSessionRevoked, "urn:example:unknown"}})
	if code != 201 {
		t.Fatalf("create stream: %d %v", code, st)
	}
	sid := st["stream_id"].(string)
	if d := st["delivery"].(map[string]any); d["endpoint_url"] != testIssuer+ssfPollPrefix+"/"+sid || st["aud"] != sa {
		t.Fatalf("stream: %v", st)
	}
	if delivered := st["events_delivered"].([]any); len(delivered) != 2 {
		t.Fatalf("events_delivered: %v", delivered)
	}
	if code, out := l.ssfDo(t, "POST", ssfAddSubjectPath, tok, map[string]any{"stream_id": sid,
		"subject": map[string]any{"format": "iss_sub", "iss": testIssuer, "sub": uid}}); code != 200 {
		t.Fatalf("add subject: %d %v", code, out)
	}
	if code, _ := l.ssfDo(t, "POST", ssfAddSubjectPath, tok, map[string]any{"stream_id": sid,
		"subject": map[string]any{"format": "iss_sub", "iss": testIssuer, "sub": "usr_00000000000000000000000000"}}); code != 404 {
		t.Fatalf("unknown subject: %d", code)
	}
	if code, out := l.ssfDo(t, "POST", ssfVerifyPath, tok, map[string]any{"stream_id": sid, "state": "abc"}); code != 204 {
		t.Fatalf("verify: %d %v", code, out)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/ssf/streams", nil); code != 200 || len(out["streams"].([]any)) != 1 {
		t.Fatalf("admin streams: %d %v", code, out)
	}

	// 運営者がユーザーを止めると account-disabled を送る。
	l.advance(time.Second)
	if code, out := l.admin(t, "/v1/admin/users/"+uid+"/suspensions", owner, map[string]string{"category": "security_risk", "reason": "takeover"}); code != 201 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	code, polled := l.ssfDo(t, "POST", ssfPollPrefix+"/"+sid, tok, map[string]any{"returnImmediately": true})
	if code != 200 {
		t.Fatalf("poll: %d %v", code, polled)
	}
	got := map[string]map[string]any{}
	var acks []string
	for jti, s := range polled["sets"].(map[string]any) {
		p := setPayload(t, s.(string))
		if p["iss"] != testIssuer || p["aud"] != sa || p["jti"] != jti {
			t.Fatalf("SET claims: %v", p)
		}
		for ev, body := range p["events"].(map[string]any) {
			got[ev] = body.(map[string]any)
			got[ev]["sub_id"] = p["sub_id"]
		}
		acks = append(acks, jti)
	}
	if v := got[ssf.EventVerification]; v == nil || v["state"] != "abc" {
		t.Fatalf("verification: %v", got)
	}
	ad := got[ssf.EventAccountDisabled]
	if ad == nil || ad["reason"] != "hijacking" || ad["sub_id"].(map[string]any)["sub"] != uid {
		t.Fatalf("account-disabled: %v", got)
	}
	if code, out := l.ssfDo(t, "POST", ssfPollPrefix+"/"+sid, tok, map[string]any{"ack": acks}); code != 200 || len(out["sets"].(map[string]any)) != 0 {
		t.Fatalf("poll after ack: %d %v", code, out)
	}
	if code, out := l.ssfDo(t, "POST", ssfStatusPath, tok, map[string]any{"stream_id": sid, "status": "paused"}); code != 200 || out["status"] != "paused" {
		t.Fatalf("status: %d %v", code, out)
	}
	if code, _ := l.ssfDo(t, "DELETE", ssfStreamsPath+"?stream_id="+sid, tok, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := l.ssfDo(t, "GET", ssfStreamsPath+"?stream_id="+sid, tok, nil); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
}

func TestSSFReceiver(t *testing.T) {
	l := featureEnv(t, nil, feature.SSFReceiver)
	_, owner := l.operator(t, "root@example.com", role.RealmOwner)
	_, cookie := l.login(t, "sam@example.com")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := jwk.Import[jwk.Key](priv.Public())
	sk, _ := jwk.Import[jwk.Key](priv)
	_ = pub.Set(jwk.KeyIDKey, "k1")
	_ = sk.Set(jwk.KeyIDKey, "k1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	jwks, _ := json.Marshal(set)
	const iss, aud = "https://signals.example.net", testIssuer + "/ssf/receiver"

	_, support := l.operator(t, "help@example.com", role.RealmSupport)
	body := map[string]any{"name": "Idp", "issuer": iss, "jwks": json.RawMessage(jwks), "audience": []string{aud},
		"allowed_actions": []string{"revoke_sessions"}}
	if code, _ := l.admin(t, "/v1/admin/ssf/transmitters", support, body); code != 403 {
		t.Fatalf("support creates: %d", code)
	}
	if code, out := l.admin(t, "/v1/admin/ssf/transmitters", owner, map[string]any{"name": "x", "issuer": iss, "audience": []string{aud}}); code != 400 ||
		out["error"] != "invalid_transmitter" {
		t.Fatalf("no keys: %d %v", code, out)
	}
	code, tr := l.admin(t, "/v1/admin/ssf/transmitters", owner, body)
	if code != 201 || tr["push_token"] == nil || tr["push_endpoint"] != testIssuer+ssfReceiverPrefix+tr["id"].(string) {
		t.Fatalf("create transmitter: %d %v", code, tr)
	}
	push := tr["push_token"].(string)
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/ssf/transmitters/"+tr["id"].(string), nil); code != 200 || out["push_token"] != nil {
		t.Fatalf("get transmitter: %d %v", code, out)
	}

	sign := func(jti, audience string) []byte {
		claims, _ := json.Marshal(map[string]any{"iss": iss, "aud": audience, "iat": l.a.deps.Clock.Now().Unix(), "jti": jti,
			"sub_id": map[string]any{"format": "email", "email": "sam@example.com"},
			"events": map[string]any{ssf.EventSessionRevoked: map[string]any{"event_timestamp": l.a.deps.Clock.Now().Unix()}}})
		h := jws.NewHeaders()
		_ = h.Set(jws.TypeKey, ssf.SETType)
		b, err := jws.Sign(claims, jws.WithKey(jwa.ES256(), sk, jws.WithProtectedHeaders(h)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	send := func(b []byte, token string) (int, map[string]any) {
		r := httptest.NewRequest("POST", tr["push_endpoint"].(string)[len(testIssuer):], strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/secevent+jwt")
		r.Header.Set("Accept", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		l.a.PublicHandler().ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := send(sign("a", aud), ""); code != 401 || out["err"] != "authentication_failed" {
		t.Fatalf("no token: %d %v", code, out)
	}
	if code, out := send(sign("b", "https://other.example.com"), push); code != 400 || out["err"] != "invalid_audience" {
		t.Fatalf("wrong aud: %d %v", code, out)
	}
	if status, _ := l.me(t, cookie); status != 200 {
		t.Fatalf("session before signal: %d", status)
	}
	if code, out := send(sign("c", aud), push); code != 202 {
		t.Fatalf("push: %d %v", code, out)
	}
	if status, _ := l.me(t, cookie); status != 401 {
		t.Fatalf("session after session-revoked: %d", status)
	}
	if code, _ := send(sign("c", aud), push); code != 202 {
		t.Fatalf("replay: %d", code)
	}
	if code, out := l.adminDo(t, "GET", owner, "/v1/admin/audit-logs?type="+ssf.AuditSignalReceived, nil); code == 200 {
		if logs, _ := out["events"].([]any); logs != nil && len(logs) != 1 {
			t.Fatalf("signal audit: %v", out)
		}
	}
	if code, _ := l.adminDo(t, "POST", owner, "/v1/admin/ssf/transmitters/"+tr["id"].(string)+":delete", nil); code != 204 {
		t.Fatalf("delete transmitter: %d", code)
	}
	if code, _ := send(sign("d", aud), push); code != 401 {
		t.Fatalf("push after delete: %d", code)
	}
}
