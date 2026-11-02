package passkey

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/imohiyoko/iam/shared/port"
)

// FuzzDecode は保存したデータの読み取りが、どんな入力でも panic せず、読めたものは資格情報を持ち、書き戻して同じに読めることを確かめる。
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"credential_id":"Y3JlZA","public_key":"Y29zZQ","alg":-7,"sign_count":3,"transports":["usb"],"user_handle":"aA"}`))
	f.Add([]byte(`{"credential_id":"","public_key":"Y29zZQ"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, err := Decode(raw)
		if err != nil {
			return
		}
		if len(d.CredentialID) == 0 || len(d.PublicKey) == 0 {
			t.Fatalf("decoded data without a credential: %+v", d)
		}
		enc, err := Encode(d)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := Decode(enc); err != nil {
			t.Fatalf("round trip: %v", err)
		}
	})
}

// FuzzInput はログインと登録の確認の入力の読み取り（と、その後の go-webauthn の読み取り）が、どんな入力でも panic せず、
// 資格情報の無い入力を拒むことを確かめる。
func FuzzInput(f *testing.F) {
	f.Add([]byte(`{"credential":{"id":"x","rawId":"eA","type":"public-key","response":{}},"name":"Key"}`))
	f.Add([]byte(`{"credential":null}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		in, err := readInput(raw)
		if err != nil {
			return
		}
		if len(in.Credential) == 0 || string(in.Credential) == "null" {
			t.Fatalf("accepted an input without a credential: %q", raw)
		}
		_, _ = protocol.ParseCredentialRequestResponseBytes(in.Credential)
		_, _ = protocol.ParseCredentialCreationResponseBytes(in.Credential)
	})
}

// FuzzState はフローの状態の読み取りが、どんな入力でも panic せず、チャレンジの無いものと期限の切れたものを拒むことを確かめる。
func FuzzState(f *testing.F) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ok, _ := json.Marshal(map[string]any{"session": map[string]any{"challenge": "Y2hhbGxlbmdl"}, "expires_at": now.Add(time.Minute)})
	f.Add(ok)
	f.Add([]byte(`{"session":{},"expires_at":"2026-01-01T00:00:00Z"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		st, err := readState(port.MethodEnv{Now: now}, raw)
		if err != nil {
			return
		}
		if len(st.Session.Challenge) == 0 || !now.Before(st.ExpiresAt) {
			t.Fatalf("accepted state %+v", st)
		}
	})
}
