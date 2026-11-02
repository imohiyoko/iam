package openid4vp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/imohiyoko/iam/authn/method/openid4vp/sdjwt"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// transaction は応答を待つ要求（方式の EphemeralStore に、state のハッシュをキーに置く）。応答で取り出して消す。
type transaction struct {
	Nonce   string    `json:"nonce"`
	Flow    string    `json:"flow"`
	Purpose string    `json:"purpose"`
	Key     []byte    `json:"key"`
	Expires time.Time `json:"expires"`
}

// result は確かめた結果（暗号化して置く）。
type result struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	// ResponseCodeHash は同じ端末の流れでウォレットに返した response_code の SHA-256（base64url）。
	ResponseCodeHash string         `json:"response_code_hash,omitempty"`
	Issuer           string         `json:"issuer,omitempty"`
	VCT              string         `json:"vct,omitempty"`
	Subject          string         `json:"subject,omitempty"`
	Email            string         `json:"email,omitempty"`
	Attributes       map[string]any `json:"attributes,omitempty"`
	VerifiedAt       time.Time      `json:"verified_at"`
}

func resultAAD(state string) []byte { return []byte(hashKey("openid4vp.result.v1:", state)) }

// sealResult は結果をフローの鍵で暗号化する（AES-256-GCM。AAD は state のハッシュ）。
func sealResult(key []byte, state string, r result) ([]byte, error) {
	pt, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, pt, resultAAD(state)), nil
}

func openResult(key []byte, state string, sealed []byte) (result, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return result{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result{}, err
	}
	if len(sealed) < gcm.NonceSize() {
		return result{}, errors.New("openid4vp: sealed result too short")
	}
	pt, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], resultAAD(state))
	if err != nil {
		return result{}, err
	}
	var r result
	if err := json.Unmarshal(pt, &r); err != nil {
		return result{}, err
	}
	return r, nil
}

// Endpoint はウォレットからの要求を受ける（ADR 0108）。
//
//   - GET request?id=…：署名した要求のオブジェクト（application/oauth-authz-req+jwt）
//   - POST response：direct_post の応答（state と vp_token か error）。確かめた結果を暗号化して置く
func (m Method) Endpoint(ctx context.Context, env port.MethodEnv, req port.MethodHTTPRequest) (port.MethodHTTPResponse, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodHTTPResponse{}, errs.New(errs.KindNotFound, "openid4vp endpoint")
	}
	switch {
	case req.Endpoint == EndpointRequest && req.HTTPMethod == http.MethodGet:
		return r.requestObject(ctx, req.Query)
	case req.Endpoint == EndpointResponse && req.HTTPMethod == http.MethodPost:
		return r.response(ctx, env, req.Form)
	}
	return port.MethodHTTPResponse{}, errs.New(errs.KindNotFound, "openid4vp endpoint")
}

// single は form の name がちょうど 1 つならその値を返す（同じ名前が 2 つあるものは、どちらを読むかで食い違うので拒む）。
func single(v url.Values, name string) (string, bool) {
	x := v[name]
	if len(x) != 1 {
		return "", false
	}
	return x[0], true
}

func (r *runtime) requestObject(ctx context.Context, q url.Values) (port.MethodHTTPResponse, error) {
	id, ok := single(q, "id")
	if !ok || id == "" {
		return port.MethodHTTPResponse{}, errInvalid
	}
	jwt, ok, err := r.store.Get(ctx, requestKey(id))
	if err != nil {
		return port.MethodHTTPResponse{}, err
	}
	if !ok {
		return port.MethodHTTPResponse{}, errs.New(errs.KindNotFound, "openid4vp request")
	}
	return port.MethodHTTPResponse{Status: http.StatusOK, ContentType: "application/oauth-authz-req+jwt", Body: jwt}, nil
}

// maxReason は監査ログに残す拒否の理由の長さの上限。
const maxReason = 256

// errorCodeRE はウォレットが返す error の形（監査ログに残すので、形の決まったものだけを受ける）。
var errorCodeRE = regexp.MustCompile(`^[a-z_]{1,64}$`)

func jsonBody(status int, v any) (port.MethodHTTPResponse, error) {
	b, err := json.Marshal(v)
	return port.MethodHTTPResponse{Status: status, ContentType: "application/json", Body: b}, err
}

// response は direct_post の応答を受ける。state のトランザクションを取り出し（1 回だけ）、提示を確かめ、結果を暗号化して置く。
// 失敗も結果として置き（ブラウザの complete を失敗で終わらせる）、ウォレットには 400 を返す。
func (r *runtime) response(ctx context.Context, env port.MethodEnv, form url.Values) (port.MethodHTTPResponse, error) {
	state, ok := single(form, "state")
	if !ok || state == "" {
		return port.MethodHTTPResponse{}, errInvalid
	}
	raw, ok, err := r.store.Take(ctx, txKey(state))
	if err != nil {
		return port.MethodHTTPResponse{}, err
	}
	if !ok {
		return port.MethodHTTPResponse{}, errs.New(errs.KindNotFound, "openid4vp transaction")
	}
	var tx transaction
	if err := json.Unmarshal(raw, &tx); err != nil || len(tx.Key) != 32 {
		return port.MethodHTTPResponse{}, fmt.Errorf("openid4vp: transaction: %v", err)
	}
	now := r.clock.Now()
	res := result{VerifiedAt: now}
	var reason string
	switch {
	case !now.Before(tx.Expires):
		reason = "request expired"
	case form.Has("error"):
		code, _ := single(form, "error")
		if !errorCodeRE.MatchString(code) {
			code = "invalid"
		}
		reason = "wallet returned error " + code
	default:
		vp, ok := single(form, "vp_token")
		if !ok {
			reason = "vp_token is missing"
			break
		}
		presentation, err := ParseVPToken(vp)
		if err != nil {
			reason = err.Error()
			break
		}
		if err := r.verify(presentation, tx, now, &res); err != nil {
			reason = err.Error()
		}
	}
	// 理由には攻撃者の値（typ など）が混じりうるので、長さを抑えて残す。
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	res.OK = reason == ""
	res.Reason = reason
	var code string
	if res.OK && tx.Flow == FlowSameDevice {
		var err error
		if code, _, err = random(32); err != nil {
			return port.MethodHTTPResponse{}, err
		}
		h := sha256.Sum256([]byte(code))
		res.ResponseCodeHash = base64.RawURLEncoding.EncodeToString(h[:])
	}
	sealed, err := sealResult(tx.Key, state, res)
	if err != nil {
		return port.MethodHTTPResponse{}, err
	}
	// 結果は、ブラウザが受け取るまでの間（要求の期限まで。短くても 1 分）だけ置く。
	if err := r.store.Set(ctx, resultKey(state), sealed, max(tx.Expires.Sub(now), time.Minute)); err != nil {
		return port.MethodHTTPResponse{}, err
	}
	if !res.OK {
		out, err := jsonBody(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		out.Events = []port.MethodEvent{{Type: "presentation_rejected", Failure: true,
			Details: map[string]any{"reason": reason, "flow": tx.Flow, "purpose": tx.Purpose}}}
		return out, err
	}
	body := map[string]string{}
	if tx.Flow == FlowSameDevice {
		body["redirect_uri"] = r.p.sameDeviceURI + "#response_code=" + code
	}
	out, err := jsonBody(http.StatusOK, body)
	out.Events = []port.MethodEvent{{Type: "presentation_received",
		Details: map[string]any{"issuer": res.Issuer, "vct": res.VCT, "flow": tx.Flow, "purpose": tx.Purpose}}}
	return out, err
}

// ParseVPToken は vp_token（JSON のオブジェクト）から提示を 1 つ取り出す。キーは QueryID だけ、値は文字列 1 つの配列に限る。
func ParseVPToken(s string) (string, error) {
	if len(s) > sdjwt.MaxSize*2 {
		return "", errors.New("vp_token too large")
	}
	m, err := sdjwt.DecodeObject([]byte(s))
	if err != nil {
		return "", errors.New("vp_token is not a JSON object")
	}
	if len(m) != 1 {
		return "", errors.New("vp_token must answer exactly one credential query")
	}
	v, ok := m[QueryID].([]any)
	if !ok || len(v) != 1 {
		return "", errors.New("vp_token must hold one presentation")
	}
	p, ok := v[0].(string)
	if !ok || p == "" {
		return "", errors.New("vp_token presentation is not a string")
	}
	return p, nil
}

// verify は提示を確かめ、結果に発行者・vct・結び付けの値・属性を入れる。
func (r *runtime) verify(presentation string, tx transaction, now time.Time, res *result) error {
	cred, err := sdjwt.Verify(presentation, sdjwt.Options{Now: now, Skew: clockSkew, KBMaxAge: r.p.kbMaxAge, Audience: r.clientID, Nonce: tx.Nonce,
		IssuerKey: func(iss string, h jose.Header) (any, error) {
			is := r.p.issuers[iss]
			if is == nil {
				return nil, errors.New("untrusted issuer")
			}
			return is.key(h, now)
		}})
	if err != nil {
		return err
	}
	is := r.p.issuers[cred.Issuer]
	if !slices.Contains(r.p.vcts, cred.VCT) || (len(is.vcts) > 0 && !slices.Contains(is.vcts, cred.VCT)) {
		return fmt.Errorf("vct %q is not accepted from %s", cred.VCT, cred.Issuer)
	}
	if cred.HasStatus && !r.p.ignoreStatus {
		return errors.New("credential has a status reference that cannot be checked")
	}
	subject, err := scalarAt(cred.Claims, r.p.subject)
	if err != nil {
		return fmt.Errorf("subject_claim: %w", err)
	}
	attrs := map[string]any{}
	for name, path := range r.p.attributes {
		v, err := claimAt(cred.Claims, path)
		if err != nil {
			return fmt.Errorf("attribute %s: %w", name, err)
		}
		attrs[name] = v
	}
	if is.linkByEmail {
		// メールアドレスは結び付けの無いときの引き当てにだけ使う。無ければ引き当てない。
		if v, err := claimAt(cred.Claims, r.p.email); err == nil {
			res.Email, _ = v.(string)
		}
	}
	res.Issuer, res.VCT, res.Subject = cred.Issuer, cred.VCT, subject
	if len(attrs) > 0 {
		res.Attributes = attrs
	}
	return nil
}

// claimAt は path の値を返す（文字列は名前、数は配列の位置）。無ければエラー。
func claimAt(claims map[string]any, path []any) (any, error) {
	var cur any = claims
	for _, e := range path {
		switch e := e.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, errors.New("claim not found")
			}
			if cur, ok = m[e]; !ok {
				return nil, errors.New("claim not found")
			}
		case int:
			a, ok := cur.([]any)
			if !ok || e >= len(a) {
				return nil, errors.New("claim not found")
			}
			cur = a[e]
		default:
			return nil, errors.New("invalid path")
		}
	}
	return cur, nil
}

// scalarAt は path の値を文字列で返す（文字列か数だけ。空は受けない）。
func scalarAt(claims map[string]any, path []any) (string, error) {
	v, err := claimAt(claims, path)
	if err != nil {
		return "", err
	}
	switch v := v.(type) {
	case string:
		if v == "" {
			return "", errors.New("claim is empty")
		}
		return v, nil
	case json.Number:
		return v.String(), nil
	}
	return "", errors.New("claim is not a string or a number")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
