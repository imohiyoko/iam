// Package openid4vp は OpenID for Verifiable Presentations 1.0 の検証者としての認証方式（ADR 0108）。
//
// begin でトランザクション（state・nonce）を作り、ウォレットを開く URL（authorization_request）を返す。ウォレットは提示
// （key binding 付きの SD-JWT VC）を response_uri（方式のエンドポイント。direct_post）に送り、方式はそこで確かめた結果を、
// フローの状態（コアが封をする）にだけある鍵で暗号化して方式の EphemeralStore に置く。ブラウザは complete で結果を受け取り
// （届くまで 202）、同じ端末の流れでは、ウォレットが戻した response_code を添える。確かめた値（subject_claim）で、本人が
// 登録した結び付け（authn_credentials。検索キーはブラインドインデックス）を引く。
//
// セキュリティ上重要なコード（13.2）。失敗は理由を外に返さず（4.9）、分からないときは拒む（fail-closed）。
package openid4vp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = "openid4vp"

// Feature はフィーチャー openid4vp の宣言（既定オフ。ADR 0089、0108）。features/openid4vp を import すると登録される。
var Feature = feature.Feature{Name: feature.OpenID4VP, DataVersion: 1}

// エンドポイントの名前（/v1/login/methods/openid4vp/endpoints/{endpoint}）。
const (
	EndpointRequest  = "request"
	EndpointResponse = "response"
)

// ErrLimit は結び付けが上限に達していること。
var ErrLimit = errs.WithCode(errs.KindConflict, "credential_limit", "too many openid4vp credentials")

// ErrExists は確かめた値が既に誰かに結び付いていること。
var ErrExists = errs.WithCode(errs.KindConflict, "credential_exists", "openid4vp credential already enrolled")

var errInvalid = errs.WithCode(errs.KindInvalid, "invalid_request", "openid4vp: invalid request")

var errNotConfigured = errors.New("openid4vp: method is not configured")

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）が、監査ログ（login.failed の reason）には残る。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "openid4vp: "+reason)
}

// Method は OpenID4VP の port.Authenticator。登録する値（features/openid4vp）は設定を持たず、Setup で realm ごとに組み立てる。
// 設定の無い Method は何も通さない（fail-closed）。
type Method struct {
	rt *runtime
}

type runtime struct {
	p           *policy
	store       port.EphemeralStore
	clock       clock.Clock
	responseURI string
	requestURI  string
	clientID    string
}

var (
	_ port.Authenticator             = Method{}
	_ port.ConfigurableAuthenticator = Method{}
	_ port.EndpointAuthenticator     = Method{}
)

// Info は方式の宣言。ウォレットの鍵の所持（key binding）を確かめる所持の要素で、1要素目と2要素目に使える。鍵がハードウェアに
// あるかと、ウォレットが本人を確かめたかは検証者から分からないので、amr は swk、AAL の上限は 2（ADR 0093）。応答はウォレットから届く。
func (Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Feature: feature.OpenID4VP, Kind: port.FactorPossession, AMR: []string{"swk"}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageFirstFactor, port.UsageSecondFactor}, DataVersion: 1, OutOfBand: true}
}

// Setup は `methods.openid4vp.realms.<realm の slug>` を読む。その realm の設定が無ければ nil（方式を動かさない）。他の realm の
// 設定も確かめる（realm を後から作ったときに初めて誤りに気づかないように）。
func (Method) Setup(_ context.Context, s port.MethodSetup) (port.Authenticator, error) {
	var c Config
	if s.Decode != nil {
		if err := s.Decode(&c); err != nil {
			return nil, fmt.Errorf("openid4vp: %w", err)
		}
	}
	if len(c.Realms) == 0 {
		return nil, nil
	}
	if s.Ephemeral == nil || s.Clock == nil {
		return nil, errors.New("openid4vp: setup is incomplete")
	}
	base := strings.TrimSuffix(s.BaseURL, "/")
	if base == "" {
		return nil, errors.New("openid4vp: server.public_url is required")
	}
	for name, rc := range c.Realms {
		if name == s.RealmSlug {
			continue
		}
		// 他の realm の URL は分からないので、形の確かめには既定の realm の URL を使う。
		if _, err := newPolicy(rc, base+endpointPath(EndpointResponse), s.Dev); err != nil {
			return nil, fmt.Errorf("openid4vp: realm %s: %w", name, err)
		}
	}
	rc, ok := c.Realms[s.RealmSlug]
	if !ok {
		return nil, nil
	}
	return New(rc, base, s.Ephemeral, s.Clock, s.Dev)
}

// endpointPath は方式のエンドポイントのパス。
func endpointPath(ep string) string { return "/v1/login/methods/" + Name + "/endpoints/" + ep }

// New は realm の設定から方式を作る。base は realm の公開の URL。
func New(rc RealmConfig, base string, store port.EphemeralStore, clk clock.Clock, dev bool) (Method, error) {
	responseURI := base + endpointPath(EndpointResponse)
	p, err := newPolicy(rc, responseURI, dev)
	if err != nil {
		return Method{}, fmt.Errorf("openid4vp: realm: %w", err)
	}
	return Method{rt: &runtime{p: p, store: store, clock: clk, responseURI: responseURI, requestURI: base + endpointPath(EndpointRequest),
		clientID: p.clientID(responseURI)}}, nil
}

func (m Method) runtime() (*runtime, error) {
	if m.rt == nil {
		return nil, errNotConfigured
	}
	return m.rt, nil
}

// 用途。
const (
	purposeLogin  = "login"
	purposeEnroll = "enroll"
)

// flowState はフローの状態（コアが封をして預かる）。Key は結果を暗号化する鍵で、ここと、応答が届くまでのトランザクションにだけある。
type flowState struct {
	State   string    `json:"state"`
	Key     []byte    `json:"key"`
	Flow    string    `json:"flow"`
	Purpose string    `json:"purpose"`
	Expires time.Time `json:"expires"`
}

// data は結び付け（コアがユーザーのデータ鍵で暗号化して置く）。
type data struct {
	Issuer      string         `json:"issuer"`
	VCT         string         `json:"vct"`
	SubjectPath []any          `json:"subject_path"`
	Subject     string         `json:"subject"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	VerifiedAt  time.Time      `json:"verified_at"`
}

// summary は本人に返す結び付けの要約（結び付けの値そのものは返さない）。
type summary struct {
	Issuer     string         `json:"issuer"`
	VCT        string         `json:"vct"`
	Attributes map[string]any `json:"attributes,omitempty"`
	VerifiedAt time.Time      `json:"verified_at"`
}

// beginInput は begin・enroll-begin の本文。
type beginInput struct {
	Flow string `json:"flow"`
}

// completeInput は complete・enroll-complete の本文。
type completeInput struct {
	ResponseCode string `json:"response_code"`
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 || string(raw) == "null" {
		return v, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, errInvalid
	}
	return v, nil
}

func random(n int) (string, []byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(b), b, nil
}

func hashKey(prefix, v string) string {
	h := sha256.Sum256([]byte(v))
	return prefix + base64.RawURLEncoding.EncodeToString(h[:])
}

func txKey(state string) string     { return hashKey("tx:", state) }
func resultKey(state string) string { return hashKey("res:", state) }
func requestKey(id string) string   { return hashKey("req:", id) }

// Begin はログイン（1要素目・2要素目）の提示の要求を作る。2要素目は、本人に結び付けが無ければ errs.NotFound。
func (m Method) Begin(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodChallenge, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if env.UserID != "" {
		cs, err := env.Credentials.List(ctx, env.UserID)
		if err != nil {
			return port.MethodChallenge{}, err
		}
		if len(cs) == 0 {
			return port.MethodChallenge{}, errs.New(errs.KindNotFound, "openid4vp credential")
		}
	}
	return r.begin(ctx, env, in, purposeLogin)
}

// EnrollBegin は結び付けの登録のための提示の要求を作る。
func (m Method) EnrollBegin(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodChallenge, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if err := r.checkLimit(ctx, env, env.UserID); err != nil {
		return port.MethodChallenge{}, err
	}
	return r.begin(ctx, env, in, purposeEnroll)
}

func (r *runtime) begin(ctx context.Context, env port.MethodEnv, in port.MethodRequest, purpose string) (port.MethodChallenge, error) {
	bi, err := decode[beginInput](in.Payload)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	flow := bi.Flow
	if flow == "" {
		flow = r.p.flows[0]
	}
	if !slices.Contains(r.p.flows, flow) {
		return port.MethodChallenge{}, errInvalid
	}
	state, _, err := random(32)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	nonce, _, err := random(32)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	_, key, err := random(32)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	expires := env.Now.Add(r.p.requestTTL)
	tx := transaction{Nonce: nonce, Flow: flow, Purpose: purpose, Key: key, Expires: expires}
	authz, reqID, reqJWT, err := r.authorizationRequest(state, nonce, env.Now)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if reqJWT != "" {
		if err := r.store.Set(ctx, requestKey(reqID), []byte(reqJWT), r.p.requestTTL); err != nil {
			return port.MethodChallenge{}, err
		}
	}
	raw, err := json.Marshal(tx) // #nosec G117 -- 結果の鍵は方式の EphemeralStore に、応答が届くまでだけ置く
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if err := r.store.Set(ctx, txKey(state), raw, r.p.requestTTL); err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(map[string]any{"authorization_request": authz, "flow": flow, "expires_at": expires})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	st, err := json.Marshal(flowState{State: state, Key: key, Flow: flow, Purpose: purpose, Expires: expires}) // #nosec G117 -- コアが封をする
	return port.MethodChallenge{Payload: out, State: st}, err
}

// awaited は、ウォレットから届いた結果を取り出す。まだ届いていなければ port.ErrMethodPending、期限切れなら拒む。
// 同じ端末の流れでは response_code を確かめる。結果は取り出して1回だけ使う。
func (r *runtime) awaited(ctx context.Context, env port.MethodEnv, in port.MethodRequest, purpose string) (result, error) {
	var st flowState
	if err := json.Unmarshal(in.State, &st); err != nil || st.State == "" || len(st.Key) != 32 || st.Purpose != purpose {
		return result{}, fmt.Errorf("openid4vp: flow state: %v", err)
	}
	ci, err := decode[completeInput](in.Payload)
	if err != nil {
		return result{}, err
	}
	sealed, ok, err := r.store.Get(ctx, resultKey(st.State))
	if err != nil {
		return result{}, err
	}
	if !ok {
		if env.Now.After(st.Expires) {
			return result{}, rejected("request expired without a response")
		}
		_, pending, err := r.store.Get(ctx, txKey(st.State))
		if err != nil {
			return result{}, err
		}
		if !pending {
			return result{}, rejected("request expired without a response")
		}
		return result{}, port.ErrMethodPending
	}
	res, err := openResult(st.Key, st.State, sealed)
	if err != nil {
		return result{}, rejected("result does not belong to this flow")
	}
	if st.Flow == FlowSameDevice {
		h := sha256.Sum256([]byte(ci.ResponseCode))
		want, _ := base64.RawURLEncoding.DecodeString(res.ResponseCodeHash)
		if ci.ResponseCode == "" || subtle.ConstantTimeCompare(h[:], want) != 1 {
			return result{}, rejected("response_code mismatch")
		}
	}
	if _, ok, err := r.store.Take(ctx, resultKey(st.State)); err != nil {
		return result{}, err
	} else if !ok {
		return result{}, rejected("result already used")
	}
	if !res.OK {
		return result{}, rejected("presentation rejected: " + res.Reason)
	}
	return res, nil
}

func (r *runtime) checkLimit(ctx context.Context, env port.MethodEnv, userID string) error {
	cs, err := env.Credentials.List(ctx, userID)
	if err != nil {
		return err
	}
	if len(cs) >= r.p.maxCredentials {
		return ErrLimit
	}
	return nil
}

// dataOf は結果から結び付けのデータを作る。
func (r *runtime) dataOf(res result) ([]byte, error) {
	return json.Marshal(data{Issuer: res.Issuer, VCT: res.VCT, SubjectPath: r.p.subject, Subject: res.Subject, Attributes: res.Attributes,
		VerifiedAt: res.VerifiedAt})
}

// lookupOf は結び付けの検索キー（発行者・path・値。コアがブラインドインデックスにする）。
func lookupOf(iss string, path []any, value string) string {
	b, err := json.Marshal([]any{iss, path, value})
	if err != nil {
		return ""
	}
	return string(b)
}

// Complete は届いた結果で、結び付けた本人を引く。結び付けが無く、発行者が link_by_email なら、確認済みのメールの本人に
// 結び付けを作る（1要素目だけ）。2要素目は本人の結び付けに限る。ログインのたびに属性を新しい提示の値で置き換える。
func (m Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodResult{}, err
	}
	res, err := r.awaited(ctx, env, in, purposeLogin)
	if err != nil {
		return port.MethodResult{}, err
	}
	lookup := lookupOf(res.Issuer, r.p.subject, res.Subject)
	raw, err := r.dataOf(res)
	if err != nil {
		return port.MethodResult{}, err
	}
	c, err := env.Credentials.FindByLookup(ctx, lookup)
	if errors.Is(err, errs.NotFound) {
		c, err = r.link(ctx, env, res, lookup, raw)
		if err != nil {
			return port.MethodResult{}, err
		}
		return port.MethodResult{Credential: c}, nil
	}
	if err != nil {
		return port.MethodResult{}, err
	}
	var d data
	if err := json.Unmarshal(c.Data, &d); err != nil {
		return port.MethodResult{}, fmt.Errorf("openid4vp: data: %w", err)
	}
	if lookupOf(d.Issuer, d.SubjectPath, d.Subject) != lookup {
		return port.MethodResult{}, rejected("enrolled under another subject claim")
	}
	if env.UserID != "" && c.UserID != env.UserID {
		return port.MethodResult{}, rejected("credential bound to another user")
	}
	c, err = env.Credentials.Update(ctx, c, raw)
	if errors.Is(err, errs.Conflict) {
		return port.MethodResult{}, rejected("credential changed during the login")
	}
	if err != nil {
		return port.MethodResult{}, err
	}
	return port.MethodResult{Credential: c}, nil
}

// link は、結び付けの無い提示を、発行者が link_by_email なら確認済みのメールの本人に結び付ける（ADR 0108）。それ以外は拒む。
func (r *runtime) link(ctx context.Context, env port.MethodEnv, res result, lookup string, raw []byte) (port.MethodCredential, error) {
	is := r.p.issuers[res.Issuer]
	if is == nil || !is.linkByEmail || env.UserID != "" || env.Usage != port.UsageFirstFactor || env.Users == nil || res.Email == "" {
		return port.MethodCredential{}, rejected("credential not enrolled")
	}
	uid, err := env.Users.LoginUser(ctx, res.Email)
	if errors.Is(err, errs.NotFound) {
		return port.MethodCredential{}, rejected("no user with the verified email")
	}
	if err != nil {
		return port.MethodCredential{}, err
	}
	if err := r.checkLimit(ctx, env, uid); err != nil {
		return port.MethodCredential{}, rejected("credential limit reached")
	}
	c, err := env.Credentials.Create(ctx, uid, lookup, raw)
	if errors.Is(err, errs.Conflict) {
		return port.MethodCredential{}, rejected("credential enrolled concurrently")
	}
	return c, err
}

// EnrollComplete は届いた結果で、本人に結び付けを作る（コアのトランザクションの中。ネットワークは使わない）。まだ届いて
// いなければ port.ErrMethodPending（コアは 202 を返す）。値が既に誰かに結び付いていれば ErrExists。
func (m Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	r, err := m.runtime()
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	res, err := r.awaited(ctx, env, in, purposeEnroll)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	if err := r.checkLimit(ctx, env, env.UserID); err != nil {
		return port.MethodEnrollment{}, err
	}
	raw, err := r.dataOf(res)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	c, err := env.Credentials.Create(ctx, env.UserID, lookupOf(res.Issuer, r.p.subject, res.Subject), raw)
	if errors.Is(err, errs.Conflict) {
		return port.MethodEnrollment{}, ErrExists
	}
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	out, err := json.Marshal(summary{Issuer: res.Issuer, VCT: res.VCT, Attributes: res.Attributes, VerifiedAt: res.VerifiedAt})
	return port.MethodEnrollment{Credential: c, Payload: out}, err
}

// Revoke は方式の外に片付けるものが無いので何もしない（資格情報そのものの失効は発行者が行う）。
func (Method) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }
