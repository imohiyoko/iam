// Package x509 は X.509 のクライアント証明書（スマートカード（PIV・CAC）を含む）の認証方式（ADR 0103）。
//
// 証明書はコアが mTLS の専用の待ち受けか、設定で信じたプロキシのヘッダーから取り出して MethodEnv.ClientCertificates で渡す
// （秘密鍵の所持は TLS のハンドシェイクで確かめてある）。方式は realm ごとのトラストアンカーへの連鎖・期限・鍵用途と拡張鍵用途・
// 失効（OCSP・CRL）を確かめ、設定の規則（証明書の指紋・SAN の UPN・SAN のメール・主体の DN）の値で、本人が登録した認証情報
// （authn_credentials。検索キーはブラインドインデックス）を引く。失効の確認はネットワークを使うので Preflight で行う。
//
// セキュリティ上重要なコード（13.2）。失敗は理由を外に返さず（4.9）、分からないときは拒む（fail-closed）。
package x509

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = "x509"

// Feature はフィーチャー x509 の宣言（既定オフ。ADR 0089）。features/x509 を import すると登録される。
var Feature = feature.Feature{Name: feature.X509, DataVersion: 1}

// ErrLimit は登録した証明書が上限に達していること。
var ErrLimit = errs.WithCode(errs.KindConflict, "credential_limit", "too many x509 credentials")

// ErrExists は証明書（マッピングの値）が既に誰かに登録されていること。
var ErrExists = errs.WithCode(errs.KindConflict, "credential_exists", "x509 certificate already enrolled")

// errNoCertificate は登録の開始で証明書が無いこと（本人に返してよい）。
var errNoCertificate = errs.WithCode(errs.KindInvalid, "client_certificate_required", "x509: no client certificate")

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）が、監査ログ（login.failed の reason）には残る。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "x509: "+reason)
}

// Method は X.509 の port.Authenticator。登録する値（features/x509）は設定を持たず、Configure で realm ごとに組み立てる。
// 設定の無い Method は何も通さない。
type Method struct {
	p   *policy
	rev *revoker
}

var (
	_ port.Authenticator  = (*Method)(nil)
	_ port.Preflighter    = (*Method)(nil)
	_ method.Configurable = (*Method)(nil)
)

// New は realm の設定から方式を作る。client は OCSP・CRL の取得に使う（nil なら既定）。
func New(rc RealmConfig, client *http.Client) (*Method, error) {
	p, err := newPolicy(rc)
	if err != nil {
		return nil, fmt.Errorf("x509: %w", err)
	}
	return &Method{p: p, rev: newRevoker(p.revocation, client)}, nil
}

// Configure は `methods.x509.realms.<realm>` を読む。その realm の設定が無ければ nil（方式を動かさない）。
func (*Method) Configure(realm string, decode func(any) error) (port.Authenticator, error) {
	var c Config
	if err := decode(&c); err != nil {
		return nil, fmt.Errorf("x509: %w", err)
	}
	// 他の realm の設定も確かめる（realm を後から作ったときに初めて誤りに気づかないように）。
	for name, rc := range c.Realms {
		if name == realm {
			continue
		}
		if _, err := newPolicy(rc); err != nil {
			return nil, fmt.Errorf("x509: realm %s: %w", name, err)
		}
	}
	rc, ok := c.Realms[realm]
	if !ok {
		return nil, nil
	}
	m, err := New(rc, nil)
	if err != nil {
		return nil, fmt.Errorf("realm %s: %w", realm, err)
	}
	return m, nil
}

// Info は方式の宣言。所持の要素で、1要素目と2要素目に使える。AAL の上限は、ハードウェアの CA を設定していれば 3、
// そうでなければ 2（鍵の置き場所が分からない証明書は、ほかの要素と合わせても AAL2 まで。ADR 0093）。
func (m *Method) Info() port.MethodInfo {
	aal := 2
	if m.p != nil && len(m.p.hardware) > 0 {
		aal = 3
	}
	return port.MethodInfo{Name: Name, Feature: feature.X509, Kind: port.FactorPossession, AMR: []string{"pop"}, AAL: aal,
		Usages: []port.MethodUsage{port.UsageFirstFactor, port.UsageSecondFactor}, DataVersion: 1}
}

// data は登録した証明書（コアが暗号化して置く）。マッピングが指紋でなければ、同じ値を持つ更新後の証明書でも通る。
type data struct {
	Rule        string    `json:"rule"`
	Identifier  string    `json:"identifier"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotAfter    time.Time `json:"not_after"`
}

// flowState はフローの状態。フローを始めた証明書に結び付ける（別の証明書で完了させない）。
type flowState struct {
	Fingerprint string `json:"fingerprint"`
}

// summary は本人に返す証明書の要約。
type summary struct {
	Fingerprint string    `json:"fingerprint"`
	Mapping     string    `json:"mapping"`
	Identifier  string    `json:"identifier"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotAfter    time.Time `json:"not_after"`
	Hardware    bool      `json:"hardware"`
}

func (m *Method) configured() error {
	if m == nil || m.p == nil {
		return rejected("method is not configured")
	}
	return nil
}

func leafFingerprint(env port.MethodEnv) (string, error) {
	if len(env.ClientCertificates) == 0 || len(env.ClientCertificates[0]) == 0 {
		return "", rejected("no client certificate")
	}
	return Fingerprint(env.ClientCertificates[0]), nil
}

func sameFingerprint(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Begin はログインを始める。証明書が無ければ拒む。確かめは Complete（Preflight）で行う。
func (m *Method) Begin(_ context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if err := m.configured(); err != nil {
		return port.MethodChallenge{}, err
	}
	fp, err := leafFingerprint(env)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	st, err := json.Marshal(flowState{Fingerprint: fp})
	return port.MethodChallenge{State: st}, err
}

// Preflight は連鎖・用途・失効を確かめ、マッピングの値を求める（Storage のトランザクションの外。ネットワークを使う）。
func (m *Method) Preflight(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) ([]byte, error) {
	if err := m.configured(); err != nil {
		return nil, err
	}
	certs, err := parseChain(env.ClientCertificates)
	if err != nil {
		return nil, err
	}
	chain, err := m.p.verify(certs, env.Now)
	if err != nil {
		return nil, err
	}
	if err := m.rev.checkChain(ctx, chain, env.Now); err != nil {
		if errors.Is(err, errRevoked) || errors.Is(err, errUnknown) {
			return nil, rejected(fmt.Sprintf("%v (certificate %s)", err, Fingerprint(certs[0].Raw)))
		}
		return nil, err
	}
	v, err := m.summarize(chain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (m *Method) summarize(chain []*x509.Certificate) (verified, error) {
	leaf := chain[0]
	ident, err := m.p.identifier(leaf)
	if err != nil {
		return verified{}, err
	}
	hw, pin := m.p.hardwareOf(chain)
	return verified{Fingerprint: Fingerprint(leaf.Raw), Lookup: lookupOf(m.p.mapping, ident), Identifier: ident, Hardware: hw, PIN: pin,
		Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.Text(16), NotAfter: leaf.NotAfter}, nil
}

// checked は Preflight の結果を読み、今の要求の証明書と、フローを始めた証明書（state）に一致することを確かめる。
func checked(env port.MethodEnv, in port.MethodRequest) (verified, error) {
	var v verified
	if len(in.Preflight) == 0 || json.Unmarshal(in.Preflight, &v) != nil {
		return v, errors.New("x509: missing preflight")
	}
	fp, err := leafFingerprint(env)
	if err != nil {
		return v, err
	}
	var st flowState
	if err := json.Unmarshal(in.State, &st); err != nil {
		return v, fmt.Errorf("x509: flow state: %w", err)
	}
	if !sameFingerprint(v.Fingerprint, fp) || !sameFingerprint(st.Fingerprint, fp) {
		return v, rejected("certificate changed during the flow")
	}
	return v, nil
}

// amr は確かめた証明書の amr。ハードウェアの CA の証明書は sc（PIN が要ると保証されていれば pin も。1要素目なら mfa）、
// そうでなければ pop（鍵の置き場所を問わない）。AAL は amr からコアが求める（ADR 0093）。
func amr(v verified, u port.MethodUsage) []string {
	switch {
	case v.Hardware && v.PIN && u == port.UsageFirstFactor:
		return []string{"sc", "pin", "mfa"}
	case v.Hardware && v.PIN:
		return []string{"sc", "pin"}
	case v.Hardware:
		return []string{"sc"}
	}
	return []string{"pop"}
}

// Complete は確かめた証明書のマッピングの値で、登録した認証情報を引く。2要素目なら本人のものに限る。
func (m *Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	if err := m.configured(); err != nil {
		return port.MethodResult{}, err
	}
	v, err := checked(env, in)
	if err != nil {
		return port.MethodResult{}, err
	}
	c, err := env.Credentials.FindByLookup(ctx, v.Lookup)
	if errors.Is(err, errs.NotFound) {
		return port.MethodResult{}, rejected("certificate not enrolled (certificate " + v.Fingerprint + ")")
	}
	if err != nil {
		return port.MethodResult{}, err
	}
	var d data
	if err := json.Unmarshal(c.Data, &d); err != nil {
		return port.MethodResult{}, fmt.Errorf("x509: data: %w", err)
	}
	if d.Rule != m.p.mapping || lookupOf(d.Rule, d.Identifier) != v.Lookup {
		return port.MethodResult{}, rejected("enrolled under another mapping rule")
	}
	if env.UserID != "" && c.UserID != env.UserID {
		return port.MethodResult{}, rejected("certificate enrolled by another user")
	}
	return port.MethodResult{Credential: c, AMR: amr(v, env.Usage)}, nil
}

// EnrollBegin は登録を始める。証明書の連鎖と用途を確かめ（失効は完了で確かめる）、何を登録するかを本人に返す。
func (m *Method) EnrollBegin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if err := m.configured(); err != nil {
		return port.MethodChallenge{}, err
	}
	certs, err := parseChain(env.ClientCertificates)
	if errors.Is(err, errs.AuthenticationFailed) && len(env.ClientCertificates) == 0 {
		return port.MethodChallenge{}, errNoCertificate
	}
	if err != nil {
		return port.MethodChallenge{}, errs.WithCode(errs.KindInvalid, "certificate_invalid", err.Error())
	}
	chain, err := m.p.verify(certs, env.Now)
	if err != nil {
		return port.MethodChallenge{}, errs.WithCode(errs.KindInvalid, "certificate_invalid", err.Error())
	}
	v, err := m.summarize(chain)
	if err != nil {
		return port.MethodChallenge{}, errs.WithCode(errs.KindInvalid, "certificate_invalid", err.Error())
	}
	if err := m.checkLimit(ctx, env); err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(m.summary(v))
	if err != nil {
		return port.MethodChallenge{}, err
	}
	st, err := json.Marshal(flowState{Fingerprint: v.Fingerprint})
	return port.MethodChallenge{Payload: out, State: st}, err
}

func (m *Method) summary(v verified) summary {
	return summary{Fingerprint: v.Fingerprint, Mapping: m.p.mapping, Identifier: v.Identifier, Subject: v.Subject, Issuer: v.Issuer,
		Serial: v.Serial, NotAfter: v.NotAfter, Hardware: v.Hardware}
}

// EnrollComplete は、フローを始めたのと同じ証明書で、失効まで確かめた（Preflight）ものを登録する。マッピングの値が既に
// 誰かに登録されていれば ErrExists。
func (m *Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	if err := m.configured(); err != nil {
		return port.MethodEnrollment{}, err
	}
	v, err := checked(env, in)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	if err := m.checkLimit(ctx, env); err != nil {
		return port.MethodEnrollment{}, err
	}
	raw, err := json.Marshal(data{Rule: m.p.mapping, Identifier: v.Identifier, Fingerprint: v.Fingerprint, Subject: v.Subject, Issuer: v.Issuer,
		Serial: v.Serial, NotAfter: v.NotAfter})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	c, err := env.Credentials.Create(ctx, env.UserID, v.Lookup, raw)
	if errors.Is(err, errs.Conflict) {
		return port.MethodEnrollment{}, ErrExists
	}
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	out, err := json.Marshal(m.summary(v))
	return port.MethodEnrollment{Credential: c, Payload: out}, err
}

// Revoke は方式の外に片付けるものが無いので何もしない（証明書そのものの失効は CA が行う）。
func (*Method) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }

func (m *Method) checkLimit(ctx context.Context, env port.MethodEnv) error {
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return err
	}
	if len(cs) >= m.p.maxCredentials {
		return ErrLimit
	}
	return nil
}
