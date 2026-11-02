// Package kerberos は Kerberos / SPNEGO（HTTP の Negotiate。RFC 4559）のデスクトップ SSO の認証方式（ADR 0107）。
//
// ブラウザ（Windows の統合認証、Kerberos のチケットを持つ macOS・Linux）は、401 と `WWW-Authenticate: Negotiate` に応えて
// `Authorization: Negotiate <SPNEGO のトークン>` を送る。コアはそのトークンを汎用のログインの完了と登録のパスでだけ取り出し、
// MethodEnv.Negotiate で渡す。方式は realm ごとの keytab（サービスの鍵）で AP-REQ を確かめ（gokrb5）、本人の Kerberos の
// プリンシパルを、設定の規則（本人の登録・確認済みのメールアドレス・LDAP の connection の外部 ID）で iam のユーザーに結び付ける。
// 確かめはネットワークを使わない（KDC には問い合わせない）。
//
// セキュリティ上重要なコード（13.2）。失敗は理由を外に返さず（4.9）、分からないときは拒む（fail-closed）。
package kerberos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = "kerberos"

// Feature はフィーチャー kerberos の宣言（既定オフ。ADR 0089）。features/kerberos を import すると登録される。
var Feature = feature.Feature{Name: feature.Kerberos, DataVersion: 1}

// ErrLimit は登録したプリンシパルが上限に達していること。
var ErrLimit = errs.WithCode(errs.KindConflict, "credential_limit", "too many kerberos principals")

// ErrExists はプリンシパルが既に誰かに登録されていること。
var ErrExists = errs.WithCode(errs.KindConflict, "credential_exists", "kerberos principal already enrolled")

// errNotEnrollable は、本人の登録を使わない規則（email・ldap）での登録。
var errNotEnrollable = errs.WithCode(errs.KindInvalid, "enrollment_not_supported", "kerberos: principals are mapped by the configuration")

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）が、監査ログ（login.failed の reason）には残る。
func rejected(reason string) error {
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "kerberos: "+reason)
}

// Method は Kerberos の port.Authenticator。登録する値（features/kerberos）は設定を持たず、Setup で realm ごとに組み立てる。
// 設定の無い Method は何も通さない。
type Method struct {
	p *policy
	// eph はインスタンスをまたぐ再送の確かめに使う（方式と realm で前置きしたもの）。nil なら gokrb5 のプロセスの中の確かめだけ。
	eph port.EphemeralStore
}

var (
	_ port.Authenticator             = (*Method)(nil)
	_ port.ConfigurableAuthenticator = (*Method)(nil)
)

// New は realm の設定から方式を作る。eph は nil でもよい。
func New(rc RealmConfig, eph port.EphemeralStore) (*Method, error) {
	p, err := newPolicy(rc)
	if err != nil {
		return nil, fmt.Errorf("kerberos: %w", err)
	}
	return &Method{p: p, eph: eph}, nil
}

// Setup は `methods.kerberos.realms.<realm の slug>` を読む。その realm の設定が無ければ nil（方式を動かさない）。
// 設定の誤り（読めない keytab、鍵の無いプリンシパル、未知の規則など）は起動を止める。
func (*Method) Setup(_ context.Context, s port.MethodSetup) (port.Authenticator, error) {
	var c Config
	if s.Decode != nil {
		if err := s.Decode(&c); err != nil {
			return nil, fmt.Errorf("kerberos: %w", err)
		}
	}
	// 他の realm の設定も確かめる（realm を後から作ったときに初めて誤りに気づかないように）。
	for name, rc := range c.Realms {
		if name == s.RealmSlug {
			continue
		}
		if _, err := newPolicy(rc); err != nil {
			return nil, fmt.Errorf("kerberos: realm %s: %w", name, err)
		}
	}
	rc, ok := c.Realms[s.RealmSlug]
	if !ok {
		return nil, nil
	}
	m, err := New(rc, s.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("realm %s: %w", s.RealmSlug, err)
	}
	return m, nil
}

// Info は方式の宣言。1要素目だけに使う。amr は wia（Windows の統合認証。RFC 8176）で、iam は KDC での本人確認の手段を
// 知らないので、外部 ID と同じく分類の分からない 1 要素に数える（単独で AAL1、所持の 2要素目と合わせて AAL2。ADR 0093）。
func (*Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Feature: feature.Kerberos, Kind: port.FactorPossession, AMR: []string{"wia"}, AAL: 2,
		Usages: []port.MethodUsage{port.UsageFirstFactor}, DataVersion: 1}
}

// data は結び付けたプリンシパル（コアが暗号化して置く）。
type data struct {
	Principal string `json:"principal"`
	// Rule は作った規則（enrollment は本人の登録、email・ldap はログインのときの自動の結び付け）。
	Rule string `json:"rule"`
}

// enrollState は登録の状態（始めで確かめたプリンシパル）。
type enrollState struct {
	Principal string `json:"principal"`
}

// summary は本人に返す要約。
type summary struct {
	Principal string `json:"principal"`
}

func (m *Method) configured() error {
	if m == nil || m.p == nil {
		return rejected("method is not configured")
	}
	return nil
}

// lookupOf は認証情報の検索キー（コアがブラインドインデックスにする）。
func lookupOf(principal string) string { return "principal:" + principal }

// Begin はログインを始める。確かめるものは無い（トークンは完了で受ける）。
func (m *Method) Begin(_ context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if err := m.configured(); err != nil {
		return port.MethodChallenge{}, err
	}
	if env.Usage != port.UsageFirstFactor {
		return port.MethodChallenge{}, rejected("kerberos is a first factor only")
	}
	return port.MethodChallenge{State: []byte(`{}`)}, nil
}

// Complete は Negotiate のトークンを確かめ、プリンシパルを規則でユーザーに結び付ける。トークンが無ければ port.ErrNegotiate
// （コアが 401 と `WWW-Authenticate: Negotiate` を返す）。
func (m *Method) Complete(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodResult, error) {
	if err := m.configured(); err != nil {
		return port.MethodResult{}, err
	}
	if env.Usage != port.UsageFirstFactor || env.UserID != "" {
		return port.MethodResult{}, rejected("kerberos is a first factor only")
	}
	pr, err := m.verify(ctx, env)
	if err != nil {
		return port.MethodResult{}, err
	}
	var c port.MethodCredential
	if m.p.mapping.Rule == RuleEnrollment {
		c, err = m.enrolled(ctx, env, pr)
	} else {
		c, err = m.mapped(ctx, env, pr)
	}
	if err != nil {
		return port.MethodResult{}, err
	}
	return port.MethodResult{Credential: c, AMR: []string{"wia"}}, nil
}

// enrolled は本人が登録したプリンシパルの認証情報を返す。
func (m *Method) enrolled(ctx context.Context, env port.MethodEnv, pr principal) (port.MethodCredential, error) {
	c, err := env.Credentials.FindByLookup(ctx, lookupOf(pr.String()))
	if errors.Is(err, errs.NotFound) {
		return port.MethodCredential{}, rejected("principal not enrolled (realm " + pr.Realm + ")")
	}
	if err != nil {
		return port.MethodCredential{}, err
	}
	var d data
	if err := json.Unmarshal(c.Data, &d); err != nil {
		return port.MethodCredential{}, fmt.Errorf("kerberos: data: %w", err)
	}
	// 自動の結び付けで作ったものは、本人の登録として使わない（規則を戻したら登録し直す）。
	if d.Rule != RuleEnrollment || d.Principal != pr.String() {
		return port.MethodCredential{}, rejected("principal not enrolled under rule enrollment")
	}
	return c, nil
}

// mapped は規則（email・ldap）でプリンシパルのユーザーを引き、そのユーザーの認証情報（無ければ作る）を返す。結び付けは毎回引き直し、
// 前に作った認証情報が別のユーザーのものなら無効化して作り直す（ディレクトリやメールの変更に追従する）。
func (m *Method) mapped(ctx context.Context, env port.MethodEnv, pr principal) (port.MethodCredential, error) {
	userID, err := m.resolve(ctx, env, pr)
	if errors.Is(err, errs.NotFound) {
		return port.MethodCredential{}, rejected("no user for the principal (realm " + pr.Realm + ", rule " + m.p.mapping.Rule + ")")
	}
	if err != nil {
		return port.MethodCredential{}, err
	}
	lookup := lookupOf(pr.String())
	c, err := env.Credentials.FindByLookup(ctx, lookup)
	switch {
	case err == nil && c.UserID == userID:
		return c, nil
	case err == nil:
		if err := env.Credentials.Revoke(ctx, c, "kerberos_remapped"); err != nil {
			return port.MethodCredential{}, err
		}
	case !errors.Is(err, errs.NotFound):
		return port.MethodCredential{}, err
	}
	raw, err := json.Marshal(data{Principal: pr.String(), Rule: m.p.mapping.Rule})
	if err != nil {
		return port.MethodCredential{}, err
	}
	c, err = env.Credentials.Create(ctx, userID, lookup, raw)
	if errors.Is(err, errs.Conflict) {
		// 同時のログインが先に作った。同じユーザーのものなら使う。
		if c, err = env.Credentials.FindByLookup(ctx, lookup); err == nil && c.UserID == userID {
			return c, nil
		}
		return port.MethodCredential{}, rejected("principal was mapped concurrently")
	}
	return c, err
}

// resolve は規則でプリンシパルのユーザー（内部 ID）を引く。
func (m *Method) resolve(ctx context.Context, env port.MethodEnv, pr principal) (string, error) {
	if env.Principals == nil {
		return "", errors.New("kerberos: the core did not pass a principal resolver")
	}
	mp := m.p.mapping
	switch mp.Rule {
	case RuleEmail:
		domain, ok := mp.EmailDomains[pr.Realm]
		if !ok {
			domain = strings.ToLower(pr.Realm)
		}
		return env.Principals.EmailUser(ctx, pr.Name+"@"+domain)
	case RuleLDAP:
		value := pr.String()
		if mp.LDAP.Value == ValueName {
			value = pr.Name
		}
		return env.Principals.DirectoryUser(ctx, mp.LDAP.Connection, mp.LDAP.Attribute, value)
	}
	return "", fmt.Errorf("kerberos: unknown rule %q", mp.Rule)
}

// EnrollBegin は本人の登録を始める（規則 enrollment だけ）。Negotiate のトークンを確かめ、何を登録するか（プリンシパル）を返す。
func (m *Method) EnrollBegin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if err := m.configured(); err != nil {
		return port.MethodChallenge{}, err
	}
	if m.p.mapping.Rule != RuleEnrollment {
		return port.MethodChallenge{}, errNotEnrollable
	}
	pr, err := m.verify(ctx, env)
	if errors.Is(err, errs.AuthenticationFailed) {
		return port.MethodChallenge{}, errs.WithCode(errs.KindInvalid, "negotiate_invalid", err.Error())
	}
	if err != nil {
		return port.MethodChallenge{}, err
	}
	switch _, err := env.Credentials.FindByLookup(ctx, lookupOf(pr.String())); {
	case err == nil:
		return port.MethodChallenge{}, ErrExists
	case !errors.Is(err, errs.NotFound):
		return port.MethodChallenge{}, err
	}
	if err := m.checkLimit(ctx, env); err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := json.Marshal(summary{Principal: pr.String()})
	if err != nil {
		return port.MethodChallenge{}, err
	}
	st, err := json.Marshal(enrollState{Principal: pr.String()})
	return port.MethodChallenge{Payload: out, State: st}, err
}

// EnrollComplete は始めで確かめたプリンシパルを登録する（コアのトランザクションの中）。既に誰かが登録していれば ErrExists。
func (m *Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	if err := m.configured(); err != nil {
		return port.MethodEnrollment{}, err
	}
	if m.p.mapping.Rule != RuleEnrollment {
		return port.MethodEnrollment{}, errNotEnrollable
	}
	var st enrollState
	if err := json.Unmarshal(in.State, &st); err != nil || st.Principal == "" {
		return port.MethodEnrollment{}, fmt.Errorf("kerberos: enrollment state: %v", err)
	}
	if err := m.checkLimit(ctx, env); err != nil {
		return port.MethodEnrollment{}, err
	}
	raw, err := json.Marshal(data{Principal: st.Principal, Rule: RuleEnrollment})
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	c, err := env.Credentials.Create(ctx, env.UserID, lookupOf(st.Principal), raw)
	if errors.Is(err, errs.Conflict) {
		return port.MethodEnrollment{}, ErrExists
	}
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	out, err := json.Marshal(summary(st))
	return port.MethodEnrollment{Credential: c, Payload: out}, err
}

// Revoke は方式の外に片付けるものが無いので何もしない。
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
