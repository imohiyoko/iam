// Package passkey は passkey（WebAuthn）の認証方式（port.Authenticator。design.md 4.1、9.4、2.5、ADR 0106）。
//
// コアの方式で、フィーチャーに属さない（Relying Party が決まる構成で、コアが組み込みとして渡す）。認証情報は
// authn_credentials（方式 passkey）に置き、検索キーは credential ID。
//
// セキュリティ上重要なコード（13.2）。不変条件（13.5）：
//   - challenge は毎回の乱数で、コアが封をしたフロー（本人・用途に結び付く）の中にだけ置き、1回限り（OneShot。失敗しても使えない）
//   - 受け入れる署名のアルゴリズムは ES256 と EdDSA（RS256 は警告と一緒に後から足す。ADR 0006）
//   - 1要素目のログインには本人確認（UV）を求める。2要素目では求めない
//   - 署名の回数が戻った（複製の疑い）応答は拒否する。回数は比較と交換で書くので、同じ応答を同時に2度は通さない
//   - 無効化した passkey ではログインできず、同じ credential ID は再登録できない（退役した検索キー。4.6）
//   - user handle はユーザーの公開 ID。内部 ID は認証器に渡さない（ADR 0045）
//   - フィーチャー passkey_attestation が動いていれば、登録とログイン（1要素目・2要素目）のたびに認証器のポリシーで判定する
//     （ADR 0096）。判定は保存した passkey とメモリのメタデータだけで行い、外部に問い合わせない
package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/authn/method/passkey/attestation"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// Name は方式の名前。
const Name = method.Passkey

// passkey によるログインの amr（RFC 8176）。本人確認（UV）があれば "user" も付ける。
const (
	AMRKey  = "hwk"
	AMRUser = "user"
)

// Algorithms は受け入れる署名のアルゴリズム（優先順。9.4）。
var Algorithms = []webauthncose.COSEAlgorithmIdentifier{webauthncose.AlgES256, webauthncose.AlgEdDSA}

// AttestationFeature は attestation と認証器のポリシーの宣言（features/passkeyattestation が登録する。ADR 0096）。
var AttestationFeature = feature.Feature{Name: feature.PasskeyAttestation, DataVersion: 1}

// ErrPasskeyExists は、登録しようとした passkey が既に登録されていること。
var ErrPasskeyExists = errs.WithCode(errs.KindConflict, "passkey_exists", "the passkey is already registered")

// ErrPasskeyRevoked は、登録しようとした passkey が無効化済みであること（再登録の拒否。4.6）。
// 本人は認証器で所有を示した後なので、理由を返してよい。
var ErrPasskeyRevoked = errs.WithCode(errs.KindConflict, "passkey_revoked", "the passkey was revoked and cannot be registered again")

// CodeNotAllowed は、認証器が realm の段のポリシー（ADR 0096）で許されないことのコード。
const CodeNotAllowed = "passkey_not_allowed"

// ErrNotAllowed は、登録しようとした passkey の認証器が realm の段のポリシーで許されないこと（ADR 0096）。
// 本人はログイン済みで、認証器で所有を示した後なので、理由を返してよい。どの条件に外れたかは監査ログにだけ残す。
var ErrNotAllowed = errs.WithCode(errs.KindFailedPrecondition, CodeNotAllowed, "the authenticator is not allowed by the passkey policy")

// NotAllowedError は、ログインに使った passkey の認証器がポリシーで許されないこと（本人確認の後の拒否。errs.Denial）。
// コアは監査ログに判定を残す（port.MethodAuditDetails）。
type NotAllowedError struct {
	PasskeyID string // 公開 ID
	Decision  attestation.Decision
}

func (e *NotAllowedError) Error() string { return "passkey not allowed: " + e.Decision.Reason }

// Reasons は拒否理由のコード（どの条件に外れたかは返さない）。
func (e *NotAllowedError) Reasons() []string { return []string{CodeNotAllowed} }

// AuditDetails は失敗の監査ログに足す、AAGUID と判定。
func (e *NotAllowedError) AuditDetails() map[string]any {
	out := e.Decision.Audit()
	out["passkey_id"] = e.PasskeyID
	return out
}

// RegistrationNotAllowed は登録の拒否（ErrNotAllowed）に、監査ログに残す判定を付けたもの。
type RegistrationNotAllowed struct {
	Decision attestation.Decision
	Result   attestation.Result
}

func (e *RegistrationNotAllowed) Error() string { return "passkey not allowed: " + e.Decision.Reason }
func (e *RegistrationNotAllowed) Unwrap() error { return ErrNotAllowed }

// AuditDetails は失敗の監査ログに足す、AAGUID・判定・attestation の結果。
func (e *RegistrationNotAllowed) AuditDetails() map[string]any {
	out := e.Decision.Audit()
	out["attestation_format"], out["attested"] = e.Result.Format, e.Result.Attested
	if e.Result.Detail != "" {
		out["attestation_detail"] = e.Result.Detail
	}
	return out
}

var (
	_ port.MethodAuditDetails = (*NotAllowedError)(nil)
	_ errs.Denial             = (*NotAllowedError)(nil)
	_ port.MethodAuditDetails = (*RegistrationNotAllowed)(nil)
)

// rejected は利用者の入力による失敗。理由は外に返さない（4.9）。
func rejected(reason string, err error) error {
	if err != nil {
		reason += ": " + err.Error()
	}
	return errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "passkey: "+reason)
}

// Config は Relying Party の設定（design.md 2.5）。
type Config struct {
	// RPID は Relying Party の ID（登録可能なドメイン。example.com など）。passkey はこのドメインに結び付く。
	RPID   string
	RPName string
	// Origins は受け入れる origin。RPID のドメインの外の origin は Related Origin Requests（/.well-known/webauthn）で関連付ける。
	Origins []string
	// TTL はチャレンジの期限。既定 5 分。コアのフローの期限より短ければ、こちらが効く。
	TTL time.Duration
}

// Method は passkey の port.Authenticator。New で作る。
type Method struct {
	cfg    Config
	wa     *webauthn.WebAuthn
	params []protocol.CredentialParameter
	// att は attestation と認証器のポリシー。nil ならフィーチャー passkey_attestation が動いていない（attestation は求めず、判定もしない）。
	att *Attestation
}

var _ port.Authenticator = (*Method)(nil)

// New は設定を確かめて方式を作る。att が nil なら attestation を求めず、認証器のポリシーで判定しない。
func New(cfg Config, att *Attestation) (*Method, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	// 期限はこのパッケージが env.Now で確かめる（ライブラリの期限は使わない。2.7）。
	wa, err := webauthn.New(&webauthn.Config{
		RPID: cfg.RPID, RPDisplayName: cfg.RPName, RPOrigins: cfg.Origins,
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: cfg.TTL, TimeoutUVD: cfg.TTL},
			Registration: webauthn.TimeoutConfig{Timeout: cfg.TTL, TimeoutUVD: cfg.TTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	m := &Method{cfg: cfg, wa: wa, att: att}
	for _, a := range Algorithms {
		m.params = append(m.params, protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: a})
	}
	return m, nil
}

// Info は方式の宣言。所持の要素で、本人確認（UV）があれば単独で多要素（SP 800-63B の多要素の暗号認証器）。同期する passkey と
// 区別できないので AAL の上限は 2（ADR 0093）。フィーチャーは無い（コア）。
func (m *Method) Info() port.MethodInfo {
	return port.MethodInfo{Name: Name, Kind: port.FactorPossession, AMR: []string{AMRKey}, AAL: 2,
		Usages:      []port.MethodUsage{port.UsageFirstFactor, port.UsageSecondFactor, port.UsageStepUp},
		DataVersion: 1, OneShot: true, ReserveRevokedLookups: true}
}

// Attestation は attestation と認証器のポリシー（無ければ nil）。
func (m *Method) Attestation() *Attestation { return m.att }

// RelatedOrigins は /.well-known/webauthn の内容（Related Origin Requests）を返す。
func (m *Method) RelatedOrigins() ([]string, error) {
	r, err := m.wa.RelatedOrigins()
	if err != nil {
		return nil, err
	}
	return r.Origins, nil
}

// state はフローの状態（コアが封をして置く）。
type state struct {
	Session webauthn.SessionData `json:"session"`
	// Handle は登録で認証器に渡したユーザーハンドル（本人の公開 ID）。
	Handle    []byte    `json:"handle,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (m *Method) state(env port.MethodEnv, sd *webauthn.SessionData, handle []byte) ([]byte, error) {
	sd.Expires = time.Time{}
	return json.Marshal(state{Session: *sd, Handle: handle, ExpiresAt: env.Now.Add(m.cfg.TTL)})
}

func readState(env port.MethodEnv, raw []byte) (state, error) {
	var st state
	if err := json.Unmarshal(raw, &st); err != nil || len(st.Session.Challenge) == 0 {
		return state{}, fmt.Errorf("passkey: flow state: %v", err)
	}
	if !env.Now.Before(st.ExpiresAt) {
		return state{}, rejected("challenge expired", nil)
	}
	return st, nil
}

// input はログインと登録の確認の入力。Credential は navigator.credentials.get / create の結果（PublicKeyCredential の JSON）。
type input struct {
	Credential json.RawMessage `json:"credential"`
	// Name は登録する passkey の名前（登録だけ。空なら DefaultName）。
	Name string `json:"name,omitempty"`
}

func readInput(raw json.RawMessage) (input, error) {
	var in input
	if len(raw) == 0 || json.Unmarshal(raw, &in) != nil || len(in.Credential) == 0 || string(in.Credential) == "null" {
		return input{}, rejected("credential is required", nil)
	}
	return in, nil
}

// user は go-webauthn に渡すユーザー。
type user struct {
	handle      []byte
	name        string
	credentials []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return u.handle }
func (u user) WebAuthnName() string                       { return u.name }
func (u user) WebAuthnDisplayName() string                { return u.name }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func credential(d Data) webauthn.Credential {
	ts := make([]protocol.AuthenticatorTransport, 0, len(d.Transports))
	for _, t := range d.Transports {
		ts = append(ts, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{ID: d.CredentialID, PublicKey: d.PublicKey, Transport: ts,
		Flags:         webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(d.Flags)),
		Authenticator: webauthn.Authenticator{AAGUID: d.AAGUID, SignCount: d.SignCount}}
}

// stored は本人の有効な passkey と、そのデータ。
type stored struct {
	c port.MethodCredential
	d Data
}

func list(ctx context.Context, env port.MethodEnv) ([]stored, error) {
	cs, err := env.Credentials.List(ctx, env.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]stored, 0, len(cs))
	for _, c := range cs {
		d, err := Decode(c.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, stored{c: c, d: d})
	}
	return out, nil
}

func options(v any) (json.RawMessage, error) { return json.Marshal(v) }

// Begin はログインを始める。1要素目（env.UserID が空）は discoverable credential で本人確認を求め、2要素目は本人の passkey を
// 許す credential に並べる（本人確認は求めない）。2要素目で passkey が無ければ errs.NotFound。
func (m *Method) Begin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if env.UserID == "" {
		assertion, sd, err := m.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return port.MethodChallenge{}, err
		}
		return m.challenge(env, assertion, sd, nil)
	}
	ps, err := list(ctx, env)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	if len(ps) == 0 {
		return port.MethodChallenge{}, errs.New(errs.KindNotFound, "no passkey")
	}
	wu := user{handle: ps[0].d.UserHandle}
	for _, p := range ps {
		wu.credentials = append(wu.credentials, credential(p.d))
	}
	assertion, sd, err := m.wa.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return m.challenge(env, assertion, sd, nil)
}

func (m *Method) challenge(env port.MethodEnv, opts any, sd *webauthn.SessionData, handle []byte) (port.MethodChallenge, error) {
	st, err := m.state(env, sd, handle)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	out, err := options(opts)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return port.MethodChallenge{Payload: out, State: st}, nil
}

// Complete は応答の署名を確かめ、署名の回数とフラグを記録し、認証器のポリシーで判定する（ADR 0096）。ポリシーによる拒否は、
// 署名を確かめた後なので *NotAllowedError（errs.Denial）で返す。
func (m *Method) Complete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodResult, error) {
	st, err := readState(env, in.State)
	if err != nil {
		return port.MethodResult{}, err
	}
	req, err := readInput(in.Payload)
	if err != nil {
		return port.MethodResult{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		return port.MethodResult{}, rejected("invalid assertion", err)
	}
	var used stored
	var c *webauthn.Credential
	if env.UserID == "" {
		// 1要素目：どのユーザーかは認証器が選ぶ。credential ID で引き、user handle が登録のときのものと同じことを確かめる。
		mc, err := env.Credentials.FindByLookup(ctx, Lookup(parsed.RawID))
		if errors.Is(err, errs.NotFound) {
			return port.MethodResult{}, rejected("unknown credential", nil)
		}
		if err != nil {
			return port.MethodResult{}, err
		}
		d, err := Decode(mc.Data)
		if err != nil {
			return port.MethodResult{}, err
		}
		used = stored{c: mc, d: d}
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			if !bytes.Equal(rawID, d.CredentialID) || !bytes.Equal(userHandle, d.UserHandle) {
				return nil, errors.New("user handle does not match the credential")
			}
			return user{handle: d.UserHandle, credentials: []webauthn.Credential{credential(d)}}, nil
		}
		if _, c, err = m.wa.ValidatePasskeyLogin(handler, st.Session, parsed); err != nil {
			return port.MethodResult{}, rejected("assertion", err)
		}
	} else {
		// 2要素目：フローは本人のもの（コアが確かめた）。応答の credential ID の、本人の有効な passkey で確かめる。
		ps, err := list(ctx, env)
		if err != nil {
			return port.MethodResult{}, err
		}
		var wu user
		for _, p := range ps {
			wu.credentials = append(wu.credentials, credential(p.d))
			if bytes.Equal(p.d.CredentialID, parsed.RawID) {
				used = p
			}
		}
		if used.c.ID == "" {
			return port.MethodResult{}, rejected("credential not registered for the user", nil)
		}
		// 統合（11.6）で移した passkey は元の持ち主のハンドルを持つ。照合するハンドルをその passkey のものに合わせる。
		wu.handle, st.Session.UserID = used.d.UserHandle, used.d.UserHandle
		if c, err = m.wa.ValidateLogin(wu, st.Session, parsed); err != nil {
			return port.MethodResult{}, rejected("assertion", err)
		}
		if !bytes.Equal(c.ID, used.d.CredentialID) {
			return port.MethodResult{}, rejected("credential mismatch", nil)
		}
	}
	if c.Authenticator.CloneWarning {
		return port.MethodResult{}, rejected(fmt.Sprintf("sign count did not increase (stored %d, got %d)", used.d.SignCount, c.Authenticator.SignCount), nil)
	}
	d := used.d
	d.SignCount, d.Flags = c.Authenticator.SignCount, uint8(c.Flags.ProtocolValue())
	raw, err := Encode(d)
	if err != nil {
		return port.MethodResult{}, err
	}
	updated, err := env.Credentials.Update(ctx, used.c, raw)
	if errors.Is(err, errs.Conflict) {
		// 同じ passkey が同時に使われたか、無効化された。
		return port.MethodResult{}, rejected("credential changed", err)
	}
	if err != nil {
		return port.MethodResult{}, err
	}
	details := map[string]any{"passkey_id": updated.PublicID}
	if m.att != nil {
		dec := m.att.Evaluate(env.Now, d)
		if !dec.Allowed {
			return port.MethodResult{}, &NotAllowedError{PasskeyID: updated.PublicID, Decision: dec}
		}
		for k, v := range dec.Audit() {
			details[k] = v
		}
	}
	amr := []string{AMRKey}
	if parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		amr = append(amr, AMRUser)
	}
	return port.MethodResult{Credential: updated, AMR: amr, Details: details}, nil
}

// EnrollBegin は本人の passkey の登録を始める。登録済みの passkey は除外を求める。ユーザーハンドルは本人の公開 ID。
func (m *Method) EnrollBegin(ctx context.Context, env port.MethodEnv, _ port.MethodRequest) (port.MethodChallenge, error) {
	if env.UserPublicID == "" {
		return port.MethodChallenge{}, errors.New("passkey: enrollment needs the user's public id")
	}
	ps, err := list(ctx, env)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	name := env.Account
	if name == "" {
		name = env.UserPublicID
	}
	wu := user{handle: []byte(env.UserPublicID), name: name}
	for _, p := range ps {
		wu.credentials = append(wu.credentials, credential(p.d))
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithCredentialParameters(m.params),
		webauthn.WithExclusions(webauthn.Credentials(wu.credentials).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationPreferred,
		}),
	}
	if m.att != nil && m.att.Conveyance != "" {
		opts = append(opts, webauthn.WithConveyancePreference(protocol.ConveyancePreference(m.att.Conveyance)))
	}
	creation, sd, err := m.wa.BeginRegistration(wu, opts...)
	if err != nil {
		return port.MethodChallenge{}, err
	}
	return m.challenge(env, creation, sd, wu.handle)
}

// EnrollComplete は登録の応答を確かめて passkey を作る。既に登録済みなら ErrPasskeyExists、無効化済みの credential なら
// ErrPasskeyRevoked、認証器がポリシーで許されなければ *RegistrationNotAllowed（ErrNotAllowed）。
func (m *Method) EnrollComplete(ctx context.Context, env port.MethodEnv, in port.MethodRequest) (port.MethodEnrollment, error) {
	st, err := readState(env, in.State)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	req, err := readInput(in.Payload)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	name := DefaultName
	if req.Name != "" {
		if name, err = ValidName(req.Name); err != nil {
			return port.MethodEnrollment{}, err
		}
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		return port.MethodEnrollment{}, rejected("invalid attestation response", err)
	}
	ps, err := list(ctx, env)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	wu := user{handle: st.Handle}
	for _, p := range ps {
		wu.credentials = append(wu.credentials, credential(p.d))
	}
	c, err := m.wa.CreateCredential(wu, st.Session, parsed)
	if err != nil {
		return port.MethodEnrollment{}, rejected("registration", err)
	}
	alg, err := algorithm(c.PublicKey)
	if err != nil {
		return port.MethodEnrollment{}, rejected("public key", err)
	}
	switch _, err := env.Credentials.FindByLookup(ctx, Lookup(c.ID)); {
	case err == nil:
		return port.MethodEnrollment{}, ErrPasskeyExists
	case !errors.Is(err, errs.NotFound):
		return port.MethodEnrollment{}, err
	}
	ts := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		ts = append(ts, string(t))
	}
	d := Data{CredentialID: c.ID, PublicKey: c.PublicKey, Alg: alg, SignCount: c.Authenticator.SignCount,
		Flags: uint8(c.Flags.ProtocolValue()), AAGUID: c.Authenticator.AAGUID, Transports: ts, UserHandle: st.Handle, Name: name,
		AttestationFormat: c.AttestationFormat}
	details := map[string]any{"alg": alg, "backup_eligible": c.Flags.BackupEligible}
	if m.att != nil {
		// 証明書の連なりを信頼の起点に照らし、realm の段のポリシーで判定する（ADR 0096）。
		r := m.att.Metadata.Verify(ctx, &parsed.Response.AttestationObject)
		d.Attested = r.Attested
		dec := m.att.Evaluate(env.Now, d)
		if !dec.Allowed {
			return port.MethodEnrollment{}, &RegistrationNotAllowed{Decision: dec, Result: r}
		}
		for k, v := range dec.Audit() {
			details[k] = v
		}
		details["attestation_format"], details["attested"] = r.Format, r.Attested
	}
	raw, err := Encode(d)
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	mc, err := env.Credentials.Create(ctx, env.UserID, Lookup(c.ID), raw)
	if errors.Is(err, errs.Conflict) {
		// 有効な passkey は上で確かめたので、無効化済みの credential（か同時の登録）。
		return port.MethodEnrollment{}, ErrPasskeyRevoked
	}
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	details["passkey_id"] = mc.PublicID
	out, err := json.Marshal(View(mc, d))
	if err != nil {
		return port.MethodEnrollment{}, err
	}
	return port.MethodEnrollment{Credential: mc, Payload: out, Details: details}, nil
}

// algorithm は COSE の公開鍵のアルゴリズムを返す。受け入れないものはエラー。
func algorithm(cose []byte) (int64, error) {
	k, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return 0, err
	}
	var alg int64
	switch k := k.(type) {
	case webauthncose.EC2PublicKeyData:
		alg = k.Algorithm
	case webauthncose.OKPPublicKeyData:
		alg = k.Algorithm
	default:
		return 0, fmt.Errorf("unsupported key type %T", k)
	}
	if !slices.Contains(Algorithms, webauthncose.COSEAlgorithmIdentifier(alg)) {
		return 0, fmt.Errorf("unsupported algorithm %d", alg)
	}
	return alg, nil
}

// Revoke は方式の外に片付けるものが無いので何もしない（credential ID の退役は Storage が行う）。
func (m *Method) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }

// Summary は本人に見せる passkey（/v1/me/methods と登録の応答）。
type Summary struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	BackupEligible bool       `json:"backup_eligible"`
}

// View は本人に見せる形にする。
func View(c port.MethodCredential, d Data) Summary {
	return Summary{ID: c.PublicID, Name: d.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt, BackupEligible: d.BackupEligible()}
}
