// Package passkey は passkey（WebAuthn）の登録とログインを行う（design.md 4.1、9.4、2.5）。
//
// セキュリティ上重要なコード（13.2）。不変条件（13.5）：
//   - challenge は毎回の乱数で、要求したフロー（Cookie か API の応答で渡すフロー ID）に結び付け、1回限り
//   - 受け入れる署名のアルゴリズムは ES256 と EdDSA（RS256 は警告と一緒に後から足す。ADR 0006）
//   - 1要素目のログインには本人確認（UV）を求める。2要素目では求めない
//   - 署名の回数が戻った（複製の疑い）応答は拒否する
//   - 無効化した passkey ではログインできず、同じ credential_id は再登録できない（4.6）
//   - user handle はユーザーの公開 ID。内部 ID は認証器に渡さない（ADR 0045）
//   - フィーチャー passkey_attestation が動いていれば、登録とログイン（1要素目・2要素目）のたびに認証器のポリシーで判定する
//     （ADR 0096）。判定は保存した passkey とメモリのメタデータだけで行い、外部に問い合わせない
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/passkey/attestation"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// ErrAuthFailed は失敗。理由は外部に返さない（4.9）。
var ErrAuthFailed = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "passkey ceremony failed")

// ErrPasskeyExists は、登録しようとした passkey が既に登録されていること。
var ErrPasskeyExists = errs.WithCode(errs.KindConflict, "passkey_exists", "the passkey is already registered")

// ErrPasskeyRevoked は、登録しようとした passkey が無効化済みであること（再登録の拒否。4.6）。
// 本人は認証器で所有を示した後なので、理由を返してよい。
var ErrPasskeyRevoked = errs.WithCode(errs.KindConflict, "passkey_revoked", "the passkey was revoked and cannot be registered again")

// AttestationFeature は attestation と認証器のポリシーの宣言（features/passkeyattestation が登録する。ADR 0096）。
var AttestationFeature = feature.Feature{Name: feature.PasskeyAttestation, DataVersion: 1}

// CodeNotAllowed は、認証器が realm の段のポリシー（ADR 0096）で許されないことのコード。
const CodeNotAllowed = "passkey_not_allowed"

// ErrNotAllowed は、登録しようとした passkey の認証器が realm の段のポリシーで許されないこと（ADR 0096）。
// 本人はログイン済みで、認証器で所有を示した後なので、理由を返してよい。どの条件に外れたかは監査ログにだけ残す。
var ErrNotAllowed = errs.WithCode(errs.KindFailedPrecondition, CodeNotAllowed, "the authenticator is not allowed by the passkey policy")

// NotAllowedError は、ログインに使った passkey の認証器がポリシーで許されないこと（本人確認の後の拒否。errs.Denial）。
type NotAllowedError struct {
	PasskeyID string // 公開 ID
	Decision  attestation.Decision
}

func (e *NotAllowedError) Error() string { return "passkey not allowed: " + e.Decision.Reason }

// Reasons は拒否理由のコード（どの条件に外れたかは返さない）。
func (e *NotAllowedError) Reasons() []string { return []string{CodeNotAllowed} }

// notAllowedRegistration は登録の拒否（ErrNotAllowed）に、監査ログに残す判定を付けたもの。
type notAllowedRegistration struct {
	decision attestation.Decision
	result   attestation.Result
}

func (e *notAllowedRegistration) Error() string { return "passkey not allowed: " + e.decision.Reason }
func (e *notAllowedRegistration) Unwrap() error { return ErrNotAllowed }

// passkey によるログインの amr（RFC 8176）。本人確認（UV）があれば "user" も付ける。
const (
	AMRKey  = "hwk"
	AMRUser = "user"
)

// DefaultName は名前を指定しなかった passkey の名前。
const DefaultName = "Passkey"

// Algorithms は受け入れる署名のアルゴリズム（優先順。9.4）。
var Algorithms = []webauthncose.COSEAlgorithmIdentifier{webauthncose.AlgES256, webauthncose.AlgEdDSA}

// Config は Relying Party の設定（design.md 2.5）。
type Config struct {
	// RPID は Relying Party の ID（登録可能なドメイン。example.com など）。passkey はこのドメインに結び付く。
	RPID   string
	RPName string
	// Origins は受け入れる origin。RPID のドメインの外の origin は Related Origin Requests
	// （/.well-known/webauthn）で関連付ける。
	Origins []string
	// TTL はフロー（challenge）の期限。既定 5 分。
	TTL time.Duration
}

// Attestation は attestation と認証器のポリシー（フィーチャー passkey_attestation。ADR 0096）。
type Attestation struct {
	// Metadata は認証器のメタデータ（MDS の BLOB と設定した信頼の起点）。全 realm で共有する。
	Metadata *attestation.Metadata
	// Conveyance は登録で求める attestation（none・indirect・direct・enterprise）。空なら none。
	Conveyance protocol.ConveyancePreference
	// Policy は realm の段のポリシー。nil なら認証器の状態（status report）だけで判定する。
	Policy *attestation.Policy
}

// Evaluate は保存した passkey p を、realm の段のポリシーと追加の段 extra で判定する。
func (a *Attestation) Evaluate(now time.Time, p port.Passkey, extra ...attestation.Tiered) attestation.Decision {
	tiers := append([]attestation.Tiered{{Tier: "realm", Policy: a.Policy}}, extra...)
	return a.Metadata.Evaluate(now, Authenticator(p), tiers...)
}

// Authenticator は保存した passkey の判定の材料。
func Authenticator(p port.Passkey) attestation.Authenticator {
	return attestation.Authenticator{AAGUID: p.AAGUID, Format: p.AttestationFormat, Attested: p.Attested}
}

// Service は passkey の登録とログインを扱う。New で作る。
type Service struct {
	Storage  port.Storage
	Cache    port.EphemeralStore
	Crypter  *pii.Crypter
	Clock    clock.Clock
	Accounts *account.Service
	Sessions *session.Manager
	Log      *slog.Logger
	// Attestation は attestation と認証器のポリシー。nil ならフィーチャー passkey_attestation が動いていない
	// （attestation は求めず、判定もしない）。
	Attestation *Attestation

	cfg    Config
	wa     *webauthn.WebAuthn
	params []protocol.CredentialParameter
}

// New は設定を確かめ、s に Relying Party の設定を加えたものを返す。
func New(cfg Config, s Service) (*Service, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	// 期限はこのパッケージが Clock で確かめる（ライブラリの期限は使わない。2.7）。
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
	s.cfg, s.wa = cfg, wa
	for _, a := range Algorithms {
		s.params = append(s.params, protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: a})
	}
	return &s, nil
}

// RelatedOrigins は /.well-known/webauthn の内容（Related Origin Requests）を返す。
func (s *Service) RelatedOrigins() ([]string, error) {
	r, err := s.wa.RelatedOrigins()
	if err != nil {
		return nil, err
	}
	return r.Origins, nil
}

// Client は要求の接続元（監査ログとセッションに残す）。
type Client struct {
	IP, UserAgent, RequestID string
}

// フローの目的。
const (
	purposeRegister = "register"
	purposeLogin    = "login"
	purposeVerify   = "verify" // 2要素目
)

// state はフローの状態。EphemeralStore に封をして置く。キーはフロー ID のハッシュ。
type state struct {
	RealmID   string               `json:"realm_id"`
	Purpose   string               `json:"purpose"`
	UserID    string               `json:"user_id,omitempty"` // 登録と2要素目のフローのユーザー（内部 ID）
	Session   webauthn.SessionData `json:"session"`
	ExpiresAt time.Time            `json:"expires_at"`
}

const sealPurpose = "flow.passkey"

func flowKey(flowID string) string {
	h := sha256.Sum256([]byte(flowID))
	return "flow:passkey:v1:" + base64.RawURLEncoding.EncodeToString(h[:])
}

// Started は開始したフロー。FlowID は要求した側にだけ渡す秘密。Options はブラウザの
// navigator.credentials.create / get に渡す内容（{"publicKey": …}）。
type Started struct {
	FlowID    string
	Options   json.RawMessage
	ExpiresAt time.Time
}

func (s *Service) begin(ctx context.Context, st state, options any) (Started, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Started{}, err
	}
	flowID := base64.RawURLEncoding.EncodeToString(b)
	st.ExpiresAt = s.Clock.Now().Add(s.cfg.TTL)
	st.Session.Expires = time.Time{}
	raw, err := json.Marshal(st)
	if err != nil {
		return Started{}, err
	}
	sealed, err := s.Crypter.Seal(ctx, sealPurpose, raw)
	if err != nil {
		return Started{}, err
	}
	if err := s.Cache.Set(ctx, flowKey(flowID), sealed, s.cfg.TTL); err != nil {
		return Started{}, err
	}
	opts, err := json.Marshal(options)
	if err != nil {
		return Started{}, err
	}
	return Started{FlowID: flowID, Options: opts, ExpiresAt: st.ExpiresAt}, nil
}

// take はフローの状態を1回限りで取り出し、realm・目的・ユーザー・期限を確かめる。
func (s *Service) take(ctx context.Context, realmID, flowID, purpose, userID string) (state, error) {
	if flowID == "" {
		return state{}, errors.New("flow id is required")
	}
	b, ok, err := s.Cache.Take(ctx, flowKey(flowID))
	if err != nil {
		return state{}, err
	}
	if !ok {
		return state{}, errors.New("unknown or used flow")
	}
	pt, err := s.Crypter.Open(ctx, sealPurpose, b)
	if err != nil {
		return state{}, err
	}
	var st state
	if err := json.Unmarshal(pt, &st); err != nil {
		return state{}, err
	}
	switch {
	case st.RealmID != realmID || !s.Clock.Now().Before(st.ExpiresAt):
		return state{}, errors.New("flow expired or in another realm")
	case st.Purpose != purpose || subtle.ConstantTimeCompare([]byte(st.UserID), []byte(userID)) != 1:
		return state{}, errors.New("flow is for another purpose or user")
	}
	return st, nil
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

func credential(p port.Passkey) webauthn.Credential {
	ts := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
	for _, t := range p.Transports {
		ts = append(ts, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{ID: p.CredentialID, PublicKey: p.PublicKey, Transport: ts,
		Flags:         webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(p.Flags)),
		Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount}}
}

// loadUser はユーザーと、無効化していない passkey を読む。name は表示用（primary のメール。無ければ公開 ID）。
func (s *Service) loadUser(ctx context.Context, tx port.Tx, realmID, userID string, withName bool) (port.User, user, []port.Passkey, error) {
	u, err := tx.Users().Get(ctx, realmID, userID)
	if err != nil {
		return port.User{}, user{}, nil, err
	}
	all, err := tx.Passkeys().ListByUser(ctx, realmID, userID)
	if err != nil {
		return port.User{}, user{}, nil, err
	}
	wu := user{handle: []byte(u.PublicID), name: u.PublicID}
	var active []port.Passkey
	for _, p := range all {
		if p.RevokedAt == nil {
			active = append(active, p)
			wu.credentials = append(wu.credentials, credential(p))
		}
	}
	if withName {
		es, err := tx.Emails().ListByUser(ctx, realmID, userID)
		if err != nil {
			return port.User{}, user{}, nil, err
		}
		for _, e := range es {
			if e.IsPrimary && len(e.Ciphertext) > 0 {
				if wu.name, err = s.Accounts.EmailAddress(ctx, tx, e); err != nil {
					return port.User{}, user{}, nil, err
				}
			}
		}
	}
	return u, wu, active, nil
}

// ---------------------------------------------------------------------------
// 登録（ログイン済みの本人だけ。4.2）

// BeginRegister はユーザー（内部 ID）の passkey の登録を始める。登録済みの passkey は除外を求める。
func (s *Service) BeginRegister(ctx context.Context, realmID, userID string) (Started, error) {
	var wu user
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		_, wu, _, err = s.loadUser(ctx, tx, realmID, userID, true)
		return err
	})
	if err != nil {
		return Started{}, err
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithCredentialParameters(s.params),
		webauthn.WithExclusions(webauthn.Credentials(wu.credentials).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationPreferred,
		}),
	}
	if s.Attestation != nil && s.Attestation.Conveyance != "" {
		opts = append(opts, webauthn.WithConveyancePreference(s.Attestation.Conveyance))
	}
	creation, sd, err := s.wa.BeginRegistration(wu, opts...)
	if err != nil {
		return Started{}, err
	}
	return s.begin(ctx, state{RealmID: realmID, Purpose: purposeRegister, UserID: userID, Session: *sd}, creation)
}

// Register は登録の応答（navigator.credentials.create の結果の JSON）を受ける。
type Register struct {
	FlowID   string
	Response []byte
	Name     string
	Client   Client
}

// FinishRegister は登録を完了する。失敗は ErrAuthFailed。既に登録済みなら ErrPasskeyExists、
// 無効化済みの credential なら ErrPasskeyRevoked（本人は所有を示した後なので理由を返す）。
func (s *Service) FinishRegister(ctx context.Context, realmID, userID string, in Register) (port.Passkey, error) {
	name := DefaultName
	if in.Name != "" {
		var err error
		if name, err = account.PasskeyName(in.Name); err != nil {
			return port.Passkey{}, err
		}
	}
	p, err := s.finishRegister(ctx, realmID, userID, name, in)
	if err != nil {
		s.recordFailure(ctx, realmID, "passkey.registration_failed", in.Client, err)
		if errors.Is(err, ErrPasskeyExists) || errors.Is(err, ErrPasskeyRevoked) {
			return port.Passkey{}, err
		}
		if errors.Is(err, ErrNotAllowed) {
			return port.Passkey{}, ErrNotAllowed
		}
		return port.Passkey{}, ErrAuthFailed
	}
	return p, nil
}

func (s *Service) finishRegister(ctx context.Context, realmID, userID, name string, in Register) (port.Passkey, error) {
	st, err := s.take(ctx, realmID, in.FlowID, purposeRegister, userID)
	if err != nil {
		return port.Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Response)
	if err != nil {
		return port.Passkey{}, err
	}
	var p port.Passkey
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		u, wu, _, err := s.loadUser(ctx, tx, realmID, userID, false)
		if err != nil {
			return err
		}
		c, err := s.wa.CreateCredential(wu, st.Session, parsed)
		if err != nil {
			return err
		}
		alg, err := algorithm(c.PublicKey)
		if err != nil {
			return err
		}
		switch _, err := tx.Passkeys().GetByCredentialID(ctx, realmID, c.ID); {
		case err == nil:
			return ErrPasskeyExists
		case !errors.Is(err, errs.NotFound):
			return err
		}
		ts := make([]string, 0, len(c.Transport))
		for _, t := range c.Transport {
			ts = append(ts, string(t))
		}
		p = port.Passkey{ID: id.New(id.Passkey), PublicID: id.NewExternal(id.Passkey), RealmID: realmID, UserID: u.ID,
			CredentialID: c.ID, PublicKey: c.PublicKey, Alg: alg, SignCount: c.Authenticator.SignCount,
			Flags: uint8(c.Flags.ProtocolValue()), AAGUID: c.Authenticator.AAGUID, Transports: ts, Name: name, CreatedAt: s.Clock.Now(),
			AttestationFormat: c.AttestationFormat}
		details := map[string]any{"passkey_id": p.PublicID, "alg": alg, "backup_eligible": c.Flags.BackupEligible}
		if s.Attestation != nil {
			// 証明書の連なりを信頼の起点に照らし、realm の段のポリシーで判定する（ADR 0096）。
			r := s.Attestation.Metadata.Verify(ctx, &parsed.Response.AttestationObject)
			p.Attested = r.Attested
			d := s.Attestation.Evaluate(p.CreatedAt, p)
			if !d.Allowed {
				return &notAllowedRegistration{decision: d, result: r}
			}
			for k, v := range d.Audit() {
				details[k] = v
			}
			details["attestation_format"], details["attested"] = r.Format, r.Attested
		}
		if err := tx.Passkeys().Create(ctx, p); err != nil {
			if errors.Is(err, errs.Conflict) {
				// 有効な passkey は上で確かめたので、無効化済みの credential（か同時の登録）。
				return ErrPasskeyRevoked
			}
			return err
		}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "passkey.registered", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID, Details: details,
		})
		return err
	})
	return p, err
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

// ---------------------------------------------------------------------------
// ログイン（1要素目。どのユーザーかは認証器が選ぶ）

// BeginLogin はログインを始める（discoverable credential。本人確認を求める）。
func (s *Service) BeginLogin(ctx context.Context, realmID string) (Started, error) {
	assertion, sd, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Started{}, err
	}
	return s.begin(ctx, state{RealmID: realmID, Purpose: purposeLogin, Session: *sd}, assertion)
}

// Login はログインの応答（navigator.credentials.get の結果の JSON）を受ける。
type Login struct {
	FlowID   string
	Response []byte
	Client   Client
	// ReplaceToken は同じブラウザが持っていた古いセッションのトークン（session.Issue を参照）。
	ReplaceToken string
}

// Result はログインの結果。
type Result struct {
	Session session.Issued
	UserID  string // 公開 ID
}

// FinishLogin はログインを完了し、セッションを発行する。失敗は ErrAuthFailed。
func (s *Service) FinishLogin(ctx context.Context, realmID string, in Login) (Result, error) {
	out, err := s.finishLogin(ctx, realmID, in)
	if err != nil {
		s.recordFailure(ctx, realmID, "login.failed", in.Client, err)
		if denied, ok := errors.AsType[errs.Denial](err); ok {
			return Result{}, denied
		}
		return Result{}, ErrAuthFailed
	}
	return out, nil
}

func (s *Service) finishLogin(ctx context.Context, realmID string, in Login) (Result, error) {
	st, err := s.take(ctx, realmID, in.FlowID, purposeLogin, "")
	if err != nil {
		return Result{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(in.Response)
	if err != nil {
		return Result{}, err
	}
	now := s.Clock.Now()
	var out Result
	err = s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var u port.User
		var used port.Passkey
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			p, err := tx.Passkeys().GetByCredentialID(ctx, realmID, rawID)
			if err != nil {
				return nil, err
			}
			var wu user
			if u, wu, _, err = s.loadUser(ctx, tx, realmID, p.UserID, false); err != nil {
				return nil, err
			}
			// 統合（11.6）で移した passkey は、元のユーザーのハンドルで登録されている。
			if len(p.UserHandle) > 0 {
				wu.handle = p.UserHandle
			}
			if !bytes.Equal(userHandle, wu.handle) {
				return nil, errors.New("user handle does not match the credential")
			}
			used = p
			return wu, nil
		}
		_, c, err := s.wa.ValidatePasskeyLogin(handler, st.Session, parsed)
		if err != nil {
			return err
		}
		if err := s.used(ctx, tx, used, c, now); err != nil {
			return err
		}
		if err := s.allowed(used, now); err != nil {
			return err
		}
		if _, err := account.Check(ctx, tx, u, now, now); err != nil {
			return err
		}
		amr := []string{AMRKey}
		if parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
			amr = append(amr, AMRUser)
		}
		is, err := s.Sessions.Issue(ctx, tx, session.Issue{
			RealmID: realmID, UserID: u.ID, AuthMethods: amr, Credentials: []string{used.ID},
			IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID, ReplaceToken: in.ReplaceToken,
		})
		if err != nil {
			return err
		}
		out = Result{Session: is, UserID: u.PublicID}
		_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: "login.succeeded", Result: audit.ResultSuccess, RealmID: realmID, Actor: audit.Actor{Type: "user", ID: u.PublicID},
			SessionID: is.Session.ID, IP: in.Client.IP, UserAgent: in.Client.UserAgent, RequestID: in.Client.RequestID,
			Details: s.loginDetails(used, now),
		})
		return err
	})
	if err == nil {
		s.Sessions.Committed(ctx, realmID, out.Session)
	}
	return out, err
}

// allowed は、ログインに使った passkey p の認証器が realm の段のポリシーで許されるかを確かめる（ADR 0096）。
// 署名を確かめた後（本人確認の後）なので、拒否は理由のコードつきの *NotAllowedError。
func (s *Service) allowed(p port.Passkey, now time.Time) error {
	if s.Attestation == nil {
		return nil
	}
	if d := s.Attestation.Evaluate(now, p); !d.Allowed {
		return &NotAllowedError{PasskeyID: p.PublicID, Decision: d}
	}
	return nil
}

// loginDetails はログインの成功の監査ログの詳細。
func (s *Service) loginDetails(p port.Passkey, now time.Time) map[string]any {
	out := map[string]any{"method": "passkey", "passkey_id": p.PublicID}
	if s.Attestation != nil {
		for k, v := range s.Attestation.Evaluate(now, p).Audit() {
			out[k] = v
		}
	}
	return out
}

// used は署名の回数を確かめ、使ったことを記録する。回数が戻った応答（複製の疑い）は拒否する。
func (s *Service) used(ctx context.Context, tx port.Tx, p port.Passkey, c *webauthn.Credential, now time.Time) error {
	if c.Authenticator.CloneWarning {
		return fmt.Errorf("sign count did not increase (stored %d, got %d)", p.SignCount, c.Authenticator.SignCount)
	}
	return tx.Passkeys().Used(ctx, p.RealmID, p.ID, c.Authenticator.SignCount, uint8(c.Flags.ProtocolValue()), now)
}

// ---------------------------------------------------------------------------
// 2要素目（ユーザーは1要素目で決まっている）

// BeginVerify はユーザー（内部 ID）の passkey による2要素目の確認を始める。passkey が無ければ errs.NotFound。
func (s *Service) BeginVerify(ctx context.Context, realmID, userID string) (Started, error) {
	var wu user
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		_, wu, _, err = s.loadUser(ctx, tx, realmID, userID, false)
		return err
	})
	if err != nil {
		return Started{}, err
	}
	if len(wu.credentials) == 0 {
		return Started{}, errs.New(errs.KindNotFound, "no passkey")
	}
	assertion, sd, err := s.wa.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		return Started{}, err
	}
	return s.begin(ctx, state{RealmID: realmID, Purpose: purposeVerify, UserID: userID, Session: *sd}, assertion)
}

// Verify は2要素目の応答を確かめ、使った passkey を返す。呼び出し側のトランザクションで呼ぶ
// （セッションの発行と同じトランザクションにするため）。失敗は ErrAuthFailed。
func (s *Service) Verify(ctx context.Context, tx port.Tx, realmID, userID, flowID string, response []byte) (port.Passkey, error) {
	p, err := s.verify(ctx, tx, realmID, userID, flowID, response)
	if na, ok := errors.AsType[*NotAllowedError](err); ok {
		// 署名を確かめた後の、ポリシーによる拒否。呼び出し側のトランザクションは戻るので、監査ログは RecordDenied で残す。
		return port.Passkey{}, na
	}
	if err != nil {
		s.logger().DebugContext(ctx, "passkey verification failed", "error", err)
		return port.Passkey{}, ErrAuthFailed
	}
	return p, nil
}

// RecordDenied は、2要素目の確認（Verify）がポリシーで拒否されたことを監査ログに残す（呼び出し側のトランザクションの後に呼ぶ）。
func (s *Service) RecordDenied(ctx context.Context, realmID string, c Client, err *NotAllowedError) {
	s.recordFailure(ctx, realmID, "login.failed", c, err)
}

func (s *Service) verify(ctx context.Context, tx port.Tx, realmID, userID, flowID string, response []byte) (port.Passkey, error) {
	st, err := s.take(ctx, realmID, flowID, purposeVerify, userID)
	if err != nil {
		return port.Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return port.Passkey{}, err
	}
	_, wu, active, err := s.loadUser(ctx, tx, realmID, userID, false)
	if err != nil {
		return port.Passkey{}, err
	}
	for _, p := range active {
		if bytes.Equal(p.CredentialID, parsed.RawID) && len(p.UserHandle) > 0 {
			// 統合（11.6）で移した passkey。フローは userID のものと take で確かめてあるので、照合する ID も合わせる。
			wu.handle, st.Session.UserID = p.UserHandle, p.UserHandle
		}
	}
	c, err := s.wa.ValidateLogin(wu, st.Session, parsed)
	if err != nil {
		return port.Passkey{}, err
	}
	for _, p := range active {
		if bytes.Equal(p.CredentialID, c.ID) {
			now := s.Clock.Now()
			if err := s.used(ctx, tx, p, c, now); err != nil {
				return port.Passkey{}, err
			}
			return p, s.allowed(p, now)
		}
	}
	return port.Passkey{}, errors.New("credential not found")
}

// recordFailure は失敗を監査ログに残す（理由は内部向け。6.1）。
// 認証器のポリシーによる拒否なら、AAGUID と判定も残す（ADR 0096）。
func (s *Service) recordFailure(ctx context.Context, realmID, typ string, c Client, cause error) {
	details := map[string]any{"method": "passkey", "reason": cause.Error()}
	if na, ok := errors.AsType[*NotAllowedError](cause); ok {
		details["passkey_id"] = na.PasskeyID
		for k, v := range na.Decision.Audit() {
			details[k] = v
		}
	}
	if na, ok := errors.AsType[*notAllowedRegistration](cause); ok {
		for k, v := range na.decision.Audit() {
			details[k] = v
		}
		details["attestation_format"], details["attested"] = na.result.Format, na.result.Attested
		if na.result.Detail != "" {
			details["attestation_detail"] = na.result.Detail
		}
	}
	err := s.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
			Type: typ, Result: audit.ResultFailure, RealmID: realmID, Actor: audit.Actor{Type: "anonymous"},
			IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID, Details: details,
		})
		return err
	})
	if err != nil {
		s.logger().WarnContext(ctx, "could not record passkey failure", "error", err)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}
