package ssf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 受信側（フィーチャー ssf_receiver）。登録した外部の送信側から push（RFC 8935）された SET を確かめ、許した動作を行う。

// 送信側ごとに許す動作。
const (
	// ActionRevokeSessions は session-revoked（CAEP）・sessions-revoked（RISC）で本人の全セッションを失効させる。
	ActionRevokeSessions = "revoke_sessions"
	// ActionRevokePassword は credential-compromise（RISC、credential_type が password）で本人のパスワードを無効化し、
	// 全セッションを失効させる（再設定は復旧の手順）。
	ActionRevokePassword = "revoke_password"
	// ActionSuspendUser は account-disabled（RISC）で本人を停止する（種別 security_risk、送信側ごとに1つ）。
	ActionSuspendUser = "suspend_user"
	// ActionRecordDevicePosture は device-compliance-change（CAEP）で端末の準拠状態を記録する（device posture input）。
	ActionRecordDevicePosture = "record_device_posture"
)

// Actions は許せる動作。
var Actions = []string{ActionRevokeSessions, ActionRevokePassword, ActionSuspendUser, ActionRecordDevicePosture}

// 受けた SET の結末（監査ログの outcome）。
const (
	OutcomeApplied        = "applied"
	OutcomeNotAllowed     = "not_allowed"
	OutcomeUnknownSubject = "unknown_subject"
	OutcomeIgnored        = "ignored"
	OutcomeStale          = "stale"
	OutcomeRefused        = "refused"
)

// ErrNotApplied は Effects が動作を行わなかったこと（realm の最後の realm:owner の停止など）。結末は OutcomeRefused。
var ErrNotApplied = errors.New("ssf: action not applied")

const (
	// DefaultMaxAge は iat がこれより古い SET を受けない時間（jti はこの間だけ覚える）。
	DefaultMaxAge  = 24 * time.Hour
	jwksTTL        = 10 * time.Minute
	jwksMinRefetch = time.Minute
	maxName        = 200
	pushTokenBytes = 32
	pushPrefix     = "ssfpt_"
)

// TransmitterConfig は送信側の登録の残りの設定（ssf_transmitters.config の JSON）。
type TransmitterConfig struct {
	// JWKSURI か JWKS のどちらか1つ（送信側の署名の公開鍵）。
	JWKSURI string          `json:"jwks_uri,omitempty"`
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	// Audience は受ける aud（どれか1つと合えばよい）。
	Audience []string `json:"audience"`
	// AllowedActions は許す動作（Actions の部分集合）。無ければ何もしない（受けて記録するだけ）。
	AllowedActions []string `json:"allowed_actions"`
	// SubjectConnection は、iss_sub の対象を外部 ID の紐付けで引く connection（slug）。無ければ email だけで引く。
	SubjectConnection string `json:"subject_connection,omitempty"`
}

// TransmitterInput は送信側の登録の作成・置き換え。
type TransmitterInput struct {
	Name    string
	Issuer  string
	Enabled bool
	TransmitterConfig
}

// Effects は受けたイベントの動作（server/app が実装する）。呼び出し側のトランザクションで行い、確定の後に after を呼ぶ。
type Effects interface {
	RevokeSessions(ctx context.Context, tx port.Tx, realmID string, u port.User, actor audit.Actor, requestID string) (after func(), err error)
	RevokePassword(ctx context.Context, tx port.Tx, realmID string, u port.User, actor audit.Actor, requestID string) (after func(), err error)
	Suspend(ctx context.Context, tx port.Tx, realmID string, u port.User, ref, reason string, actor audit.Actor, requestID string) (after func(), err error)
}

// Receiver は受信側の送信側の登録と、SET の受け取り。
type Receiver struct {
	Storage   port.Storage
	Replay    port.EphemeralStore
	Clock     clock.Clock
	Directory Directory
	Effects   Effects
	// Dev は開発ビルド（http の jwks_uri を許す）。AllowPrivateNetworks は公開でないアドレスの jwks_uri を許す（開発・テストだけ）。
	Dev                  bool
	AllowPrivateNetworks bool
	// MaxAge は iat の古さの上限（既定 DefaultMaxAge）。
	MaxAge time.Duration
	// HTTP は JWKS の取得に使う（テスト用）。nil なら公開のアドレスにだけつなぐクライアント。
	HTTP *http.Client
	Log  *slog.Logger

	mu   sync.Mutex
	jwks map[string]cachedKeys
}

type cachedKeys struct {
	set     jwk.Set
	fetched time.Time
}

func (r *Receiver) maxAge() time.Duration {
	if r.MaxAge > 0 {
		return r.MaxAge
	}
	return DefaultMaxAge
}

func (r *Receiver) logger() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

func invalidTransmitter(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_transmitter", msg)
}

// check は登録の内容を確かめて正規化する。
func (r *Receiver) check(in *TransmitterInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > maxName {
		return invalidTransmitter("name is required and at most 200 bytes")
	}
	if in.Issuer == "" || len(in.Issuer) > maxSubjectField {
		return invalidTransmitter("issuer is required")
	}
	switch {
	case (in.JWKSURI == "") == (len(in.JWKS) == 0):
		return invalidTransmitter("exactly one of jwks_uri and jwks is required")
	case in.JWKSURI != "":
		u, err := (&eventsub.Service{Dev: r.Dev, AllowPrivateNetworks: r.AllowPrivateNetworks}).CheckURL(in.JWKSURI)
		if err != nil {
			return invalidTransmitter("jwks_uri must be an absolute https URL")
		}
		in.JWKSURI = u
	default:
		if _, err := PublicKeys(in.JWKS); err != nil {
			return invalidTransmitter("jwks must be a JWK set of public keys")
		}
	}
	if len(in.Audience) == 0 || len(in.Audience) > 10 {
		return invalidTransmitter("audience must have 1 to 10 values")
	}
	for _, a := range in.Audience {
		if a == "" || len(a) > maxSubjectField {
			return invalidTransmitter("audience")
		}
	}
	for _, a := range in.AllowedActions {
		if !slices.Contains(Actions, a) {
			return invalidTransmitter("unknown action: " + a)
		}
	}
	in.AllowedActions = slices.Clone(in.AllowedActions)
	slices.Sort(in.AllowedActions)
	in.AllowedActions = slices.Compact(in.AllowedActions)
	if in.AllowedActions == nil {
		in.AllowedActions = []string{}
	}
	return nil
}

// ConfigOf は登録の残りの設定を読む。
func ConfigOf(t port.SSFTransmitter) (TransmitterConfig, error) {
	var c TransmitterConfig
	err := json.Unmarshal(t.Config, &c)
	return c, err
}

func (r *Receiver) connection(ctx context.Context, tx port.Tx, realmID, slug string) (*port.Connection, error) {
	if slug == "" {
		return nil, nil
	}
	c, err := tx.Connections().GetBySlug(ctx, realmID, slug)
	if errors.Is(err, errs.NotFound) {
		return nil, invalidTransmitter("subject_connection is not a connection in this realm")
	}
	return &c, err
}

func newPushToken() (string, []byte, error) {
	b := make([]byte, pushTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	tok := pushPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	return tok, h[:], nil
}

// CreateTransmitter は送信側を登録し、送信側が push で付ける Authorization: Bearer の値を返す（返すのはこのときだけ）。
func (r *Receiver) CreateTransmitter(ctx context.Context, tx port.Tx, realmID string, in TransmitterInput, actor audit.Actor, requestID string) (port.SSFTransmitter, string, error) {
	if err := r.check(&in); err != nil {
		return port.SSFTransmitter{}, "", err
	}
	if _, err := r.connection(ctx, tx, realmID, in.SubjectConnection); err != nil {
		return port.SSFTransmitter{}, "", err
	}
	cfg, err := json.Marshal(in.TransmitterConfig)
	if err != nil {
		return port.SSFTransmitter{}, "", err
	}
	tok, h, err := newPushToken()
	if err != nil {
		return port.SSFTransmitter{}, "", err
	}
	now := r.Clock.Now()
	t := port.SSFTransmitter{ID: id.NewExternal(id.SSFTransmitter), RealmID: realmID, Name: in.Name, Issuer: in.Issuer, Config: cfg,
		PushTokenHash: h, Enabled: in.Enabled, CreatedAt: now, UpdatedAt: now}
	if err := tx.SSFTransmitters().Create(ctx, t); errors.Is(err, errs.Conflict) {
		return t, "", errs.WithCode(errs.KindConflict, "transmitter_exists", "a transmitter with the issuer exists")
	} else if err != nil {
		return t, "", err
	}
	return t, tok, r.recordAdmin(ctx, tx, AuditTransmitterCreated, t, in.TransmitterConfig, actor, requestID)
}

// UpdateTransmitter は登録を置き換える。rotate なら push の Authorization の値を作り直して返す。
func (r *Receiver) UpdateTransmitter(ctx context.Context, tx port.Tx, realmID, tid string, in TransmitterInput, rotate bool, actor audit.Actor, requestID string) (port.SSFTransmitter, string, error) {
	t, err := tx.SSFTransmitters().Get(ctx, realmID, tid)
	if err != nil {
		return t, "", err
	}
	if err := r.check(&in); err != nil {
		return t, "", err
	}
	if _, err := r.connection(ctx, tx, realmID, in.SubjectConnection); err != nil {
		return t, "", err
	}
	cfg, err := json.Marshal(in.TransmitterConfig)
	if err != nil {
		return t, "", err
	}
	tok := ""
	if rotate {
		var h []byte
		if tok, h, err = newPushToken(); err != nil {
			return t, "", err
		}
		t.PushTokenHash = h
	}
	t.Name, t.Issuer, t.Config, t.Enabled, t.UpdatedAt = in.Name, in.Issuer, cfg, in.Enabled, r.Clock.Now()
	if err := tx.SSFTransmitters().Update(ctx, t); errors.Is(err, errs.Conflict) {
		return t, "", errs.WithCode(errs.KindConflict, "transmitter_exists", "a transmitter with the issuer exists")
	} else if err != nil {
		return t, "", err
	}
	r.forgetKeys(t.ID)
	return t, tok, r.recordAdmin(ctx, tx, AuditTransmitterUpdated, t, in.TransmitterConfig, actor, requestID)
}

// DeleteTransmitter は登録と、その送信側が知らせた端末の準拠状態を消す。
func (r *Receiver) DeleteTransmitter(ctx context.Context, tx port.Tx, realmID, tid string, actor audit.Actor, requestID string) error {
	t, err := tx.SSFTransmitters().Get(ctx, realmID, tid)
	if err != nil {
		return err
	}
	if err := tx.SSFTransmitters().Delete(ctx, realmID, tid); err != nil {
		return err
	}
	if _, err := tx.DevicePostures().DeleteBySource(ctx, realmID, tid); err != nil {
		return err
	}
	r.forgetKeys(tid)
	cfg, _ := ConfigOf(t)
	return r.recordAdmin(ctx, tx, AuditTransmitterDeleted, t, cfg, actor, requestID)
}

func (r *Receiver) recordAdmin(ctx context.Context, tx port.Tx, typ string, t port.SSFTransmitter, cfg TransmitterConfig, actor audit.Actor, requestID string) error {
	_, err := eventlog.Record(ctx, tx, r.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: t.RealmID, Actor: actor,
		RequestID: requestID, Details: map[string]any{"transmitter_id": t.ID, "issuer": t.Issuer, "enabled": t.Enabled,
			"allowed_actions": nonNil(cfg.AllowedActions)}})
	return err
}

// ReceiveError は受けなかった SET（RFC 8935 2.3）。Status は HTTP の状態、Code は err の値。
type ReceiveError struct {
	Status int
	Code   string
	Desc   string
}

func (e *ReceiveError) Error() string { return "ssf: " + e.Code + ": " + e.Desc }

func reject(status int, code, desc string) error { return &ReceiveError{Status: status, Code: code, Desc: desc} }

// Received は受けた SET の結末。
type Received struct {
	Event     string
	Outcome   string
	Duplicate bool
}

// Receive は送信側 tid から push された SET を確かめ、許した動作を行う（RFC 8935）。bearer は Authorization: Bearer の値。
// 受けない SET は *ReceiveError（400 か 401）、ストレージなどの障害はそれ以外のエラー。同じ jti の2度目は何もせずに受ける。
func (r *Receiver) Receive(ctx context.Context, realmID, tid, bearer string, body []byte, requestID string) (Received, error) {
	var t port.SSFTransmitter
	var cfg TransmitterConfig
	err := r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		t, err = tx.SSFTransmitters().Get(ctx, realmID, tid)
		return err
	})
	if errors.Is(err, errs.NotFound) || (err == nil && !t.Enabled) {
		return Received{}, reject(http.StatusUnauthorized, "authentication_failed", "unknown transmitter")
	}
	if err != nil {
		return Received{}, err
	}
	h := sha256.Sum256([]byte(bearer))
	if bearer == "" || subtle.ConstantTimeCompare(h[:], t.PushTokenHash) != 1 {
		return Received{}, reject(http.StatusUnauthorized, "authentication_failed", "invalid authorization")
	}
	if cfg, err = ConfigOf(t); err != nil {
		return Received{}, err
	}
	set, err := r.verify(ctx, t, cfg, body)
	if err != nil {
		return Received{}, err
	}
	// 同じ jti は1度だけ動かす（受けた時刻から MaxAge より長く覚える）。
	jh := sha256.Sum256([]byte(t.ID + "\x00" + set.JTI))
	n, err := r.Replay.Incr(ctx, "ssf:rx:jti:v1:"+base64.RawURLEncoding.EncodeToString(jh[:]), r.maxAge()+2*setSkew)
	if err != nil {
		return Received{}, errs.Wrap(errs.KindUnavailable, err, "ssf: replay")
	}
	if n != 1 {
		return Received{Event: set.Event, Duplicate: true}, nil
	}
	var after []func()
	var out Received
	err = r.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		after = nil
		var err error
		out, after, err = r.apply(ctx, tx, t, cfg, set, requestID)
		return err
	})
	if err != nil {
		// 動かせなかった SET は、送信側が送り直したときにもう一度試す。
		if derr := r.Replay.Delete(ctx, "ssf:rx:jti:v1:"+base64.RawURLEncoding.EncodeToString(jh[:])); derr != nil {
			r.logger().WarnContext(ctx, "ssf: could not forget jti", "error", derr)
		}
		return Received{}, err
	}
	for _, f := range after {
		f()
	}
	return out, nil
}

// verify は署名・iss・aud・iat・形を確かめる。
func (r *Receiver) verify(ctx context.Context, t port.SSFTransmitter, cfg TransmitterConfig, body []byte) (SET, error) {
	compact := bytes.TrimSpace(body)
	h, err := ParseHeader(compact)
	if err != nil {
		return SET{}, reject(http.StatusBadRequest, err.Error(), "malformed SET")
	}
	keys, fetched, err := r.keys(ctx, t, cfg, false)
	if err != nil {
		return SET{}, err
	}
	payload, err := VerifySignature(compact, h, keys)
	if err != nil && cfg.JWKSURI != "" && time.Since(fetched) > jwksMinRefetch {
		// 鍵の入れ替えに追い付くため、古い JWKS なら1度だけ取り直す。
		if keys, _, err2 := r.keys(ctx, t, cfg, true); err2 == nil {
			payload, err = VerifySignature(compact, h, keys)
		}
	}
	if err != nil {
		return SET{}, reject(http.StatusBadRequest, ErrInvalidKey.Error(), "signature verification failed")
	}
	set, err := ParseClaims(payload, r.Clock.Now(), r.maxAge())
	if err != nil {
		code := ErrInvalidRequest.Error()
		if errors.Is(err, ErrInvalidAudience) {
			code = err.Error()
		}
		return SET{}, reject(http.StatusBadRequest, code, "invalid SET claims")
	}
	if set.Issuer != t.Issuer {
		return SET{}, reject(http.StatusBadRequest, ErrInvalidIssuer.Error(), "unexpected issuer")
	}
	if !slices.ContainsFunc(set.Audience, func(a string) bool { return slices.Contains(cfg.Audience, a) }) {
		return SET{}, reject(http.StatusBadRequest, ErrInvalidAudience.Error(), "unexpected audience")
	}
	return set, nil
}

func (r *Receiver) forgetKeys(tid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.jwks {
		if strings.HasPrefix(k, tid+"\x00") {
			delete(r.jwks, k)
		}
	}
}

// keys は送信側の公開鍵を返す。jwks_uri は jwksTTL の間覚える（refresh なら取り直す）。取れなければ 400 invalid_key ではなく、
// 送り直してもらうよう障害（503）として返す。
func (r *Receiver) keys(ctx context.Context, t port.SSFTransmitter, cfg TransmitterConfig, refresh bool) (jwk.Set, time.Time, error) {
	if cfg.JWKSURI == "" {
		set, err := PublicKeys(cfg.JWKS)
		if err != nil {
			return nil, time.Time{}, reject(http.StatusBadRequest, ErrInvalidKey.Error(), "no usable keys")
		}
		return set, time.Time{}, nil
	}
	key := t.ID + "\x00" + cfg.JWKSURI
	r.mu.Lock()
	c, ok := r.jwks[key]
	r.mu.Unlock()
	if ok && !refresh && time.Since(c.fetched) < jwksTTL {
		return c.set, c.fetched, nil
	}
	set, err := r.fetch(ctx, cfg.JWKSURI)
	if err != nil {
		if ok {
			// 取り直せないときは、覚えている鍵で確かめる。
			return c.set, c.fetched, nil
		}
		return nil, time.Time{}, errs.Wrap(errs.KindUnavailable, err, "ssf: fetch jwks")
	}
	now := time.Now()
	r.mu.Lock()
	if r.jwks == nil {
		r.jwks = map[string]cachedKeys{}
	}
	r.jwks[key] = cachedKeys{set: set, fetched: now}
	r.mu.Unlock()
	return set, now, nil
}

func (r *Receiver) fetch(ctx context.Context, uri string) (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	client := r.HTTP
	if client == nil {
		client = eventsub.PublicClient(r.AllowPrivateNetworks)
	}
	resp, err := client.Do(req) // #nosec G704 -- jwks_uri は運営者が登録し、公開のアドレスに限る（eventsub.PublicClient）
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	return PublicKeys(b)
}

// apply はイベントを動作にし、許されていれば行って監査ログに残す。
func (r *Receiver) apply(ctx context.Context, tx port.Tx, t port.SSFTransmitter, cfg TransmitterConfig, set SET, requestID string) (Received, []func(), error) {
	out := Received{Event: set.Event}
	actor := audit.Actor{Type: auditActorTransmitter, ID: t.ID}
	var action string
	switch set.Event {
	case EventSessionRevoked, EventSessionsRevoked:
		action = ActionRevokeSessions
	case EventCredentialCompromise:
		if set.String("credential_type") == "password" {
			action = ActionRevokePassword
		}
	case EventAccountDisabled:
		action = ActionSuspendUser
	case EventDeviceComplianceChange:
		action = ActionRecordDevicePosture
	}
	details := map[string]any{"transmitter_id": t.ID, "event": shortEvent(set.Event), "jti": jtiRef(set.JTI)}
	finish := func(outcome string, after []func()) (Received, []func(), error) {
		out.Outcome = outcome
		details["outcome"] = outcome
		_, err := eventlog.Record(ctx, tx, r.Clock, audit.Event{Type: AuditSignalReceived, Result: audit.ResultSuccess, RealmID: t.RealmID,
			Actor: actor, RequestID: requestID, Details: details})
		return out, after, err
	}
	if action == "" {
		return finish(OutcomeIgnored, nil)
	}
	conn, err := r.connection(ctx, tx, t.RealmID, cfg.SubjectConnection)
	if err != nil && !errors.Is(err, errs.Invalid) {
		return out, nil, err
	}
	u, err := resolveUser(ctx, tx, r.Directory, t.RealmID, set.Subject.UserPart(), nil, conn)
	if errors.Is(err, ErrUnknownSubject) {
		return finish(OutcomeUnknownSubject, nil)
	}
	if err != nil {
		return out, nil, err
	}
	details["user_id"] = u.PublicID
	if !slices.Contains(cfg.AllowedActions, action) {
		return finish(OutcomeNotAllowed, nil)
	}
	details["action"] = action
	var after func()
	switch action {
	case ActionRevokeSessions:
		after, err = r.Effects.RevokeSessions(ctx, tx, t.RealmID, u, actor, requestID)
	case ActionRevokePassword:
		after, err = r.Effects.RevokePassword(ctx, tx, t.RealmID, u, actor, requestID)
	case ActionSuspendUser:
		after, err = r.Effects.Suspend(ctx, tx, t.RealmID, u, "ssf:"+t.ID+":"+jtiRef(set.JTI), "account-disabled signal from SSF transmitter "+t.Name, actor, requestID)
	case ActionRecordDevicePosture:
		stored, perr := r.recordPosture(ctx, tx, t, set, u, actor, requestID)
		if perr != nil {
			return out, nil, perr
		}
		if stored == "" {
			return finish(OutcomeUnknownSubject, nil)
		}
		if stored == OutcomeStale {
			return finish(OutcomeStale, nil)
		}
	}
	if errors.Is(err, ErrNotApplied) {
		delete(details, "action")
		return finish(OutcomeRefused, nil)
	}
	if err != nil {
		return out, nil, err
	}
	var afters []func()
	if after != nil {
		afters = append(afters, after)
	}
	return finish(OutcomeApplied, afters)
}

// recordPosture は device-compliance-change の端末の状態を記録する。端末が読めなければ空、古い知らせなら OutcomeStale。
func (r *Receiver) recordPosture(ctx context.Context, tx port.Tx, t port.SSFTransmitter, set SET, u port.User, actor audit.Actor, requestID string) (string, error) {
	device := ""
	if s := set.Subject; s != nil && s.Format == FormatComplex && s.Device != nil {
		switch s.Device.Format {
		case FormatOpaque:
			device = s.Device.ID
		case FormatIssSub:
			device = s.Device.Iss + " " + s.Device.Sub
		}
	}
	status := set.String("current_status")
	if device == "" || (status != port.DeviceCompliant && status != port.DeviceNotCompliant) {
		return "", nil
	}
	now := r.Clock.Now()
	prev, err := tx.DevicePostures().Get(ctx, t.RealmID, u.ID, device)
	if err != nil && !errors.Is(err, errs.NotFound) {
		return "", err
	}
	ok, err := tx.DevicePostures().Set(ctx, port.DevicePosture{RealmID: t.RealmID, UserID: u.ID, DeviceID: device, Status: status,
		Source: t.ID, EventAt: set.EventTime(), UpdatedAt: now})
	if err != nil {
		return "", err
	}
	if !ok {
		return OutcomeStale, nil
	}
	ref := sha256.Sum256([]byte(t.RealmID + "\x00" + device))
	d := map[string]any{"user_id": u.PublicID, "device_ref": hex.EncodeToString(ref[:8]), "status": status, "transmitter_id": t.ID}
	if prev.Status != "" {
		d["previous_status"] = prev.Status
	}
	if prev.Status == status {
		return OutcomeApplied, nil
	}
	_, err = eventlog.Record(ctx, tx, r.Clock, audit.Event{Type: AuditDevicePostureChanged, Result: audit.ResultSuccess, RealmID: t.RealmID,
		Actor: actor, RequestID: requestID, Details: d})
	return OutcomeApplied, err
}

// shortEvent はイベントの URI の末尾の名前（監査ログ）。知らない URI は "other"。
func shortEvent(uri string) string {
	for _, p := range []string{caepPrefix, riscPrefix, ssfPrefix} {
		if name, ok := strings.CutPrefix(uri, p); ok && len(name) <= 64 {
			return name
		}
	}
	return "other"
}

// jtiRef は jti の短いハッシュ（監査ログ。送信側の値をそのまま残さない）。
func jtiRef(jti string) string {
	h := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(h[:8])
}

// PurgeReceiver は全 realm の送信側の登録と端末の準拠状態を最大 limit 件消す（フィーチャーの無効化）。
func PurgeReceiver(ctx context.Context, tx port.Tx, limit int) (int, error) {
	n, err := tx.SSFTransmitters().Purge(ctx, limit)
	if err != nil || n >= limit {
		return n, err
	}
	m, err := tx.DevicePostures().Purge(ctx, limit-n)
	return n + m, err
}

// CountReceiver は全 realm の送信側の登録と端末の準拠状態の数。
func CountReceiver(ctx context.Context, tx port.Tx) (int, error) {
	n, err := tx.SSFTransmitters().Count(ctx)
	if err != nil {
		return 0, err
	}
	m, err := tx.DevicePostures().Count(ctx)
	return n + m, err
}
