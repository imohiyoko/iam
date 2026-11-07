package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/ssf"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// OpenID Shared Signals Framework（フィーチャー ssf_transmitter・ssf_receiver。ADR 0118）。
//
//	GET    /.well-known/ssf-configuration  送信側のメタデータ（SSF 1.0 の 6 章）
//	POST   /ssf/streams                    ストリームの作成（GET で取得・一覧、PATCH で変更、PUT で置き換え、DELETE で削除）
//	GET    /ssf/status                     ストリームの状態（POST で変更）
//	POST   /ssf/subjects:add               対象を足す
//	POST   /ssf/subjects:remove            対象を外す
//	POST   /ssf/verify                     検証のイベントを求める
//	POST   /ssf/poll/{stream_id}           poll の配送（RFC 8936）
//	POST   /ssf/receiver/{transmitter_id}  受信側の push の受け口（RFC 8935）
//
// 送信側の API はサービスアカウントの、自前の API に向けたアクセストークン（aud は <issuer>/ssf、スコープ ssf）で呼ぶ。

const (
	wellKnownSSF         = "/.well-known/ssf-configuration"
	ssfStreamsPath       = "/ssf/streams"
	ssfStatusPath        = "/ssf/status"
	ssfAddSubjectPath    = "/ssf/subjects:add"
	ssfRemoveSubjectPath = "/ssf/subjects:remove"
	ssfVerifyPath        = "/ssf/verify"
	ssfPollPrefix        = "/ssf/poll"
	ssfReceiverPrefix    = "/ssf/receiver/"
	// SSFScope は送信側の API を呼ぶアクセストークンのスコープ。
	SSFScope = "ssf"
)

func isSSF(path string) bool { return path == wellKnownSSF || strings.HasPrefix(path, "/ssf/") }

// ssfAudience は送信側の API に向けたトークンの aud（自前の API として登録するリソースの URI。ADR 0112）。
func (a *App) ssfAudience() string { return a.issuer + "/ssf" }

// newSSFHandler は SSF のハンドラ。どちらのフィーチャーも動いていないか、issuer が無ければ nil。
func newSSFHandler(a *App) http.Handler {
	if (a.ssfTx == nil && a.ssfRx == nil) || a.issuer == "" {
		return nil
	}
	mux := http.NewServeMux()
	if a.ssfTx != nil {
		mux.HandleFunc("GET "+wellKnownSSF, a.ssfConfiguration)
		mux.HandleFunc(ssfStreamsPath, a.ssfCall(a.ssfStreams))
		mux.HandleFunc(ssfStatusPath, a.ssfCall(a.ssfStatus))
		mux.HandleFunc("POST "+ssfAddSubjectPath, a.ssfCall(a.ssfSubject(true)))
		mux.HandleFunc("POST "+ssfRemoveSubjectPath, a.ssfCall(a.ssfSubject(false)))
		mux.HandleFunc("POST "+ssfVerifyPath, a.ssfCall(a.ssfVerify))
		mux.HandleFunc("POST "+ssfPollPrefix+"/{stream}", a.ssfCall(a.ssfPoll))
	}
	if a.ssfRx != nil {
		mux.HandleFunc("POST "+ssfReceiverPrefix+"{transmitter}", a.ssfReceive)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

// ssfConfiguration は送信側のメタデータ（SSF 1.0 の 6.1）。
func (a *App) ssfConfiguration(w http.ResponseWriter, _ *http.Request) {
	iss := a.issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"spec_version": "1_0", "issuer": iss, "jwks_uri": iss + oidcKeys,
		"delivery_methods_supported": []string{ssf.DeliveryPushURN, ssf.DeliveryPollURN},
		"configuration_endpoint":     iss + ssfStreamsPath, "status_endpoint": iss + ssfStatusPath,
		"add_subject_endpoint": iss + ssfAddSubjectPath, "remove_subject_endpoint": iss + ssfRemoveSubjectPath,
		"verification_endpoint": iss + ssfVerifyPath,
		"authorization_schemes": []map[string]string{{"spec_urn": "urn:ietf:rfc:6749"}},
		"default_subjects":      "NONE",
	})
}

type ssfHandler func(w http.ResponseWriter, r *http.Request, c ssf.Caller)

// ssfCall は送信側の API のアクセストークンを確かめる。aud が <issuer>/ssf、スコープ ssf を持つ Bearer のトークンに限る
// （DPoP に結び付けたトークンは受けない）。
func (a *App) ssfCall(next ssfHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || bearer == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ssf"`)
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		// 前提（自前の API に向けたトークンとサービスアカウント）が動いていなければ、どのトークンも受けない（fail-closed）。
		if a.resources == nil || !a.plan.IsActive(feature.ServiceAccounts) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ssf", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		var c ssf.Caller
		var scoped bool
		err := a.deps.Storage.Tx(r.Context(), func(ctx context.Context, tx port.Tx) error {
			t, au, err := a.serviceAccounts.ResourceToken(ctx, tx, a.realm.ID, bearer, a.deps.Clock.Now())
			if err != nil {
				return err
			}
			if t.Audience != a.ssfAudience() || t.JKT != "" {
				return serviceaccount.ErrInvalid
			}
			scoped = slices.Contains(t.Scopes, SSFScope)
			c = ssf.Caller{AccountID: au.Account.ID, RequestID: requestID(ctx)}
			return nil
		})
		switch {
		case errors.Is(err, serviceaccount.ErrInvalid):
			w.Header().Set("WWW-Authenticate", `Bearer realm="ssf", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token")
			return
		case err != nil:
			a.unavailable(w, r, err)
			return
		case !scoped:
			w.Header().Set("WWW-Authenticate", `Bearer realm="ssf", error="insufficient_scope", scope="ssf"`)
			writeError(w, http.StatusForbidden, "insufficient_scope")
			return
		}
		next(w, r, c)
	}
}

// ssfFail は送信側の API の誤りを返す。
func (a *App) ssfFail(w http.ResponseWriter, r *http.Request, err error) {
	code := "invalid_request"
	var e *errs.Error
	if errors.As(err, &e) && e.Code != "" {
		code = e.Code
	}
	switch errs.KindOf(err) {
	case errs.KindInvalid:
		writeError(w, http.StatusBadRequest, code)
	case errs.KindNotFound:
		writeError(w, http.StatusNotFound, code)
	case errs.KindConflict:
		writeError(w, http.StatusConflict, code)
	default:
		a.unavailable(w, r, err)
	}
}

func decodeSSF(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(b) > 64<<10 {
		return errs.WithCode(errs.KindInvalid, "invalid_request", "body")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(v); err != nil {
		return errs.WithCode(errs.KindInvalid, "invalid_request", "malformed JSON")
	}
	return nil
}

func (a *App) ssfTxDo(r *http.Request, fn func(ctx context.Context, tx port.Tx) error) error {
	return a.deps.Storage.Tx(r.Context(), fn)
}

func (a *App) ssfPollURL() string { return a.issuer + ssfPollPrefix }

// ssfStreams はストリームの設定の API（SSF 1.0 の 7.1.1）。
func (a *App) ssfStreams(w http.ResponseWriter, r *http.Request, c ssf.Caller) {
	cfg := func(s port.SSFStream) ssf.StreamConfig { return ssf.Config(s, a.issuer, a.ssfPollURL()) }
	switch r.Method {
	case http.MethodGet:
		sid := r.URL.Query().Get("stream_id")
		if sid != "" {
			var s port.SSFStream
			if err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
				var err error
				s, err = a.ssfTx.Get(ctx, tx, a.realm.ID, c, sid)
				return err
			}); err != nil {
				a.ssfFail(w, r, err)
				return
			}
			writeJSON(w, http.StatusOK, cfg(s))
			return
		}
		out := []ssf.StreamConfig{}
		if err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
			ss, err := a.ssfTx.List(ctx, tx, a.realm.ID, c)
			for _, s := range ss {
				out = append(out, cfg(s))
			}
			return err
		}); err != nil {
			a.ssfFail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost, http.MethodPatch, http.MethodPut:
		var in ssf.StreamInput
		if err := decodeSSF(r, &in); err != nil {
			a.ssfFail(w, r, err)
			return
		}
		var s port.SSFStream
		status := http.StatusOK
		err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
			var err error
			if r.Method == http.MethodPost {
				status = http.StatusCreated
				s, err = a.ssfTx.Create(ctx, tx, a.realm.ID, c, in)
			} else {
				s, err = a.ssfTx.Update(ctx, tx, a.realm.ID, c, in, r.Method == http.MethodPut)
			}
			return err
		})
		if err != nil {
			a.ssfFail(w, r, err)
			return
		}
		writeJSON(w, status, cfg(s))
	case http.MethodDelete:
		if err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
			return a.ssfTx.Delete(ctx, tx, a.realm.ID, c, r.URL.Query().Get("stream_id"))
		}); err != nil {
			a.ssfFail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ssfStatus はストリームの状態の API（SSF 1.0 の 7.1.2）。
func (a *App) ssfStatus(w http.ResponseWriter, r *http.Request, c ssf.Caller) {
	var in ssf.StreamStatus
	switch r.Method {
	case http.MethodGet:
		in.StreamID = r.URL.Query().Get("stream_id")
	case http.MethodPost:
		if err := decodeSSF(r, &in); err != nil {
			a.ssfFail(w, r, err)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var s port.SSFStream
	if err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
		var err error
		if r.Method == http.MethodGet {
			s, err = a.ssfTx.Get(ctx, tx, a.realm.ID, c, in.StreamID)
		} else {
			s, err = a.ssfTx.SetStatus(ctx, tx, a.realm.ID, c, in)
		}
		return err
	}); err != nil {
		a.ssfFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ssf.StreamStatus{StreamID: s.ID, Status: s.Status, Reason: s.StatusReason})
}

// ssfSubject は対象を足す・外す（SSF 1.0 の 7.1.3）。足すのは 200、外すのは 204。
func (a *App) ssfSubject(add bool) ssfHandler {
	return func(w http.ResponseWriter, r *http.Request, c ssf.Caller) {
		var in struct {
			StreamID string       `json:"stream_id"`
			Subject  *ssf.Subject `json:"subject"`
		}
		if err := decodeSSF(r, &in); err != nil {
			a.ssfFail(w, r, err)
			return
		}
		err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
			if add {
				return a.ssfTx.AddSubject(ctx, tx, a.realm.ID, a.issuer, c, in.StreamID, in.Subject)
			}
			return a.ssfTx.RemoveSubject(ctx, tx, a.realm.ID, a.issuer, c, in.StreamID, in.Subject)
		})
		if err != nil {
			a.ssfFail(w, r, err)
			return
		}
		if add {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ssfVerify は検証のイベントを求める（SSF 1.0 の 7.1.4）。ストリームごとに1分に5回まで。
func (a *App) ssfVerify(w http.ResponseWriter, r *http.Request, c ssf.Caller) {
	var in struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state"`
	}
	if err := decodeSSF(r, &in); err != nil {
		a.ssfFail(w, r, err)
		return
	}
	// 呼び出した受信側ごとに数える（ほかの受信側が、他人のストリームの上限を使い切れないように）。
	if err := a.ssfVerifyLimit.Allow(r.Context(), "ssf-verify:"+a.realm.ID+":"+c.AccountID+":"+in.StreamID); err != nil {
		if _, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
			writeError(w, http.StatusTooManyRequests, codeRateLimited)
			return
		}
		a.unavailable(w, r, err)
		return
	}
	if err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
		return a.ssfTx.RequestVerification(ctx, tx, a.realm.ID, c, in.StreamID, in.State)
	}); err != nil {
		a.ssfFail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ssfPoll は poll の配送（RFC 8936）。
func (a *App) ssfPoll(w http.ResponseWriter, r *http.Request, c ssf.Caller) {
	var in ssf.PollRequest
	if err := decodeSSF(r, &in); err != nil {
		a.ssfFail(w, r, err)
		return
	}
	var out ssf.PollResponse
	if err := a.ssfTxDo(r, func(ctx context.Context, tx port.Tx) error {
		var err error
		out, err = a.ssfTx.Poll(ctx, tx, a.realm.ID, a.issuer, c, r.PathValue("stream"), in, a.deps.Logger)
		return err
	}); err != nil {
		a.ssfFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ssfReceive は外部の送信側からの push（RFC 8935）。受けたら 202、受けない SET は 400（err・description）。
func (a *App) ssfReceive(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, ssf.MaxSETBytes+1))
	if err != nil || len(body) > ssf.MaxSETBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{"err": "invalid_request", "description": "body too large"})
		return
	}
	bearer, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	res, err := a.ssfRx.Receive(r.Context(), a.realm.ID, r.PathValue("transmitter"), bearer, body, requestID(r.Context()))
	if re, ok := errors.AsType[*ssf.ReceiveError](err); ok {
		a.deps.Logger.InfoContext(r.Context(), "ssf: SET rejected", "code", re.Code, "reason", re.Desc)
		writeJSON(w, re.Status, map[string]string{"err": re.Code, "description": re.Desc})
		return
	}
	if err != nil {
		a.unavailable(w, r, err)
		return
	}
	a.deps.Logger.DebugContext(r.Context(), "ssf: SET received", "event", res.Event, "outcome", res.Outcome, "duplicate", res.Duplicate)
	w.WriteHeader(http.StatusAccepted)
}

// ssfEffects は受けたイベントの動作（ssf.Effects）。
type ssfEffects struct{ a *App }

func (e ssfEffects) RevokeSessions(ctx context.Context, tx port.Tx, realmID string, u port.User, actor audit.Actor, requestID string) (func(), error) {
	ids, err := e.a.sessions.RevokeAllTx(ctx, tx, realmID, u.ID, "", ReasonSSFSignal, actor, requestID)
	return func() { e.a.sessions.ForgetIDs(ctx, realmID, ids) }, err
}

func (e ssfEffects) RevokePassword(ctx context.Context, tx port.Tx, realmID string, u port.User, actor audit.Actor, requestID string) (func(), error) {
	if err := e.a.accounts.AdminRevokePassword(ctx, tx, realmID, u, actor, requestID); err != nil && !errors.Is(err, errs.NotFound) {
		return nil, err
	}
	return e.RevokeSessions(ctx, tx, realmID, u, actor, requestID)
}

func (e ssfEffects) Suspend(ctx context.Context, tx port.Tx, realmID string, u port.User, ref, reason string, actor audit.Actor, requestID string) (func(), error) {
	sp, created, err := e.a.accounts.SuspendUser(ctx, tx, realmID, u, account.Suspend{Category: account.CategorySecurityRisk, Reason: reason,
		ExternalRef: ref}, actor, requestID)
	if errors.Is(err, account.ErrLastRealmOwner) {
		return nil, ssf.ErrNotApplied
	}
	if err != nil {
		return nil, err
	}
	if created && !sp.StartsAt.After(e.a.deps.Clock.Now()) {
		if err := e.a.sessions.EndUserTx(ctx, tx, realmID, u.ID, session.ReasonSuspended, requestID); err != nil {
			return nil, err
		}
	}
	return func() { e.a.sessions.Forget(ctx, realmID, u.ID) }, nil
}

// ReasonSSFSignal は SSF の受信側が受けた知らせによるセッションの失効（ADR 0118）。
const ReasonSSFSignal = "ssf_signal"
