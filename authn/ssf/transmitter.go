package ssf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/imohiyoko/iam/authn/eventsub"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// 送信側のストリームの管理（SSF 1.0 の 7 章）。受信側はサービスアカウントで、自分のストリームだけを扱える。

const (
	// MaxStreamsPerReceiver と MaxStreamsPerRealm はストリームの数の上限。
	MaxStreamsPerReceiver = 5
	MaxStreamsPerRealm    = 50
	// MaxSubjectsPerStream はストリームの対象の数の上限。
	MaxSubjectsPerStream = 100000
	// MaxPendingPoll は poll のストリームで確認を待つ SET の数の上限（超えると監査ログの位置で待つ）。
	MaxPendingPoll = 1000
	maxDescription = 1000
	maxAuthHeader  = 1024
	maxState       = 256
	maxReason      = 256
	// AuthorizationAAD は push の Authorization ヘッダーの暗号文の付加データ。
	AuthorizationAAD = "ssf.stream.authorization"
)

// Signer は realm の鍵で JWS を作る（provider.Keys）。
type Signer interface {
	Sign(ctx context.Context, tx port.Tx, realmID, alg, typ string, claims []byte) (string, error)
}

// Transmitter は送信側のストリームの作成・変更・削除と、SET の作成。
type Transmitter struct {
	Crypter *pii.Crypter
	Clock   clock.Clock
	Keys    Signer
	// Directory は対象のメールからユーザーを引く（account.Service）。
	Directory Directory
	// Dev は開発ビルド（http の送り先を許す）。AllowPrivateNetworks は公開でないアドレスの送り先を許す（開発・テストだけ）。
	Dev                  bool
	AllowPrivateNetworks bool
}

// Caller は SSF の API を呼んだ受信側（確かめたサービスアカウント）。
type Caller struct {
	AccountID string
	RequestID string
}

func (c Caller) actor() audit.Actor { return audit.Actor{Type: "service_account", ID: c.AccountID} }

// Delivery は SSF のストリームの delivery。AuthorizationHeader は書くだけで、返さない。
type Delivery struct {
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

// StreamInput はストリームの作成・変更の要求（SSF 1.0 の 7.1.1）。送信側が決める項目（iss・aud・events_supported・
// events_delivered）は受けても無視する。nil の項目は変えない（置き換えでは既定値）。
type StreamInput struct {
	StreamID        string    `json:"stream_id,omitempty"`
	Delivery        *Delivery `json:"delivery,omitempty"`
	EventsRequested *[]string `json:"events_requested,omitempty"`
	Description     *string   `json:"description,omitempty"`
}

// StreamConfig はストリームの設定の応答（SSF 1.0 の 7.1.1）。
type StreamConfig struct {
	StreamID        string   `json:"stream_id"`
	Iss             string   `json:"iss"`
	Aud             string   `json:"aud"`
	EventsSupported []string `json:"events_supported"`
	EventsRequested []string `json:"events_requested"`
	EventsDelivered []string `json:"events_delivered"`
	Delivery        Delivery `json:"delivery"`
	Description     string   `json:"description,omitempty"`
}

// StreamStatus はストリームの状態（SSF 1.0 の 7.1.2）。
type StreamStatus struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// Config はストリームの設定の応答を作る。pollURL は poll のストリームの受け取り口（stream_id を足す前）。
func Config(s port.SSFStream, issuer, pollURL string) StreamConfig {
	d := Delivery{Method: DeliveryPushURN, EndpointURL: s.EndpointURL}
	if s.DeliveryMethod == port.SSFDeliveryPoll {
		d = Delivery{Method: DeliveryPollURN, EndpointURL: pollURL + "/" + s.ID}
	}
	return StreamConfig{StreamID: s.ID, Iss: issuer, Aud: s.ServiceAccountID, EventsSupported: slices.Clone(SupportedEvents),
		EventsRequested: nonNil(s.EventsRequested), EventsDelivered: nonNil(s.EventsDelivered), Delivery: d, Description: s.Description}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

func invalid(msg string) error { return errs.WithCode(errs.KindInvalid, "invalid_request", msg) }

// ErrStreamNotFound は無いか、ほかの受信側のストリーム（どちらか分からないようにする）。
var ErrStreamNotFound = errs.WithCode(errs.KindNotFound, "not_found", "stream not found")

// own はストリームを引き、呼び出した受信側のものかを確かめる。
func own(ctx context.Context, tx port.Tx, realmID string, c Caller, streamID string) (port.SSFStream, error) {
	if streamID == "" {
		return port.SSFStream{}, invalid("stream_id is required")
	}
	s, err := tx.SSFStreams().Get(ctx, realmID, streamID)
	if errors.Is(err, errs.NotFound) || (err == nil && s.ServiceAccountID != c.AccountID) {
		return port.SSFStream{}, ErrStreamNotFound
	}
	return s, err
}

// Create はストリームを作る。位置は今の最新（過去の出来事は送らない）。
func (t *Transmitter) Create(ctx context.Context, tx port.Tx, realmID string, c Caller, in StreamInput) (port.SSFStream, error) {
	now := t.Clock.Now()
	s := port.SSFStream{ID: id.NewExternal(id.SSFStream), RealmID: realmID, ServiceAccountID: c.AccountID, Status: port.SSFStatusEnabled,
		CreatedAt: now, UpdatedAt: now}
	if in.Delivery == nil {
		return s, invalid("delivery is required")
	}
	if err := t.apply(ctx, tx, &s, in, true, false); err != nil {
		return s, err
	}
	all, err := tx.SSFStreams().List(ctx, realmID)
	if err != nil {
		return s, err
	}
	mine := 0
	for _, x := range all {
		if x.ServiceAccountID == c.AccountID {
			mine++
		}
	}
	if mine >= MaxStreamsPerReceiver || len(all) >= MaxStreamsPerRealm {
		return s, errs.WithCode(errs.KindConflict, "stream_limit", "too many streams")
	}
	if last, err := tx.Audit().Last(ctx); err != nil {
		return s, err
	} else if last != nil {
		s.CursorSeq = last.Seq
	}
	if err := t.Crypter.CreateDataKey(ctx, tx.DataKeys(), s.ID, now); err != nil {
		return s, err
	}
	if err := t.seal(ctx, tx, &s, in.Delivery.AuthorizationHeader); err != nil {
		return s, err
	}
	if err := tx.SSFStreams().Create(ctx, s); err != nil {
		return s, err
	}
	return s, t.record(ctx, tx, AuditStreamCreated, s, c, nil)
}

// apply は in を s に書く。create・replace なら省いた項目は既定値にする。
func (t *Transmitter) apply(_ context.Context, _ port.Tx, s *port.SSFStream, in StreamInput, create, replace bool) error {
	full := create || replace
	if in.Delivery != nil {
		switch in.Delivery.Method {
		case DeliveryPushURN:
			u, err := (&eventsub.Service{Dev: t.Dev, AllowPrivateNetworks: t.AllowPrivateNetworks}).CheckURL(in.Delivery.EndpointURL)
			if err != nil {
				return invalid("delivery.endpoint_url must be an absolute https URL")
			}
			s.DeliveryMethod, s.EndpointURL = port.SSFDeliveryPush, u
		case DeliveryPollURN:
			if in.Delivery.EndpointURL != "" && !create {
				// 受け取り口は送信側が決める（応答で返したものと同じなら受ける）。
				if !strings.HasSuffix(in.Delivery.EndpointURL, "/"+s.ID) {
					return invalid("delivery.endpoint_url is set by the transmitter for poll delivery")
				}
			}
			s.DeliveryMethod, s.EndpointURL = port.SSFDeliveryPoll, ""
		default:
			return invalid("delivery.method must be " + DeliveryPushURN + " or " + DeliveryPollURN)
		}
		if h := in.Delivery.AuthorizationHeader; len(h) > maxAuthHeader || strings.ContainsAny(h, "\r\n\x00") {
			return invalid("delivery.authorization_header is too long or contains control characters")
		}
		if s.DeliveryMethod == port.SSFDeliveryPoll && in.Delivery.AuthorizationHeader != "" {
			return invalid("delivery.authorization_header is only for push delivery")
		}
	} else if full {
		return invalid("delivery is required")
	}
	if in.EventsRequested != nil || full {
		var req []string
		if in.EventsRequested != nil {
			req = *in.EventsRequested
		}
		if len(req) > 50 {
			return invalid("too many events_requested")
		}
		for _, e := range req {
			if e == "" || len(e) > 512 {
				return invalid("events_requested")
			}
		}
		req = slices.Clone(req)
		slices.Sort(req)
		req = slices.Compact(req)
		s.EventsRequested = req
		s.EventsDelivered = []string{}
		for _, e := range req {
			if slices.Contains(SupportedEvents, e) {
				s.EventsDelivered = append(s.EventsDelivered, e)
			}
		}
	}
	if in.Description != nil || full {
		d := ""
		if in.Description != nil {
			d = *in.Description
		}
		if len(d) > maxDescription {
			return invalid("description is too long")
		}
		s.Description = d
	}
	return nil
}

// seal は push の Authorization ヘッダーの値を暗号化して s に置く。空なら付けない。
func (t *Transmitter) seal(ctx context.Context, tx port.Tx, s *port.SSFStream, header string) error {
	if header == "" || s.DeliveryMethod != port.SSFDeliveryPush {
		s.AuthorizationCiphertext = nil
		return nil
	}
	ct, err := t.Crypter.Encrypt(ctx, tx.DataKeys(), s.ID, []byte(header), AuthorizationAAD)
	s.AuthorizationCiphertext = ct
	return err
}

// Authorization は push で付ける Authorization ヘッダーの値（無ければ空）。
func (t *Transmitter) Authorization(ctx context.Context, tx port.Tx, s port.SSFStream) (string, error) {
	if len(s.AuthorizationCiphertext) == 0 {
		return "", nil
	}
	b, err := t.Crypter.Decrypt(ctx, tx.DataKeys(), s.ID, s.AuthorizationCiphertext, AuthorizationAAD)
	return string(b), err
}

// Get は受信側のストリームを返す。
func (t *Transmitter) Get(ctx context.Context, tx port.Tx, realmID string, c Caller, streamID string) (port.SSFStream, error) {
	return own(ctx, tx, realmID, c, streamID)
}

// List は受信側のストリームを作成の順に返す。
func (t *Transmitter) List(ctx context.Context, tx port.Tx, realmID string, c Caller) ([]port.SSFStream, error) {
	all, err := tx.SSFStreams().List(ctx, realmID)
	out := []port.SSFStream{}
	for _, s := range all {
		if s.ServiceAccountID == c.AccountID {
			out = append(out, s)
		}
	}
	return out, err
}

// Update はストリームを変える（PATCH）か置き換える（PUT、replace）。Authorization ヘッダーは delivery を送ったときだけ変える。
func (t *Transmitter) Update(ctx context.Context, tx port.Tx, realmID string, c Caller, in StreamInput, replace bool) (port.SSFStream, error) {
	s, err := own(ctx, tx, realmID, c, in.StreamID)
	if err != nil {
		return s, err
	}
	was := s.DeliveryMethod
	if err := t.apply(ctx, tx, &s, in, false, replace); err != nil {
		return s, err
	}
	if in.Delivery != nil {
		if err := t.seal(ctx, tx, &s, in.Delivery.AuthorizationHeader); err != nil {
			return s, err
		}
	}
	s.UpdatedAt = t.Clock.Now()
	if err := tx.SSFStreams().Update(ctx, s); err != nil {
		return s, err
	}
	if was == port.SSFDeliveryPoll && s.DeliveryMethod != port.SSFDeliveryPoll {
		// poll から push に変えたら、確認を待っていた SET は push で送り直さない（受信側が取りに来なくなる）。
		if err := clearPoll(ctx, tx, s); err != nil {
			return s, err
		}
	}
	return s, t.record(ctx, tx, AuditStreamUpdated, s, c, map[string]any{"status": s.Status})
}

// Delete はストリームと、その対象・待ちの SET・Authorization の鍵（データ鍵）を消す。
func (t *Transmitter) Delete(ctx context.Context, tx port.Tx, realmID string, c Caller, streamID string) error {
	s, err := own(ctx, tx, realmID, c, streamID)
	if err != nil {
		return err
	}
	return t.remove(ctx, tx, s, c.actor(), c.RequestID)
}

// AdminDelete は運営者がストリームを消す（受信側を問わない）。
func (t *Transmitter) AdminDelete(ctx context.Context, tx port.Tx, realmID, streamID string, actor audit.Actor, requestID string) error {
	s, err := tx.SSFStreams().Get(ctx, realmID, streamID)
	if err != nil {
		return err
	}
	return t.remove(ctx, tx, s, actor, requestID)
}

func (t *Transmitter) remove(ctx context.Context, tx port.Tx, s port.SSFStream, actor audit.Actor, requestID string) error {
	if err := tx.SSFStreams().Delete(ctx, s.RealmID, s.ID); err != nil {
		return err
	}
	if err := tx.DataKeys().Delete(ctx, s.ID); err != nil {
		return err
	}
	return t.recordAs(ctx, tx, AuditStreamDeleted, s, actor, requestID, nil)
}

// SetStatus はストリームの状態を変える。disabled から戻すと今から送り（止めていた間の出来事は捨てる）、paused から戻すと
// 止めた所から送る。disabled にすると poll の待ちの SET を捨てる。変われば stream-updated を送る。
func (t *Transmitter) SetStatus(ctx context.Context, tx port.Tx, realmID string, c Caller, in StreamStatus) (port.SSFStream, error) {
	s, err := own(ctx, tx, realmID, c, in.StreamID)
	if err != nil {
		return s, err
	}
	switch in.Status {
	case port.SSFStatusEnabled, port.SSFStatusPaused, port.SSFStatusDisabled:
	default:
		return s, invalid("status must be enabled, paused or disabled")
	}
	if len(in.Reason) > maxReason {
		return s, invalid("reason is too long")
	}
	if s.Status == in.Status && s.StatusReason == in.Reason {
		return s, nil
	}
	was := s.Status
	s.Status, s.StatusReason, s.UpdatedAt = in.Status, in.Reason, t.Clock.Now()
	if err := tx.SSFStreams().Update(ctx, s); err != nil {
		return s, err
	}
	switch {
	case in.Status == port.SSFStatusDisabled:
		if err := clearPoll(ctx, tx, s); err != nil {
			return s, err
		}
	case was == port.SSFStatusDisabled:
		last, err := tx.Audit().Last(ctx)
		if err != nil {
			return s, err
		}
		d := s.SSFStreamDelivery
		d.Failures, d.NextAttemptAt, d.LastError = 0, nil, ""
		if last != nil {
			d.CursorSeq = last.Seq
		}
		if err := tx.SSFStreams().SetDelivery(ctx, s.RealmID, s.ID, d); err != nil {
			return s, err
		}
		s.SSFStreamDelivery = d
	case in.Status == port.SSFStatusEnabled:
		d := s.SSFStreamDelivery
		d.Failures, d.NextAttemptAt, d.LastError = 0, nil, ""
		if err := tx.SSFStreams().SetDelivery(ctx, s.RealmID, s.ID, d); err != nil {
			return s, err
		}
		s.SSFStreamDelivery = d
	}
	extra := map[string]any{"status": s.Status, "previous_status": was}
	if s.StatusReason != "" {
		extra["reason"] = s.StatusReason
	}
	return s, t.record(ctx, tx, AuditStreamUpdated, s, c, extra)
}

func clearPoll(ctx context.Context, tx port.Tx, s port.SSFStream) error {
	for {
		evs, err := tx.SSFStreams().ListPollEvents(ctx, s.RealmID, s.ID, 500)
		if err != nil || len(evs) == 0 {
			return err
		}
		jtis := make([]string, 0, len(evs))
		for _, e := range evs {
			jtis = append(jtis, e.JTI)
		}
		if _, err := tx.SSFStreams().AckPollEvents(ctx, s.RealmID, s.ID, jtis); err != nil {
			return err
		}
	}
}

// AddSubject はストリームに対象を足す。対象は realm のユーザーに限る（知らなければ errs.NotFound）。
func (t *Transmitter) AddSubject(ctx context.Context, tx port.Tx, realmID, issuer string, c Caller, streamID string, sub *Subject) error {
	s, err := own(ctx, tx, realmID, c, streamID)
	if err != nil {
		return err
	}
	u, err := t.subjectUser(ctx, tx, realmID, issuer, sub)
	if err != nil {
		return err
	}
	if ok, err := tx.SSFStreams().HasSubject(ctx, realmID, s.ID, u.PublicID); err != nil || ok {
		return err
	}
	if n, err := tx.SSFStreams().CountSubjects(ctx, realmID, s.ID); err != nil {
		return err
	} else if n >= MaxSubjectsPerStream {
		return errs.WithCode(errs.KindConflict, "subject_limit", "too many subjects in the stream")
	}
	if err := tx.SSFStreams().AddSubject(ctx, realmID, s.ID, u.PublicID, t.Clock.Now()); err != nil {
		return err
	}
	return t.record(ctx, tx, AuditSubjectAdded, s, c, map[string]any{"user_id": u.PublicID})
}

// RemoveSubject はストリームから対象を外す。
func (t *Transmitter) RemoveSubject(ctx context.Context, tx port.Tx, realmID, issuer string, c Caller, streamID string, sub *Subject) error {
	s, err := own(ctx, tx, realmID, c, streamID)
	if err != nil {
		return err
	}
	u, err := t.subjectUser(ctx, tx, realmID, issuer, sub)
	if err != nil {
		return err
	}
	if err := tx.SSFStreams().RemoveSubject(ctx, realmID, s.ID, u.PublicID); err != nil {
		return err
	}
	return t.record(ctx, tx, AuditSubjectRemoved, s, c, map[string]any{"user_id": u.PublicID})
}

// ErrUnknownSubject は realm のユーザーに結び付かない対象。
var ErrUnknownSubject = errs.WithCode(errs.KindNotFound, "subject_not_found", "subject not found")

// subjectUser は送信側の API の対象を realm のユーザーにする。email（確認済みのメール）と、iss が自分の iss_sub（sub は公開 ID）。
func (t *Transmitter) subjectUser(ctx context.Context, tx port.Tx, realmID, issuer string, sub *Subject) (port.User, error) {
	if !sub.Valid() {
		return port.User{}, invalid("subject")
	}
	u, err := resolveUser(ctx, tx, t.Directory, realmID, sub.UserPart(), func(s *Subject) bool { return s.Iss == issuer }, nil)
	if errors.Is(err, ErrUnknownSubject) {
		return port.User{}, err
	}
	return u, err
}

// RequestVerification は検証のイベント（verification）を送るよう監査ログに残す。送るのは配送のループ。
func (t *Transmitter) RequestVerification(ctx context.Context, tx port.Tx, realmID string, c Caller, streamID, state string) error {
	s, err := own(ctx, tx, realmID, c, streamID)
	if err != nil {
		return err
	}
	if len(state) > maxState {
		return invalid("state is too long")
	}
	extra := map[string]any{}
	if state != "" {
		extra["state"] = state
	}
	return t.record(ctx, tx, AuditVerificationRequested, s, c, extra)
}

func (t *Transmitter) record(ctx context.Context, tx port.Tx, typ string, s port.SSFStream, c Caller, extra map[string]any) error {
	return t.recordAs(ctx, tx, typ, s, c.actor(), c.RequestID, extra)
}

// recordAs はストリームの出来事を監査ログに残す。push の URL はホスト名だけを残す（経路や問い合わせに秘密を含みうる）。
func (t *Transmitter) recordAs(ctx context.Context, tx port.Tx, typ string, s port.SSFStream, actor audit.Actor, requestID string, extra map[string]any) error {
	d := map[string]any{"stream_id": s.ID, "service_account_id": s.ServiceAccountID, "delivery": s.DeliveryMethod}
	if s.EndpointURL != "" {
		if u, err := url.Parse(s.EndpointURL); err == nil {
			d["host"] = u.Host
		}
	}
	if typ == AuditStreamCreated || typ == AuditStreamUpdated {
		d["events"] = nonNil(s.EventsDelivered)
	}
	for k, v := range extra {
		d[k] = v
	}
	_, err := eventlog.Record(ctx, tx, t.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: s.RealmID, Actor: actor,
		RequestID: requestID, Details: d})
	return err
}

// jtiOf は SET の jti（ストリーム・監査ログのイベント・何番目かから決める。送り直しても同じ値になり、受信側が重複を除ける）。
func jtiOf(streamID, eventID string, i int) string {
	h := sha256.Sum256([]byte(streamID + "\x00" + eventID + "\x00" + strconv.Itoa(i)))
	return hex.EncodeToString(h[:16])
}

// signed は1つのストリームに送る SET。
type signed struct {
	Seq int64
	JTI string
	SET string
	// Purged は account-purged を送った対象（届けたらストリームから外す。以後、その ID の対象は残さない）。
	Purged string
}

// forget は account-purged を届けた対象をストリームから外す。
func forget(ctx context.Context, tx port.Tx, s port.SSFStream, x signed) error {
	if x.Purged == "" {
		return nil
	}
	if err := tx.SSFStreams().RemoveSubject(ctx, s.RealmID, s.ID, x.Purged); err != nil && !errors.Is(err, errs.NotFound) {
		return err
	}
	return nil
}

// prepare は監査ログのレコードを、ストリーム s に送る SET にする（対象・求めたイベントで絞り、realm の鍵で署名する）。
func (t *Transmitter) prepare(ctx context.Context, tx port.Tx, s port.SSFStream, issuer string, rs []audit.Record,
	skip func(audit.Record, error)) ([]signed, error) {
	var out []signed
	for _, r := range rs {
		e, err := audit.Unmarshal(r.Payload)
		if err != nil {
			skip(r, err)
			continue
		}
		items, err := translate(ctx, tx, e)
		if err != nil {
			return nil, err
		}
		for i, it := range items {
			if it.Stream != "" {
				if it.Stream != s.ID {
					continue
				}
			} else {
				if !slices.Contains(s.EventsDelivered, it.Event) {
					continue
				}
				ok, err := tx.SSFStreams().HasSubject(ctx, s.RealmID, s.ID, it.User)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
			}
			jti := jtiOf(s.ID, e.ID, i)
			set, err := t.sign(ctx, tx, s, issuer, e, jti, it)
			if err != nil {
				return nil, err
			}
			x := signed{Seq: r.Seq, JTI: jti, SET: set}
			if it.Event == EventAccountPurged {
				x.Purged = it.User
			}
			out = append(out, x)
		}
	}
	return out, nil
}

// sign は SET（SSF 1.0 の 4 章）を ES256 で署名する。aud は受信側のサービスアカウントの ID。
func (t *Transmitter) sign(ctx context.Context, tx port.Tx, s port.SSFStream, issuer string, e audit.Event, jti string, it item) (string, error) {
	var sub *Subject
	switch {
	case it.Stream != "":
		sub = &Subject{Format: FormatOpaque, ID: s.ID}
	case it.Device != nil:
		sub = &Subject{Format: FormatComplex, User: &Subject{Format: FormatIssSub, Iss: issuer, Sub: it.User}, Device: it.Device}
	default:
		sub = &Subject{Format: FormatIssSub, Iss: issuer, Sub: it.User}
	}
	claims := map[string]any{"iss": issuer, "aud": s.ServiceAccountID, "iat": t.Clock.Now().Unix(), "jti": jti, "txn": e.ID,
		"sub_id": sub, "events": map[string]any{it.Event: it.Payload}}
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return t.Keys.Sign(ctx, tx, s.RealmID, port.AlgES256, SETType, b)
}

// Purge は全 realm のストリームを最大 limit 件、Authorization の鍵（データ鍵）とともに消す（フィーチャーの無効化）。
func Purge(ctx context.Context, tx port.Tx, limit int) (int, error) {
	ids, err := tx.SSFStreams().Purge(ctx, limit)
	if err != nil {
		return 0, err
	}
	for _, sid := range ids {
		if err := tx.DataKeys().Delete(ctx, sid); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
