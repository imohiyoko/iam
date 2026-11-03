package port

import (
	"context"
	"time"
)

// OpenID Shared Signals Framework（SSF 1.0、CAEP・RISC。ADR 0118）の Repository。
// 送信側（フィーチャー ssf_transmitter）はストリームと、その対象・ポーリングの待ちの SET を持つ。
// 受信側（フィーチャー ssf_receiver）は信頼する送信側の登録と、端末の準拠状態（device posture input）を持つ。

// SSF のストリームの配送の方法と状態。
const (
	SSFDeliveryPush = "push" // RFC 8935（iam が受信側の URL に POST する）
	SSFDeliveryPoll = "poll" // RFC 8936（受信側が iam に取りに来る）

	SSFStatusEnabled  = "enabled"
	SSFStatusPaused   = "paused"   // 送らずに位置で止める（再開すると止めた所から送る）
	SSFStatusDisabled = "disabled" // 送らずに捨てる（再開すると今から送る）
)

// SSFStream は ssf_streams の1行（送信側のストリーム。受信側はサービスアカウント）。
type SSFStream struct {
	ID      string // 外部 ID（stream_id）
	RealmID string
	// ServiceAccountID はストリームを作った受信側（サービスアカウントの ID）。受信側は自分のストリームだけを扱える。
	ServiceAccountID string
	DeliveryMethod   string // SSFDeliveryPush / SSFDeliveryPoll
	// EndpointURL は push の送り先（受信側の URL）。poll では空。
	EndpointURL string
	// AuthorizationCiphertext は push で送る Authorization ヘッダーの値の暗号文（データ鍵の owner はストリームの ID）。無ければ空。
	AuthorizationCiphertext []byte
	// EventsRequested は受信側が求めたイベントの種類（URI）、EventsDelivered は送信側が送ると決めたもの（求めたものと送れるものの共通部分）。
	EventsRequested []string
	EventsDelivered []string
	Description     string
	Status          string // SSFStatus*
	StatusReason    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	SSFStreamDelivery
}

// SSFStreamDelivery はストリームの配送の状態。CursorSeq は監査ログの seq（そこまで処理した）。
type SSFStreamDelivery struct {
	CursorSeq       int64
	Failures        int
	NextAttemptAt   *time.Time
	LastError       string
	LastDeliveredAt *time.Time
}

// SSFPollEvent は ssf_poll_events の1行（poll のストリームで受信側の確認を待つ SET）。
type SSFPollEvent struct {
	RealmID  string
	StreamID string
	JTI      string
	// Seq は元の監査ログの seq（返す順）。
	Seq       int64
	SET       string // 署名済みの SET（compact の JWS）
	CreatedAt time.Time
}

// SSFStreamRepo は ssf_streams・ssf_stream_subjects・ssf_poll_events の Repository。
type SSFStreamRepo interface {
	// Create は ID が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, s SSFStream) error
	// Get は無ければ errs.NotFound。
	Get(ctx context.Context, realmID, id string) (SSFStream, error)
	// List は realm のストリームを作成の順（同時刻は ID の順）に返す。
	List(ctx context.Context, realmID string) ([]SSFStream, error)
	// Update は設定と状態（配送の方法・URL・Authorization・イベント・説明・状態・更新時刻）を書く。配送の状態は変えない。
	// 無ければ errs.NotFound。
	Update(ctx context.Context, s SSFStream) error
	// SetDelivery は配送の状態を書く。CursorSeq は今より大きいときだけ進める（戻さない）。無ければ errs.NotFound。
	SetDelivery(ctx context.Context, realmID, id string, d SSFStreamDelivery) error
	// Delete はストリームと、その対象・待ちの SET を消す。無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
	// DuePush は全 realm の、状態が enabled の push のストリームで NextAttemptAt が now 以前（または無い）ものを、
	// NextAttemptAt の早い順（無いものが先、同じなら ID の順）に最大 limit 件返す。
	DuePush(ctx context.Context, now time.Time, limit int) ([]SSFStream, error)

	// AddSubject はストリームに対象（ユーザーの公開 ID）を足す。既にあれば何もしない。
	AddSubject(ctx context.Context, realmID, streamID, subject string, at time.Time) error
	// RemoveSubject は対象を外す。無ければ errs.NotFound。
	RemoveSubject(ctx context.Context, realmID, streamID, subject string) error
	// HasSubject は対象がストリームにあるかを返す。
	HasSubject(ctx context.Context, realmID, streamID, subject string) (bool, error)
	// CountSubjects はストリームの対象の数を返す。
	CountSubjects(ctx context.Context, realmID, streamID string) (int, error)
	// RemoveSubjectEverywhere は realm の全ストリームから対象を外し、その数を返す（ユーザーの消去）。
	RemoveSubjectEverywhere(ctx context.Context, realmID, subject string) (int, error)

	// AddPollEvents は待ちの SET を足す。同じ (stream, jti) があれば足さない（少なくとも1回の再試行で重ならないように）。
	AddPollEvents(ctx context.Context, evs []SSFPollEvent) error
	// ListPollEvents はストリームの待ちの SET を Seq の順（同じなら jti の順）に最大 limit 件返す。
	ListPollEvents(ctx context.Context, realmID, streamID string, limit int) ([]SSFPollEvent, error)
	// CountPollEvents はストリームの待ちの SET の数を返す。
	CountPollEvents(ctx context.Context, realmID, streamID string) (int, error)
	// AckPollEvents は確認を受けた SET を消し、消した数を返す（知らない jti は無視する）。
	AckPollEvents(ctx context.Context, realmID, streamID string, jtis []string) (int, error)

	// Count は全 realm のストリームの数（フィーチャーの無効化。design.md 11.12）。
	Count(ctx context.Context) (int, error)
	// Purge は全 realm のストリームを最大 limit 件、対象・待ちの SET とともに消し、消したストリームの ID を返す
	// （データ鍵は呼び出し側が消す）。
	Purge(ctx context.Context, limit int) ([]string, error)
}

// SSFTransmitter は ssf_transmitters の1行（受信側として信頼する外部の送信側）。
type SSFTransmitter struct {
	ID      string // 外部 ID（受信の URL に入る）
	RealmID string
	Name    string
	// Issuer は SET の iss（完全一致）。realm の中で一意。
	Issuer string
	// Config は残りの設定（JSON。形は authn/ssf の TransmitterConfig。JWKS、aud、許す動作など）。
	Config []byte
	// PushTokenHash は送信側が push で付ける Authorization: Bearer の値の SHA-256。
	PushTokenHash []byte
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SSFTransmitterRepo は ssf_transmitters の Repository。
type SSFTransmitterRepo interface {
	// Create は ID・(realm, Issuer) が重複すれば errs.Conflict を返す。
	Create(ctx context.Context, t SSFTransmitter) error
	// Get は無ければ errs.NotFound。
	Get(ctx context.Context, realmID, id string) (SSFTransmitter, error)
	// List は realm の送信側を作成の順（同時刻は ID の順）に返す。
	List(ctx context.Context, realmID string) ([]SSFTransmitter, error)
	// Update は ID・realm・作成時刻以外を置き換える。無ければ errs.NotFound、Issuer が重複すれば errs.Conflict。
	Update(ctx context.Context, t SSFTransmitter) error
	// Delete は無ければ errs.NotFound。
	Delete(ctx context.Context, realmID, id string) error
	// Count と Purge はフィーチャーの無効化（全 realm）。
	Count(ctx context.Context) (int, error)
	Purge(ctx context.Context, limit int) (int, error)
}

// 端末の準拠状態。
const (
	DeviceCompliant    = "compliant"
	DeviceNotCompliant = "not-compliant"
)

// DevicePosture は ssf_device_postures の1行（device posture input。ADR 0118）。ユーザーと端末ごとの最新の準拠状態で、
// CAEP の device-compliance-change を受けて書く（今は MDM などの外部の送信側から）。認可の層が後で条件に使う。
type DevicePosture struct {
	RealmID string
	UserID  string // ユーザーの内部 ID
	// DeviceID は送信側が示した端末の識別子（opaque の id、または iss_sub の "iss sub"）。
	DeviceID string
	Status   string // DeviceCompliant / DeviceNotCompliant
	// Source は知らせた送信側（ssf_transmitters の ID）。
	Source string
	// EventAt は状態が変わった時刻（SET の event_timestamp、無ければ iat）。これより古い知らせでは上書きしない。
	EventAt   time.Time
	UpdatedAt time.Time
}

// DevicePostureRepo は ssf_device_postures の Repository（device posture input）。
type DevicePostureRepo interface {
	// Set は (realm, user, device) の状態を書く。既にある行の EventAt が p.EventAt より新しければ書かずに false を返す
	// （順序の入れ替わりで古い状態に戻さない）。
	Set(ctx context.Context, p DevicePosture) (bool, error)
	// Get は無ければ errs.NotFound。
	Get(ctx context.Context, realmID, userID, deviceID string) (DevicePosture, error)
	// ListByUser はユーザーの端末の状態を DeviceID の順に返す。
	ListByUser(ctx context.Context, realmID, userID string) ([]DevicePosture, error)
	// DeleteByUser はユーザーの行を消す（ユーザーの消去）。DeleteBySource は送信側の行を消す（送信側の登録の削除）。
	DeleteByUser(ctx context.Context, realmID, userID string) (int, error)
	DeleteBySource(ctx context.Context, realmID, source string) (int, error)
	// Count と Purge はフィーチャーの無効化（全 realm）。
	Count(ctx context.Context) (int, error)
	Purge(ctx context.Context, limit int) (int, error)
}
