// Package ssf は OpenID Shared Signals Framework 1.0（SSF）と、その上の CAEP・RISC のイベントを扱う（ADR 0118）。
//
// 送信側（フィーチャー ssf_transmitter）は、受信側（サービスアカウント）が SSF のストリーム管理の API で作ったストリームに、
// 監査ログの出来事から作った Security Event Token（SET、RFC 8417）を realm の鍵で署名して送る。配送は push（RFC 8935）と
// poll（RFC 8936）。監査ログを outbox にして、ストリームごとに処理した位置を持つ（イベントの Webhook の購読と同じ形。ADR 0100）。
//
// 受信側（フィーチャー ssf_receiver）は、登録した外部の送信側から push された SET を、その JWKS で確かめ、
// 送信側ごとに許した動作（セッションの失効・パスワードの無効化・停止・端末の準拠状態の記録）だけを本人に行う。
package ssf

import (
	"github.com/imohiyoko/iam/shared/feature"
)

// TransmitterFeature は SSF の送信側。受信側はサービスアカウントの、自前の API に向けたトークン（RFC 8707）で認証する。
// resource_indicators とサービスアカウントは前提だが、バイナリの依存（Requires）にはしない（前提を先に無効化できるように）。
// 前提が動いていなければ、送信側の API はどのトークンも受けない。
var TransmitterFeature = feature.Feature{Name: feature.SSFTransmitter, DataVersion: 1}

// ReceiverFeature は SSF の受信側。データは送信側の登録と端末の準拠状態。
var ReceiverFeature = feature.Feature{Name: feature.SSFReceiver, DataVersion: 1}

// イベントの種類（URI）。
const (
	caepPrefix = "https://schemas.openid.net/secevent/caep/event-type/"
	riscPrefix = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfPrefix  = "https://schemas.openid.net/secevent/ssf/event-type/"

	EventSessionRevoked         = caepPrefix + "session-revoked"
	EventCredentialChange       = caepPrefix + "credential-change"
	EventAssuranceLevelChange   = caepPrefix + "assurance-level-change"
	EventDeviceComplianceChange = caepPrefix + "device-compliance-change"

	EventAccountDisabled      = riscPrefix + "account-disabled"
	EventAccountPurged        = riscPrefix + "account-purged"
	EventCredentialCompromise = riscPrefix + "credential-compromise"
	EventSessionsRevoked      = riscPrefix + "sessions-revoked"

	EventVerification  = ssfPrefix + "verification"
	EventStreamUpdated = ssfPrefix + "stream-updated"
)

// SupportedEvents は送信側が送れるイベント（events_supported）。verification と stream-updated は求めなくても送る。
var SupportedEvents = []string{
	EventSessionRevoked, EventCredentialChange, EventAssuranceLevelChange, EventDeviceComplianceChange,
	EventAccountDisabled, EventAccountPurged, EventCredentialCompromise, EventSessionsRevoked,
}

// 配送の方法の URN（SSF 1.0 の delivery.method）。
const (
	DeliveryPushURN = "urn:ietf:rfc:8935"
	DeliveryPollURN = "urn:ietf:rfc:8936"
)

// SETType は SET の JWS ヘッダーの typ（SSF 1.0、RFC 8417 2.3）。
const SETType = "secevent+jwt"

// 監査ログの種類（SSF 自身の出来事）。
const (
	AuditStreamCreated          = "ssf.stream_created"
	AuditStreamUpdated          = "ssf.stream_updated"
	AuditStreamDeleted          = "ssf.stream_deleted"
	AuditSubjectAdded           = "ssf.subject_added"
	AuditSubjectRemoved         = "ssf.subject_removed"
	AuditVerificationRequested  = "ssf.verification_requested"
	AuditPollErrors             = "ssf.poll_errors"
	AuditTransmitterCreated     = "ssf.transmitter_created"
	AuditTransmitterUpdated     = "ssf.transmitter_updated"
	AuditTransmitterDeleted     = "ssf.transmitter_deleted"
	AuditSignalReceived         = "ssf.signal_received"
	AuditDevicePostureChanged   = "device_posture.changed"
	auditActorTransmitter       = "ssf_transmitter"
	auditActorTransmitterSystem = "system"
)
