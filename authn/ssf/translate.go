package ssf

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/imohiyoko/iam/shared/acr"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 監査ログの出来事から SSF のイベントを作る（ADR 0118）。新しい発生源は作らず、すでに監査ログに残っている出来事だけを読む。

// item は1つの監査ログの出来事から作った1つのイベント。
type item struct {
	Event   string
	Payload map[string]any
	// User はイベントの対象のユーザー（公開 ID）。ストリームの対象に入っているときだけ送る。空ならストリームのイベント。
	User string
	// Device は complex の device の部分（device-compliance-change）。無ければ nil。
	Device *Subject
	// Stream はストリームのイベント（verification・stream-updated）の宛先。
	Stream string
}

// セッションの入れ替え（同じログインの続き）による失効。本人のセッションが終わったわけではないので送らない。
var replacementReasons = []string{"rotated", "replaced_by_login", "second_factor_completed", "deletion_cancelled", "org_switched"}

// credentialTypes は認証方式の名前を CAEP の credential_type にする。知らない方式のイベントは送らない。
var credentialTypes = map[string]string{
	"password": "password", "passkey": "fido2-platform", "totp": "app", "hotp": "app", "push": "app",
	"sms": "phone-sms", "x509": "x509", "openid4vp": "verifiable-credential",
}

// translate は監査ログの出来事 e を SSF のイベントにする。読めない・送らない出来事は空。
func translate(ctx context.Context, tx port.Tx, e audit.Event) ([]item, error) {
	at := e.Time.Unix()
	user := detail(e, "user_id")
	if user == "" && e.Actor.Type == "user" {
		user = e.Actor.ID
	}
	if e.Result != audit.ResultSuccess {
		return nil, nil
	}
	switch e.Type {
	case "session.revoked":
		reason := detail(e, "reason")
		if user == "" || slices.Contains(replacementReasons, reason) {
			return nil, nil
		}
		p := map[string]any{"event_timestamp": at, "initiating_entity": initiator(e.Actor, user)}
		if reason != "" {
			p["reason_admin"] = map[string]any{"en": reason}
		}
		out := []item{{Event: EventSessionRevoked, Payload: p, User: user}}
		if _, all := e.Details["sessions"]; all {
			out = append(out, item{Event: EventSessionsRevoked, Payload: map[string]any{"event_timestamp": at}, User: user})
		}
		return out, nil
	case "credential.registered", "passkey.registered", "credential.revoked", "passkey.revoked", "totp.revoked", "password.removed":
		method := detail(e, "method")
		switch e.Type {
		case "passkey.registered", "passkey.revoked":
			method = "passkey"
		case "totp.revoked":
			method = "totp"
		case "password.removed":
			method = "password"
		}
		ct, ok := credentialTypes[method]
		if user == "" || !ok {
			return nil, nil
		}
		change := "delete"
		if e.Type == "credential.registered" || e.Type == "passkey.registered" {
			change = "create"
		}
		return []item{{Event: EventCredentialChange, User: user, Payload: map[string]any{"event_timestamp": at,
			"credential_type": ct, "change_type": change, "initiating_entity": initiator(e.Actor, user)}}}, nil
	case "credentials.revoked_all":
		// 侵害の疑いでの一括の無効化（運営者の初動）。パスワードを無効化したときだけ、漏れたものとして知らせる。
		if pw, _ := e.Details["password"].(bool); !pw || user == "" {
			return nil, nil
		}
		return []item{{Event: EventCredentialCompromise, User: user, Payload: map[string]any{"event_timestamp": at,
			"credential_type": "password", "reason_admin": map[string]any{"en": detail(e, "reason")}}}}, nil
	case "session.created":
		return assurance(ctx, tx, e, user)
	case "user.suspended":
		// 予約の停止は、始まったとき（user.suspension_started）に送る。
		if starts, err := time.Parse(time.RFC3339Nano, detail(e, "starts_at")); err != nil || starts.After(e.Time) {
			return nil, nil
		}
		return disabled(e, user), nil
	case "user.suspension_started", "user.validity_ended":
		return disabled(e, user), nil
	case "user.deleted":
		if user == "" {
			return nil, nil
		}
		return []item{{Event: EventAccountPurged, User: user, Payload: map[string]any{}}}, nil
	case AuditDevicePostureChanged:
		ref, status := detail(e, "device_ref"), detail(e, "status")
		if user == "" || ref == "" || (status != port.DeviceCompliant && status != port.DeviceNotCompliant) {
			return nil, nil
		}
		p := map[string]any{"event_timestamp": at, "current_status": status}
		if prev := detail(e, "previous_status"); prev == port.DeviceCompliant || prev == port.DeviceNotCompliant {
			p["previous_status"] = prev
		}
		return []item{{Event: EventDeviceComplianceChange, User: user, Device: &Subject{Format: FormatOpaque, ID: ref}, Payload: p}}, nil
	case AuditVerificationRequested:
		p := map[string]any{}
		if st := detail(e, "state"); st != "" {
			p["state"] = st
		}
		return []item{{Event: EventVerification, Stream: detail(e, "stream_id"), Payload: p}}, nil
	case AuditStreamUpdated:
		// 状態を変えたときだけ（設定の変更では送らない）。
		st := detail(e, "status")
		if st == "" || detail(e, "previous_status") == "" {
			return nil, nil
		}
		p := map[string]any{"status": st}
		if r := detail(e, "reason"); r != "" {
			p["reason"] = r
		}
		return []item{{Event: EventStreamUpdated, Stream: detail(e, "stream_id"), Payload: p}}, nil
	}
	return nil, nil
}

func disabled(e audit.Event, user string) []item {
	if user == "" {
		return nil
	}
	p := map[string]any{}
	if detail(e, "category") == "security_risk" {
		p["reason"] = "hijacking"
	}
	return []item{{Event: EventAccountDisabled, User: user, Payload: p}}
}

// assurance は認証の強さが変わったログイン（2要素目の確認・同じブラウザでのログインのやり直し）を assurance-level-change にする。
// 前のセッションの amr から前の AAL を求め、変わったときだけ送る。前のセッションが読めなければ送らない。
func assurance(ctx context.Context, tx port.Tx, e audit.Event, user string) ([]item, error) {
	prev := detail(e, "previous")
	if prev == "" {
		prev = detail(e, "replaced")
	}
	if prev == "" || user == "" {
		return nil, nil
	}
	old, err := tx.Sessions().Get(ctx, e.RealmID, prev)
	if errors.Is(err, errs.NotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// replaced は共有のブラウザで別の人のセッションのこともある。同じ本人のセッションのときだけ前後を比べる。
	u, err := tx.Users().GetByPublicID(ctx, e.RealmID, user)
	if errors.Is(err, errs.NotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if old.PrincipalType != port.PrincipalUser || old.PrincipalID != u.ID {
		return nil, nil
	}
	amr := stringList(e.Details["amr"])
	before, after := acr.AAL(old.AuthMethods), acr.AAL(amr)
	if before == after || after == 0 {
		return nil, nil
	}
	dir := "increase"
	if after < before {
		dir = "decrease"
	}
	p := map[string]any{"event_timestamp": e.Time.Unix(), "namespace": "NIST-AAL", "current_level": nistAAL(after),
		"change_direction": dir, "initiating_entity": "user"}
	if before > 0 {
		p["previous_level"] = nistAAL(before)
	}
	return []item{{Event: EventAssuranceLevelChange, User: user, Payload: p}}, nil
}

func nistAAL(n int) string { return "nist-aal" + strconv.Itoa(n) }

// initiator は CAEP の initiating_entity（本人・運営者・システム）。
func initiator(a audit.Actor, user string) string {
	switch {
	case a.Type == "user" && a.ID == user:
		return "user"
	case a.Type == "system" || a.Type == "":
		return "system"
	case a.Type == auditActorTransmitter:
		return "policy"
	}
	return "admin"
}

func detail(e audit.Event, key string) string {
	v, _ := e.Details[key].(string)
	return v
}

func stringList(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
