package sinkfmt

import (
	"strings"

	"github.com/imohiyoko/iam/shared/audit"
)

// OCSF（Open Cybersecurity Schema Framework 1.3）の Identity & Access Management カテゴリ（category_uid 3）への対応。
// 種類はイベントの type の接頭辞で決め、IAM 固有の項目は unmapped に入れる。

// OCSFVersion は出力する OCSF の版。
const OCSFVersion = "1.3.0"

// OCSF のクラス。
const (
	ocsfAccountChange   = 3001
	ocsfAuthentication  = 3002
	ocsfEntityMgmt      = 3004
	ocsfUserAccessMgmt  = 3005
	ocsfGroupMgmt       = 3006
	ocsfCategoryIAM     = 3
	ocsfActivityOther   = 99
	ocsfSeverityInfo    = 1
	ocsfStatusSuccess   = 1
	ocsfStatusFailure   = 2
	ocsfActivityLogon   = 1
	ocsfActivityLogoff  = 2
	ocsfActivityCreate  = 1
	ocsfActivityDelete  = 4
	ocsfActivityUpdate  = 2
	ocsfProductName     = "iam"
	ocsfProductVendor   = "imohiyoko"
	ocsfLogName         = "audit"
	ocsfUnmappedVersion = 1
)

// classOf はイベントの type から OCSF のクラスを決める。
func classOf(typ string) int {
	prefix, _, _ := strings.Cut(typ, ".")
	switch prefix {
	case "login", "login_link", "session", "oidc", "rate_limit":
		return ocsfAuthentication
	case "user", "account", "email", "identity", "password", "passkey", "totp", "recovery", "recovery_codes":
		return ocsfAccountChange
	case "role", "authz":
		return ocsfUserAccessMgmt
	case "group":
		return ocsfGroupMgmt
	}
	return ocsfEntityMgmt
}

// activityOf はクラスと type の末尾から activity_id を決める（分からなければ Other）。
func activityOf(class int, typ string) int {
	switch {
	case class == ocsfAuthentication && (strings.HasSuffix(typ, ".succeeded") || strings.HasSuffix(typ, ".failed") || strings.HasPrefix(typ, "login")):
		return ocsfActivityLogon
	case class == ocsfAuthentication && (strings.Contains(typ, "logout") || strings.HasSuffix(typ, ".revoked") || strings.HasSuffix(typ, ".ended")):
		return ocsfActivityLogoff
	case class != ocsfAuthentication && strings.HasSuffix(typ, ".created"):
		return ocsfActivityCreate
	case class != ocsfAuthentication && (strings.HasSuffix(typ, ".deleted") || strings.HasSuffix(typ, ".removed")):
		return ocsfActivityDelete
	case class != ocsfAuthentication && (strings.HasSuffix(typ, ".updated") || strings.HasSuffix(typ, ".changed")):
		return ocsfActivityUpdate
	}
	return ocsfActivityOther
}

// OCSF はイベントを OCSF の形にする。e は Redact の後のもの。
func OCSF(e audit.Event) map[string]any {
	class := classOf(e.Type)
	act := activityOf(class, e.Type)
	status, statusID := "Success", ocsfStatusSuccess
	if e.Result == audit.ResultFailure {
		status, statusID = "Failure", ocsfStatusFailure
	}
	meta := map[string]any{
		"version":    OCSFVersion,
		"uid":        e.ID,
		"event_code": e.Type,
		"log_name":   ocsfLogName,
		"product":    map[string]any{"name": ocsfProductName, "vendor_name": ocsfProductVendor},
	}
	if e.RequestID != "" {
		meta["correlation_uid"] = e.RequestID
	}
	out := map[string]any{
		"class_uid":    class,
		"category_uid": ocsfCategoryIAM,
		"activity_id":  act,
		"type_uid":     class*100 + act,
		"time":         e.Time.UnixMilli(),
		"severity_id":  ocsfSeverityInfo,
		"status":       status,
		"status_id":    statusID,
		"message":      e.Type,
		"metadata":     meta,
		"actor":        map[string]any{"user": map[string]any{"uid": e.Actor.ID, "type": e.Actor.Type}},
	}
	if e.SessionID != "" {
		out["actor"].(map[string]any)["session"] = map[string]any{"uid": e.SessionID}
	}
	if e.IP != "" || e.UserAgent != "" {
		src := map[string]any{}
		if e.IP != "" {
			// 仮名は IP の形ではないので、ip ではなく uid に入れる。
			if strings.HasPrefix(e.IP, "p_") {
				src["uid"] = e.IP
			} else {
				src["ip"] = e.IP
			}
		}
		if e.UserAgent != "" {
			src["agent_list"] = []map[string]any{{"name": e.UserAgent}}
		}
		out["src_endpoint"] = src
	}
	unmapped := map[string]any{"v": ocsfUnmappedVersion}
	for k, v := range map[string]string{"realm_id": e.RealmID, "org_id": e.OrgID} {
		if v != "" {
			unmapped[k] = v
		}
	}
	if len(e.Details) > 0 {
		unmapped["details"] = e.Details
	}
	if e.Chain != nil {
		unmapped["chain"] = e.Chain
	}
	out["unmapped"] = unmapped
	return out
}
