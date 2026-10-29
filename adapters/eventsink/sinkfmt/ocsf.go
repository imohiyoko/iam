package sinkfmt

import (
	"net/netip"
	"slices"
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
	ocsfProductName     = "iam"
	ocsfProductVendor   = "imohiyoko"
	ocsfLogName         = "audit"
	ocsfUnmappedVersion = 1
	ocsfUnknown         = "unknown"
)

// mfaPrefixes は認証の要素（Account Change の MFA Factor Enable / Disable）。
var mfaPrefixes = []string{"passkey", "totp", "recovery_codes"}

// classOf はイベントの type から OCSF のクラスを決める。
func classOf(typ string) int {
	prefix, _, _ := strings.Cut(typ, ".")
	switch prefix {
	case "login", "login_link", "session", "oidc", "rate_limit":
		return ocsfAuthentication
	case "user", "account", "email", "identity", "password", "passkey", "totp", "recovery", "recovery_codes":
		return ocsfAccountChange
	case "authz":
		return ocsfUserAccessMgmt
	case "role":
		// 付与・取り消しは User Access Management、ロールそのものの作成・変更・削除は Entity Management。
		if typ == "role.granted" || typ == "role.revoked" {
			return ocsfUserAccessMgmt
		}
	case "group":
		return ocsfGroupMgmt
	}
	return ocsfEntityMgmt
}

// activityOf はクラスと type から、そのクラスの activity_id（OCSF 1.3 の列挙）を決める（分からなければ Other）。
func activityOf(class int, typ string) int {
	prefix, _, _ := strings.Cut(typ, ".")
	has := func(suffixes ...string) bool {
		for _, x := range suffixes {
			if strings.HasSuffix(typ, "."+x) {
				return true
			}
		}
		return false
	}
	switch class {
	case ocsfAuthentication: // 1 Logon, 2 Logoff
		switch {
		case strings.Contains(typ, "logout") || has("revoked", "ended"):
			return 2
		case has("succeeded", "failed") || strings.HasPrefix(typ, "login"):
			return 1
		}
	case ocsfAccountChange: // 1 Create, 2 Enable, 3 Password Change, 4 Password Reset, 5 Disable, 6 Delete, 9 Lock, 10/11 MFA
		mfa := slices.Contains(mfaPrefixes, prefix)
		switch {
		case mfa && has("created", "registered", "enabled"):
			return 10
		case mfa && has("deleted", "removed", "disabled", "revoked"):
			return 11
		case prefix == "password" && has("reset"):
			return 4
		case prefix == "password" && has("changed", "updated", "set"):
			return 3
		case has("created"):
			return 1
		case has("enabled", "suspension_lifted"):
			return 2
		case has("disabled", "suspended"):
			return 5
		case has("deleted", "removed"):
			return 6
		case has("locked"):
			return 9
		}
	case ocsfEntityMgmt: // 1 Create, 3 Update, 4 Delete, 8 Enable, 9 Disable, 12 Suspend, 13 Resume
		switch {
		case has("created"):
			return 1
		case has("updated", "changed", "renamed", "settings_changed"):
			return 3
		case has("deleted", "removed"):
			return 4
		case has("enabled"):
			return 8
		case has("disabled"):
			return 9
		case has("suspended"):
			return 12
		case has("resumed", "suspension_lifted"):
			return 13
		}
	case ocsfUserAccessMgmt: // 1 Assign Privileges, 2 Revoke Privileges
		switch {
		case has("granted", "assigned"):
			return 1
		case has("revoked", "removed"):
			return 2
		}
	case ocsfGroupMgmt: // 1 Assign Privileges, 2 Revoke Privileges, 3 Add User, 4 Remove User, 5 Delete, 6 Create
		switch {
		case has("member_added"):
			return 3
		case has("member_removed"):
			return 4
		case has("deleted"):
			return 5
		case has("created"):
			return 6
		}
	}
	return ocsfActivityOther
}

// detail は details の文字列の値（無ければ空）。
func detail(e audit.Event, key string) string {
	v, _ := e.Details[key].(string)
	return v
}

// named は uid と name の組（どちらも無ければ name を unknown にする。OCSF の対象は必須なので省かない）。
func named(uid, name string) map[string]any {
	m := map[string]any{}
	if uid != "" {
		m["uid"] = uid
	}
	if name != "" {
		m["name"] = name
	}
	if len(m) == 0 {
		m["name"] = ocsfUnknown
	}
	return m
}

// targetUser はイベントの対象の利用者。details の user_id（無ければ principal_id）、それも無く主体が利用者なら主体。
func targetUser(e audit.Event) map[string]any {
	uid := detail(e, "user_id")
	if uid == "" && (detail(e, "principal_type") == "" || detail(e, "principal_type") == "user") {
		uid = detail(e, "principal_id")
	}
	if uid == "" && e.Actor.Type == "user" {
		uid = e.Actor.ID
	}
	return named(uid, "")
}

// targets はクラスごとに必須の対象（Authentication・Account Change は user、User Access Management は user と
// privileges、Group Management は group、Entity Management は entity）を out に足す。
func targets(out map[string]any, class int, e audit.Event) {
	prefix, _, _ := strings.Cut(e.Type, ".")
	switch class {
	case ocsfAuthentication, ocsfAccountChange:
		out["user"] = targetUser(e)
	case ocsfUserAccessMgmt:
		out["user"] = targetUser(e)
		priv := detail(e, "role")
		if priv == "" {
			priv = e.Type
		}
		out["privileges"] = []string{priv}
	case ocsfGroupMgmt:
		out["group"] = named(detail(e, "group_id"), detail(e, "name"))
		if m := detail(e, "member_id"); m != "" {
			out["user"] = named(m, "")
		}
	default:
		uid := detail(e, prefix+"_id")
		if uid == "" && prefix == "org" {
			uid = e.OrgID
		}
		ent := named(uid, detail(e, "name"))
		ent["type"] = prefix
		out["entity"] = ent
	}
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
	targets(out, class, e)
	if e.SessionID != "" {
		out["actor"].(map[string]any)["session"] = map[string]any{"uid": e.SessionID}
	}
	if e.IP != "" || e.UserAgent != "" {
		src := map[string]any{}
		if e.IP != "" {
			// 仮名は IP の形ではないので、ip ではなく uid に入れる。
			// 切り詰めた IP（CIDR）はアドレスではないので subnet_uid に入れる（ip は完全なアドレスのときだけ）。
			if strings.HasPrefix(e.IP, "p_") {
				src["uid"] = e.IP
			} else if _, err := netip.ParseAddr(e.IP); err == nil {
				src["ip"] = e.IP
			} else {
				src["subnet_uid"] = e.IP
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
