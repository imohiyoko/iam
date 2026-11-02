// Package orgauditlog はフィーチャー org_audit_log をバイナリに含める（ADR 0100）。import すると登録される。
package orgauditlog

import (
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(eventlog.OrgAuditLogFeature) }
