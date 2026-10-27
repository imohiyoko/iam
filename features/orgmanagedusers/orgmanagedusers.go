// Package orgmanagedusers はフィーチャー org_managed_users をバイナリに含める（design.md 11.11）。import すると登録される。
package orgmanagedusers

import (
	impl "github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.ManagedUsersFeature) }
