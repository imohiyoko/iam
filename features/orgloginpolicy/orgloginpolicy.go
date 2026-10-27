// Package orgloginpolicy はフィーチャー org_login_policy（Org のログインポリシー）をバイナリに含める（design.md 11.11）。import すると登録される。
package orgloginpolicy

import (
	impl "github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.PolicyFeature) }
