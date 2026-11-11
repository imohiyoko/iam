// Package standardclaims はフィーチャー standard_claims（カスタム属性から OIDC の標準クレームへの対応付け。ADR 0127）を
// バイナリに含める。import すると登録される。
package standardclaims

import (
	"github.com/imohiyoko/iam/authn/attribute"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(attribute.StandardClaimsFeature) }
