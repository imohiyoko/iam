// Package personalaccesstokens はフィーチャー personal_access_tokens（本人の Personal Access Token。ADR 0109）をバイナリに含める
// （design.md 11.11）。import すると登録される。
package personalaccesstokens

import (
	impl "github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
