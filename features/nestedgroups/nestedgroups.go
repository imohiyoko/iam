// Package nestedgroups はフィーチャー nested_groups をバイナリに含める（design.md 11.5）。import すると登録される。
package nestedgroups

import (
	impl "github.com/imohiyoko/iam/authz/manage"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.NestedGroupsFeature) }
