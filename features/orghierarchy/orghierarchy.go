// Package orghierarchy はフィーチャー org_hierarchy をバイナリに含める（design.md 11.4）。import すると登録される。
package orghierarchy

import (
	impl "github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.HierarchyFeature) }
