// Package all はすべてのフィーチャーをバイナリに含める（テストと全部入りの構成用）。
package all

import (
	_ "github.com/imohiyoko/iam/features/org"
	_ "github.com/imohiyoko/iam/features/orgloginpolicy"
	_ "github.com/imohiyoko/iam/features/orgmanagedusers"
	_ "github.com/imohiyoko/iam/features/password"
	_ "github.com/imohiyoko/iam/features/quota"
	_ "github.com/imohiyoko/iam/features/serviceaccounts"
	_ "github.com/imohiyoko/iam/features/warnings"
)
