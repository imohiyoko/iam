// Package ldap はフィーチャー ldap（LDAP / Active Directory のバインド認証と同期。ADR 0102）をバイナリに含める。import すると登録される。
package ldap

import (
	impl "github.com/imohiyoko/iam/authn/method/ldap"
	"github.com/imohiyoko/iam/shared/feature"
)

func init() { feature.Register(impl.Feature) }
