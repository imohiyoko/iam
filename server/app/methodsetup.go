package app

import (
	"context"
	"encoding/base64"

	"github.com/imohiyoko/iam/authn/method"
	"github.com/imohiyoko/iam/shared/port"
)

// methodSetup は、設定を持つ認証方式（port.ConfigurableAuthenticator）に渡すものを作る（ADR 0104）。EphemeralStore は方式と
// realm で前置きし、ブラインドインデックスは方式ごとの用途で作る。
func (a *App) methodSetup(realmID, realmSlug string) func(port.MethodInfo) port.MethodSetup {
	return func(i port.MethodInfo) port.MethodSetup {
		purpose := "authn.method." + i.Name + ".key"
		return port.MethodSetup{
			RealmID: realmID, RealmSlug: realmSlug, Decode: a.cfg.MethodSettings(i.Name), Ephemeral: method.Scoped(a.deps.Ephemeral, i.Name, realmID),
			Blind: func(ctx context.Context, value string) (string, error) {
				ix, err := a.pii.Index(ctx, purpose, value)
				if err != nil {
					return "", err
				}
				return base64.RawURLEncoding.EncodeToString(ix.Value), nil
			},
			SMS: a.deps.SMS, Push: a.deps.Push, Dev: a.cfg.Dev, Clock: a.deps.Clock, Log: a.deps.Logger,
		}
	}
}
