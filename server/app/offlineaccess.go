package app

import (
	"context"
	"errors"
	"time"

	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/port"
)

// 本人の offline_access（フィーチャー offline_access。ADR 0126）。ログアウトしても残る認可を連携先ごとに見て、取り消す。

// offlineCleaner はフィーチャー offline_access の片付け。連携先の許可を外し、Offline の認可（とそのトークン）を消す。
var offlineCleaner = cleaner{
	Count: func(ctx context.Context, tx port.Tx) (int, error) {
		n, err := eachClient(ctx, tx, -1, func(c port.Client) (bool, error) { return c.OfflineAccess, nil })
		if err != nil {
			return 0, err
		}
		g, err := tx.Grants().CountOffline(ctx)
		return n + g, err
	},
	Purge: func(ctx context.Context, tx port.Tx, now time.Time, limit int) (int, error) {
		n, err := eachClient(ctx, tx, limit, func(c port.Client) (bool, error) {
			if !c.OfflineAccess {
				return false, nil
			}
			c.OfflineAccess, c.UpdatedAt = false, now
			return true, tx.Clients().Update(ctx, c)
		})
		if err != nil || n >= limit {
			return n, err
		}
		g, err := tx.Grants().PurgeOffline(ctx, limit-n)
		return n + g, err
	},
}

func (s publicServer) ListMyOfflineAccess(ctx context.Context, _ publicapi.ListMyOfflineAccessRequestObject) (publicapi.ListMyOfflineAccessResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.ListMyOfflineAccess401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.a.tokens.Offline {
		return publicapi.ListMyOfflineAccess404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	var apps []provider.OfflineApp
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		apps, err = s.a.tokens.OfflineApps(ctx, tx, s.a.realm.ID, au.PrincipalID)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := publicapi.ListMyOfflineAccess200JSONResponse{Applications: make([]publicapi.OfflineAccessApplication, 0, len(apps))}
	for _, a := range apps {
		out.Applications = append(out.Applications, publicapi.OfflineAccessApplication{ClientId: a.Client.PublicID, Name: a.Client.Name,
			Scopes: a.Scopes, CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt})
	}
	return out, nil
}

func (s publicServer) RevokeMyOfflineAccess(ctx context.Context, req publicapi.RevokeMyOfflineAccessRequestObject) (publicapi.RevokeMyOfflineAccessResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.RevokeMyOfflineAccess401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.a.tokens.Offline {
		return publicapi.RevokeMyOfflineAccess404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		return s.a.tokens.RevokeOffline(ctx, tx, s.a.realm.ID, au.PrincipalID, req.ClientId, s.a.clientOf(ctx).RequestID)
	})
	if errors.Is(err, errs.NotFound) {
		return publicapi.RevokeMyOfflineAccess404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if err != nil {
		return nil, err
	}
	return publicapi.RevokeMyOfflineAccess204Response{}, nil
}
