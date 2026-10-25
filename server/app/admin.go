package app

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

type adminKey struct{}

// adminPrincipal は管理 API の呼び出し元。
type adminPrincipal struct {
	Type port.PrincipalType
	ID   string
}

// withAdminAuth は管理 API の認証（サービスアカウントの API キー）。権限の判定は各操作で行う。
func (a *App) withAdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || key == "" {
			next.ServeHTTP(w, r)
			return
		}
		var sa port.ServiceAccount
		err := a.deps.Storage.Tx(r.Context(), func(ctx context.Context, tx port.Tx) error {
			var err error
			sa, err = serviceaccount.Authenticate(ctx, tx, a.realm.ID, strings.TrimSpace(key), a.deps.Clock.Now())
			return err
		})
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), adminKey{}, adminPrincipal{Type: port.PrincipalServiceAccount, ID: sa.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorize は呼び出し元が perm を持つかを確かめる。未認証なら 401、権限が無ければ 403 のコードを返す。
func (a *App) authorize(ctx context.Context, perm string) (adminPrincipal, string, error) {
	p, ok := ctx.Value(adminKey{}).(adminPrincipal)
	if !ok {
		return p, "authentication_failed", nil
	}
	var allowed bool
	err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		allowed, err = role.Allowed(ctx, tx, a.realm.ID, p.Type, p.ID, perm)
		return err
	})
	if err != nil {
		return p, "", err
	}
	if !allowed {
		return p, "permission_denied", nil
	}
	return p, "", nil
}

func (s adminServer) ClaimNotification(ctx context.Context, req adminapi.ClaimNotificationRequestObject) (adminapi.ClaimNotificationResponseObject, error) {
	p, code, err := s.a.authorize(ctx, role.PermNotificationsClaim)
	switch {
	case err != nil:
		return nil, err
	case code == "authentication_failed":
		return adminapi.ClaimNotification401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse{Error: code}}, nil
	case code != "":
		return adminapi.ClaimNotification403JSONResponse{Error: code}, nil
	}
	sec, err := s.a.notify.Claim(ctx, s.a.realm.ID, req.Id)
	if errors.Is(err, notify.ErrNotClaimable) {
		return adminapi.ClaimNotification404JSONResponse{Error: "not_found"}, nil
	}
	if err != nil {
		return nil, err
	}
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		_, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "notification.claimed", Result: audit.ResultSuccess, RealmID: s.a.realm.ID,
			Actor: audit.Actor{Type: string(p.Type), ID: p.ID}, RequestID: requestID(ctx),
			Details: map[string]any{"notification_id": req.Id},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := adminapi.ClaimNotification200JSONResponse{To: sec.To, ExpiresAt: sec.ExpiresAt}
	if sec.Code != "" {
		out.Code = &sec.Code
	}
	if sec.Token != "" {
		out.Token = &sec.Token
	}
	return out, nil
}
