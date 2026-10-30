package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/notify"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
)

type adminKey struct{}

// adminPrincipal は管理 API の呼び出し元。
type adminPrincipal struct {
	Type port.PrincipalType
	ID   string // 内部 ID（ユーザー）またはサービスアカウントの ID
	// Actor は監査ログの行為者（ユーザーは公開 ID。ADR 0045）。
	Actor audit.Actor
	// AuthenticatedAt は運営者のセッションの認証の時刻（サービスアカウントでは空）。
	AuthenticatedAt time.Time
	// Context は呼び出し元の認証の文脈（ADR 0084）。付与の条件と権限の検査に使う。
	Context *check.AuthContext
}

// withAdminAuth は管理 API の認証。Bearer のトークンが運営者のセッションならそのユーザー、
// そうでなければサービスアカウントの API キーかアクセストークンとして確かめる。権限の判定は各操作で行う。
func (a *App) withAdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			next.ServeHTTP(w, r)
			return
		}
		var p adminPrincipal
		if _, _, isSession := session.SplitToken(key); isSession {
			v, err := a.sessions.Validate(r.Context(), a.realm.ID, key)
			if err != nil && !errors.Is(err, session.ErrInvalid) {
				a.unavailable(w, r, err)
				return
			}
			// 制限つき（2要素目の確認待ち・登録待ち・復旧中）のセッションは管理 API では未認証として扱う（4.1）。
			if err != nil || v.PrincipalType != port.PrincipalUser || v.Restriction != port.RestrictionNone {
				next.ServeHTTP(w, r)
				return
			}
			p = adminPrincipal{Type: port.PrincipalUser, ID: v.PrincipalID, Actor: v.Actor(), AuthenticatedAt: v.AuthenticatedAt, Context: sessionContext(v)}
		} else {
			var sa serviceaccount.Authenticated
			err := a.deps.Storage.Tx(r.Context(), func(ctx context.Context, tx port.Tx) error {
				var err error
				sa, err = a.serviceAccounts.Authenticate(ctx, tx, a.realm.ID, key, a.deps.Clock.Now())
				return err
			})
			if err != nil && !errors.Is(err, serviceaccount.ErrInvalid) {
				a.unavailable(w, r, err)
				return
			}
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			p = adminPrincipal{Type: port.PrincipalServiceAccount, ID: sa.Account.ID, Actor: audit.Actor{Type: "service_account", ID: sa.Account.ID},
				Context: serviceAccountContext(sa.Method, sa.AuthTime)}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminKey{}, p)))
	})
}

// denial は認証・認可の失敗。Status は 401 か 403。
type denial struct {
	Status int
	Body   adminapi.Error
}

// authorize は呼び出し元が perm を持つかを確かめる。未認証・再認証が要るなら 401、権限が無ければ 403。
// 運営者のセッションには直近の認証を求める（max_auth_age。4.11）。
func (a *App) authorize(ctx context.Context, perm string) (adminPrincipal, *denial, error) {
	return a.authorizeWith(ctx, perm, false)
}

// authorizeWith は authorize で、cached なら判定の材料のキャッシュを使う（数の多い問い合わせ。check の API）。
func (a *App) authorizeWith(ctx context.Context, perm string, cached bool) (adminPrincipal, *denial, error) {
	return a.authorizeOn(ctx, perm, check.Resource{}, cached)
}

// authorizeOn は authorizeWith で、判定の対象のリソースを res に限る（リソース単位の付与も効く）。
func (a *App) authorizeOn(ctx context.Context, perm string, res check.Resource, cached bool) (adminPrincipal, *denial, error) {
	p, ok := ctx.Value(adminKey{}).(adminPrincipal)
	if !ok {
		return p, &denial{http.StatusUnauthorized, adminapi.Error{Error: errs.CodeAuthenticationFailed}}, nil
	}
	if p.Type == port.PrincipalUser {
		if age := a.cfg.Security.Session.MaxAuthAge.Default.D(); a.deps.Clock.Now().Sub(p.AuthenticatedAt) > age {
			return p, &denial{http.StatusUnauthorized, adminapi.Error{Error: "reauthentication_required"}}, nil
		}
	}
	var allowed bool
	var err error
	if cached {
		allowed, err = a.authz.Check(ctx, a.realm.ID, check.Request{Principal: check.Principal{Type: p.Type, ID: p.ID}, Action: perm, Resource: res, Context: p.Context})
	} else {
		err = a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			// 運営者の操作は数が少なく、取り消しをすぐに効かせたいので、キャッシュを使わずに判定する。
			allowed, err = a.authz.CheckTx(ctx, tx, a.realm.ID, check.Request{Principal: check.Principal{Type: p.Type, ID: p.ID}, Action: perm, Resource: res, Context: p.Context})
			return err
		})
	}
	if err != nil {
		return p, nil, err
	}
	if !allowed {
		return p, &denial{http.StatusForbidden, adminapi.Error{Error: errs.CodePermissionDenied}}, nil
	}
	return p, nil, nil
}

func (s adminServer) ClaimNotification(ctx context.Context, req adminapi.ClaimNotificationRequestObject) (adminapi.ClaimNotificationResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermNotificationsClaim)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.ClaimNotification401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.ClaimNotification403JSONResponse(d.Body), nil
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
			Actor: p.Actor, RequestID: requestID(ctx),
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
