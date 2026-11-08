package app

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/authn/pat"
	"github.com/imohiyoko/iam/authn/provider"
	"github.com/imohiyoko/iam/authn/serviceaccount"
	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/authz/permcatalog"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/port"
)

// 認可の判定の API（design.md 4.5、ADR 0064）。判定は判定の材料のキャッシュを使う（反映の遅れは validity_max_delay まで）。

// checkResource は API の対象のリソースを判定の形にする。種類と ID は両方か、どちらも無しか。
func checkResource(typ, rid *string) (check.Resource, bool) {
	var r check.Resource
	if typ != nil {
		r.Type = *typ
	}
	if rid != nil {
		r.ID = *rid
	}
	return r, (r.Type == "") == (r.ID == "")
}

// orgTarget は、対象が Org なら resource_id を判定先の Org（公開 ID）にして返す。org_id と食い違えば ok は false。
// 判定先を先に決め、その Org を内部 ID に直して所属を確かめるため（Checker はリソースの Org を判定先にする）。
func orgTarget(orgID *string, res check.Resource) (*string, check.Resource, bool) {
	if res.Type != check.ResourceOrg {
		return orgID, res, true
	}
	if orgID != nil && *orgID != res.ID {
		return nil, res, false
	}
	return &res.ID, check.Resource{}, true
}

// authorizeCheck は判定の問い合わせの呼び出し元を確かめる（ADR 0121）。連携先の権限の判定には、その権限のカタログの
// authz:check（カタログの単位の付与か realm 全体の付与）が要る。IAM 自身の権限（と形の正しくない操作）の判定には、realm 全体の
// authz:check が要る。連携先のサービスアカウントには自分のカタログの authz:check だけを渡し、ほかの連携先の権限を問い合わせ
// させない。
func (s adminServer) authorizeCheck(ctx context.Context, actions []string) (adminPrincipal, *denial, error) {
	var targets []check.Resource
	for _, a := range actions {
		res := check.Resource{}
		if prefix, ok := role.CatalogPrefix(a); ok {
			res = check.Resource{Type: permcatalog.ResourceType, ID: prefix}
		}
		if !slices.Contains(targets, res) {
			targets = append(targets, res)
		}
	}
	if len(targets) == 0 {
		targets = []check.Resource{{}}
	}
	var p adminPrincipal
	for _, res := range targets {
		var d *denial
		var err error
		if p, d, err = s.a.authorizeOn(ctx, role.PermAuthzCheck, res, true); d != nil || err != nil {
			return p, d, err
		}
	}
	return p, nil, nil
}

func (s adminServer) CheckAuthz(ctx context.Context, req adminapi.CheckAuthzRequestObject) (adminapi.CheckAuthzResponseObject, error) {
	var actions []string
	if req.Body != nil {
		actions = []string{req.Body.Action}
	}
	p, d, err := s.authorizeCheck(ctx, actions)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CheckAuthz401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CheckAuthz403JSONResponse(d.Body), nil
	case req.Body == nil:
		return adminapi.CheckAuthz400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	b := req.Body
	res, ok := checkResource(b.ResourceType, b.ResourceId)
	orgID := b.OrgId
	if ok {
		orgID, res, ok = orgTarget(orgID, res)
	}
	sa := b.PrincipalType != nil && *b.PrincipalType == adminapi.CheckRequestPrincipalTypeServiceAccount
	// サービスアカウントの判定（#152）は、フィーチャー service_accounts が動いているときだけ。
	if !ok || !role.ValidPermission(b.Action) || (sa && !s.a.plan.IsActive(feature.ServiceAccounts)) ||
		(b.PrincipalType != nil && !sa && *b.PrincipalType != adminapi.CheckRequestPrincipalTypeUser) {
		return adminapi.CheckAuthz400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	r, reasons, err := s.checkSubject(ctx, p, sa, b, orgID)
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.CheckAuthz404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	case reasons != nil:
		return adminapi.CheckAuthz200JSONResponse{Allowed: false, Reasons: &reasons}, nil
	}
	r.Action, r.Resource = b.Action, res
	dec, err := s.a.authz.Decide(ctx, s.a.realm.ID, r)
	if err != nil {
		return nil, err
	}
	return adminapi.CheckAuthz200JSONResponse(s.checkResult(dec)), nil
}

// checkResult は判定を API の形にする。条件だけで拒んだときは満たさなかった条件と step-up を付ける。
func (s adminServer) checkResult(dec check.Decision) adminapi.CheckResult {
	out := adminapi.CheckResult{Allowed: dec.Allow}
	if len(dec.Unmet) > 0 {
		out.Unmet = &dec.Unmet
		if v, m, ok := stepUpValues(dec.StepUp); ok && s.a.acrActive() {
			out.StepUp = &adminapi.StepUp{AcrValues: v, MaxAge: m}
		}
	}
	return out
}

// checkSubject は判定の主体・認証の文脈・Org（公開 ID の orgID）を 1 つのトランザクションで決め、Action と Resource の無い
// 判定の問いを返す。主体が使えなければ理由のコード（nil でない）。主体か Org が無ければ errs.NotFound。
func (s adminServer) checkSubject(ctx context.Context, caller adminPrincipal, sa bool, b *adminapi.CheckRequest, orgID *string) (check.Request, []string, error) {
	var r check.Request
	var reasons []string
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var principal check.Principal
		var err error
		if sa {
			principal, reasons, err = s.checkServiceAccount(ctx, tx, b.PrincipalId)
		} else {
			principal, reasons, err = s.checkUser(ctx, tx, b.PrincipalId)
		}
		if err != nil || reasons != nil {
			return err
		}
		r = check.Request{Principal: principal}
		if sa {
			r.Context, err = s.serviceAccountCheckContext(ctx, tx, principal.ID, b)
		} else {
			r.Context, err = s.checkContext(ctx, tx, caller, principal.ID, b)
		}
		if err != nil {
			return err
		}
		if orgID != nil && s.a.orgs != nil {
			o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *orgID)
			if err != nil {
				return err
			}
			r.OrgID = o.ID
		}
		return nil
	})
	return r, reasons, err
}

func (s adminServer) BatchCheckAuthz(ctx context.Context, req adminapi.BatchCheckAuthzRequestObject) (adminapi.BatchCheckAuthzResponseObject, error) {
	bad := adminapi.BatchCheckAuthz400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}
	// 件数の上限は、カタログごとの呼び出し元の確かめより先に見る（上限を超えた要求で判定を重ねない）。認証の 401 は先に返す。
	var actions []string
	if b := req.Body; b != nil && len(b.Checks) > 0 && len(b.Checks) <= s.a.cfg.Authz.BatchCheckMax {
		for _, c := range b.Checks {
			actions = append(actions, c.Action)
		}
	} else if _, authed := ctx.Value(adminKey{}).(adminPrincipal); authed {
		return bad, nil
	}
	p, d, err := s.authorizeCheck(ctx, actions)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.BatchCheckAuthz401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.BatchCheckAuthz403JSONResponse(d.Body), nil
	}
	b := req.Body
	items := make([]check.Item, len(b.Checks))
	for i, c := range b.Checks {
		res, ok := checkResource(c.ResourceType, c.ResourceId)
		// 判定の Org は org_id で共通に決めるので、Org を対象にする判定は受けない（付与の材料を 1 回で読むため）。
		if !ok || res.Type == check.ResourceOrg || !role.ValidPermission(c.Action) {
			return bad, nil
		}
		items[i] = check.Item{Action: c.Action, Resource: res}
	}
	one := &adminapi.CheckRequest{PrincipalId: b.PrincipalId, OrgId: b.OrgId, Sid: b.Sid, AccessToken: b.AccessToken, Context: b.Context}
	sa := false
	if b.PrincipalType != nil {
		switch *b.PrincipalType {
		case adminapi.BatchCheckRequestPrincipalTypeUser:
		case adminapi.BatchCheckRequestPrincipalTypeServiceAccount:
			sa = true
		default:
			return bad, nil
		}
	}
	if sa && !s.a.plan.IsActive(feature.ServiceAccounts) {
		return bad, nil
	}
	r, reasons, err := s.checkSubject(ctx, p, sa, one, b.OrgId)
	switch {
	case errors.Is(err, errs.NotFound):
		return adminapi.BatchCheckAuthz404JSONResponse(adminError("not_found", "")), nil
	case err != nil:
		return nil, err
	}
	out := adminapi.BatchCheckAuthz200JSONResponse{Results: make([]adminapi.CheckResult, len(items))}
	if reasons != nil {
		for i := range out.Results {
			rs := slices.Clone(reasons)
			out.Results[i] = adminapi.CheckResult{Allowed: false, Reasons: &rs}
		}
		return out, nil
	}
	decs, err := s.a.authz.DecideMany(ctx, s.a.realm.ID, r, items)
	if err != nil {
		return nil, err
	}
	for i, dec := range decs {
		out.Results[i] = s.checkResult(dec)
	}
	return out, nil
}

func (s publicServer) CheckMyAuthz(ctx context.Context, req publicapi.CheckMyAuthzRequestObject) (publicapi.CheckMyAuthzResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.CheckMyAuthz401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	b := req.Body
	if b == nil {
		return publicapi.CheckMyAuthz400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	res, ok := checkResource(b.ResourceType, b.ResourceId)
	orgID := b.OrgId
	if ok {
		orgID, res, ok = orgTarget(orgID, res)
	}
	if !ok || !role.ValidPermission(b.Action) {
		return publicapi.CheckMyAuthz400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	r := check.Request{Principal: check.Principal{Type: au.PrincipalType, ID: au.PrincipalID}, Action: b.Action, Resource: res, OrgID: au.ActiveOrgID,
		Context: sessionContext(au.Validated)}
	// realm の範囲の付与は所属を見ないので、判定の文脈の Org（指定したか、active な Org）に使える所属があるかを確かめる。
	if s.a.orgs != nil && (orgID != nil || r.OrgID != "") {
		member := false
		err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			if orgID != nil {
				o, err := tx.Orgs().GetByPublicID(ctx, s.a.realm.ID, *orgID)
				if err != nil {
					return err
				}
				r.OrgID = o.ID
			}
			var err error
			_, member, err = authzMembers{}.OrgRole(ctx, tx, s.a.realm.ID, r.Principal, r.OrgID, s.a.deps.Clock.Now())
			return err
		})
		if errors.Is(err, errs.NotFound) || (err == nil && !member) {
			// 無い Org と所属していない Org では何もできない（区別しない）。
			return publicapi.CheckMyAuthz200JSONResponse{Allowed: false}, nil
		}
		if err != nil {
			return nil, err
		}
	}
	d, err := s.a.authz.Decide(ctx, s.a.realm.ID, r)
	if err != nil {
		return nil, err
	}
	out := publicapi.CheckMyAuthz200JSONResponse{Allowed: d.Allow}
	if len(d.Unmet) > 0 {
		out.Unmet = &d.Unmet
		if v, m, ok := stepUpValues(d.StepUp); ok && s.a.acrActive() {
			out.StepUp = &publicapi.StepUp{AcrValues: v, MaxAge: m}
		}
	}
	return out, nil
}

// checkUser は判定の主体のユーザー（公開 ID）。使えないユーザーは理由のコードを返す（ログインと同じ規則。4.7、4.8）。
// 無ければ errs.NotFound。
func (s adminServer) checkUser(ctx context.Context, tx port.Tx, publicID string) (check.Principal, []string, error) {
	u, err := tx.Users().GetByPublicID(ctx, s.a.realm.ID, publicID)
	if err != nil {
		return check.Principal{}, nil, err
	}
	now := s.a.deps.Clock.Now()
	if _, err := account.Check(ctx, tx, u, now, now); err != nil {
		if ue, ok := errors.AsType[*account.UnavailableError](err); ok {
			return check.Principal{}, unavailableReasons(ue), nil
		}
		if errors.Is(err, account.ErrInactive) {
			return check.Principal{}, []string{"inactive"}, nil
		}
		return check.Principal{}, nil, err
	}
	return check.Principal{Type: port.PrincipalUser, ID: u.ID}, nil, nil
}

// unavailableReasons は使えない主体の理由のコード。空でも nil にしない（nil は「使える」の意味なので）。
func unavailableReasons(ue *account.UnavailableError) []string {
	if r := ue.Reasons(); r != nil {
		return r
	}
	return []string{}
}

// checkServiceAccount は判定の主体のサービスアカウント（#152）。削除済みは inactive、停止・有効期間の外・所属の Org が
// 使えないときはその理由のコード（ユーザーと同じ。4.7、4.8）。無ければ errs.NotFound。
func (s adminServer) checkServiceAccount(ctx context.Context, tx port.Tx, accountID string) (check.Principal, []string, error) {
	a, err := tx.ServiceAccounts().Get(ctx, s.a.realm.ID, accountID)
	if err != nil {
		return check.Principal{}, nil, err
	}
	if err := serviceaccount.Available(ctx, tx, a, s.a.deps.Clock.Now()); err != nil {
		if ue, ok := errors.AsType[*account.UnavailableError](err); ok {
			return check.Principal{}, unavailableReasons(ue), nil
		}
		if errors.Is(err, serviceaccount.ErrDeleted) {
			return check.Principal{}, []string{"inactive"}, nil
		}
		return check.Principal{}, nil, err
	}
	return check.Principal{Type: port.PrincipalServiceAccount, ID: a.ID}, nil, nil
}

// serviceAccountCheckContext はサービスアカウントの判定の文脈（ADR 0084）。主体のアクセストークン（管理 API 向けか自前の API
// 向け）を渡せば、その認証から組み立てる（attested）。API キーは受けない（秘密そのものを判定の問いに載せさせない）。
// トークンが使えないか、主体のものでないか、DPoP に結び付いていれば文脈なし。sid と申告の文脈はユーザーのためのものなので使わない。
func (s adminServer) serviceAccountCheckContext(ctx context.Context, tx port.Tx, accountID string, b *adminapi.CheckRequest) (*check.AuthContext, error) {
	if b.AccessToken == nil || !serviceaccount.IsAccessToken(*b.AccessToken) {
		return nil, nil
	}
	au, err := s.a.serviceAccounts.CheckAccessToken(ctx, tx, s.a.realm.ID, *b.AccessToken, s.a.deps.Clock.Now())
	// DPoP に結び付けたトークン（ADR 0113）は、ここでは鍵の証明を確かめられないので文脈にしない（盗んだトークンの文字列だけで
	// attested の条件を満たさせない）。
	if errors.Is(err, serviceaccount.ErrInvalid) || (err == nil && (au.Account.ID != accountID || au.JKT != "")) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return serviceAccountContext(au.Method, au.AuthTime), nil
}

// checkContext は判定の問いの認証の文脈（ADR 0084）。アクセストークンか sid があれば IAM がそこから組み立て（attested）、申告は
// 捨てる。どちらも無ければ、realm の設定 declared_context_clients に載せた呼び出し元の申告だけを使う（attested でない）。
// トークン・系列が使えないか主体のものでなければ、文脈なし（条件は満たさない）。
func (s adminServer) checkContext(ctx context.Context, tx port.Tx, caller adminPrincipal, userID string, b *adminapi.CheckRequest) (*check.AuthContext, error) {
	switch {
	case b.AccessToken != nil && pat.Looks(*b.AccessToken):
		// 本人の Personal Access Token（ADR 0109）。主体と同じユーザーのものなら、スコープで絞った文脈にする。
		au, err := s.a.authenticatePAT(ctx, tx, *b.AccessToken)
		if errors.Is(err, pat.ErrInvalid) || (err == nil && au.User.ID != userID) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return patContext(au), nil
	case b.AccessToken != nil:
		if s.a.tokens == nil {
			return nil, nil
		}
		acc, err := s.a.tokens.Validate(ctx, tx, s.a.realm.ID, *b.AccessToken)
		if errors.Is(err, provider.ErrInvalidToken) || (err == nil && acc.Grant.UserID != userID) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		risk, err := s.a.tokens.LineageRisk(ctx, tx, s.a.realm.ID, acc.Grant.SID)
		if err != nil {
			return nil, err
		}
		g := acc.Grant
		return &check.AuthContext{AMR: g.AuthMethods, Factors: check.Factors(g.AuthMethods), AuthTime: g.AuthTime, Risk: risk, Attested: true}, nil
	case b.Sid != nil:
		ses, _, err := s.a.sessions.CheckLineage(ctx, tx, s.a.realm.ID, *b.Sid, s.a.deps.Clock.Now())
		if errors.Is(err, session.ErrInvalid) || (err == nil && (ses.PrincipalType != port.PrincipalUser || ses.PrincipalID != userID)) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		risk, err := session.Risk(ctx, tx, ses)
		if err != nil {
			return nil, err
		}
		return &check.AuthContext{AMR: ses.AuthMethods, Factors: check.Factors(ses.AuthMethods), AuthTime: ses.AuthenticatedAt, Risk: risk, Attested: true}, nil
	case b.Context != nil:
		if caller.Type != port.PrincipalServiceAccount || !slices.Contains(s.a.settings.DeclaredContextClients, caller.Actor.ID) {
			return nil, nil
		}
		return declaredContext(ctx, tx, s.a.realm.ID, *b.Context)
	}
	return nil, nil
}

// declaredContext は申告の文脈。リスクは一覧で有効な種類・範囲内の値だけを残す。
func declaredContext(ctx context.Context, tx port.Tx, realmID string, in adminapi.DeclaredContext) (*check.AuthContext, error) {
	out := &check.AuthContext{}
	if in.Amr != nil {
		out.AMR = slices.Clone(*in.Amr)
		out.Factors = check.Factors(out.AMR)
	}
	if in.AuthTime != nil {
		out.AuthTime = *in.AuthTime
	}
	if in.Risk != nil && len(*in.Risk) > 0 {
		cat, err := session.Catalog(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		out.Risk, _ = cat.Keep(*in.Risk)
	}
	return out, nil
}
