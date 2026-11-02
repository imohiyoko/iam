package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	dirldap "github.com/imohiyoko/iam/authn/method/ldap"
	"github.com/imohiyoko/iam/authn/oauth"
	"github.com/imohiyoko/iam/authn/org"
	"github.com/imohiyoko/iam/authz/role"
	"github.com/imohiyoko/iam/server/adminapi"
	"github.com/imohiyoko/iam/server/publicapi"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/ratelimit"
)

// LDAP / Active Directory のバインド認証と同期（ADR 0102）。フィーチャー ldap。Org 専用の connection には org_managed_users も要る。

func (s publicServer) ldapCredentials(ctx context.Context, b publicapi.LDAPCredentials) dirldap.Credentials {
	c := s.a.clientOf(ctx)
	return dirldap.Credentials{Username: b.Username, Password: b.Password, Client: oauth.Client{IP: c.IP, UserAgent: c.UserAgent, RequestID: c.RequestID}}
}

func directoryUnavailable() publicapi.DirectoryUnavailableJSONResponse {
	return publicapi.DirectoryUnavailableJSONResponse{Error: errCode(dirldap.ErrUnavailable)}
}

func (s publicServer) LdapLogin(ctx context.Context, req publicapi.LdapLoginRequestObject) (publicapi.LdapLoginResponseObject, error) {
	fail := publicapi.LdapLogin401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	if s.a.ldap == nil {
		return publicapi.LdapLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return fail, nil
	}
	in := s.ldapCredentials(ctx, *req.Body)
	if tok, viaCookie := s.a.sessionToken(httpFrom(ctx).r); viaCookie {
		in.ReplaceToken = tok
	}
	res, err := s.a.ldap.Login(ctx, s.a.realm.ID, req.Connection, in)
	if d, ok := errors.AsType[errs.Denial](err); ok {
		return publicapi.LdapLogin403JSONResponse{DeniedJSONResponse: denied(d)}, nil
	}
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.LdapLogin429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.LdapLogin404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, dirldap.ErrUnavailable):
		return publicapi.LdapLogin503JSONResponse{DirectoryUnavailableJSONResponse: directoryUnavailable()}, nil
	// コードつきのものを先に比べる（OAuth と同じ）。
	case errors.Is(err, oauth.ErrSSODomainNotVerified):
		return publicapi.LdapLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, oauth.ErrQuotaExceeded):
		return publicapi.LdapLogin409JSONResponse(conflictOf(err, errs.CodeQuotaExceeded)), nil
	case errors.Is(err, oauth.ErrAccountExists):
		return publicapi.LdapLogin409JSONResponse{Error: "account_exists"}, nil
	case errors.Is(err, oauth.ErrEmailUnverified):
		return publicapi.LdapLogin400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "email_unverified"}}, nil
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.LdapLogin200JSONResponse(s.loginResult(ctx, res.Session, res.UserID, res.Created, req.Body.ReturnToken)), nil
}

func (s publicServer) LinkLDAPIdentity(ctx context.Context, req publicapi.LinkLDAPIdentityRequestObject) (publicapi.LinkLDAPIdentityResponseObject, error) {
	fail := publicapi.LinkLDAPIdentity401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}
	au, ok := authFrom(ctx)
	if !ok || req.Body == nil {
		return fail, nil
	}
	if s.stale(ctx, au) {
		return publicapi.LinkLDAPIdentity401JSONResponse{UnauthenticatedJSONResponse: reauthRequired()}, nil
	}
	if s.a.ldap == nil {
		return publicapi.LinkLDAPIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	ident, err := s.a.ldap.Link(ctx, s.a.realm.ID, req.Connection, au.PrincipalID, s.ldapCredentials(ctx, *req.Body))
	if ex, ok := errors.AsType[*ratelimit.ExceededError](err); ok {
		return publicapi.LinkLDAPIdentity429JSONResponse{RateLimitedJSONResponse: rateLimited(ex)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.LinkLDAPIdentity404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, dirldap.ErrUnavailable):
		return publicapi.LinkLDAPIdentity503JSONResponse{DirectoryUnavailableJSONResponse: directoryUnavailable()}, nil
	case errors.Is(err, oauth.ErrIdentityExists), errors.Is(err, oauth.ErrNotManagedByOwner):
		return publicapi.LinkLDAPIdentity409JSONResponse{ConflictJSONResponse: publicapi.ConflictJSONResponse{Error: errCode(err)}}, nil
	case errors.Is(err, errs.AuthenticationFailed):
		return fail, nil
	case err != nil:
		return nil, err
	}
	return publicapi.LinkLDAPIdentity200JSONResponse{Id: ident.PublicID, Connection: req.Connection, CreatedAt: ident.CreatedAt}, nil
}

func ldapSyncIn(b *publicapi.LDAPSync) dirldap.Sync {
	if b == nil {
		return dirldap.Sync{}
	}
	out := dirldap.Sync{Enabled: deref(b.Enabled), Provision: deref(b.Provision), IntervalSeconds: deref(b.IntervalSeconds)}
	if b.OnMissing != nil {
		out.OnMissing = string(*b.OnMissing)
	}
	return out
}

func adminLDAPSyncIn(b *adminapi.LDAPSync) dirldap.Sync {
	if b == nil {
		return dirldap.Sync{}
	}
	out := dirldap.Sync{Enabled: deref(b.Enabled), Provision: deref(b.Provision), IntervalSeconds: deref(b.IntervalSeconds)}
	if b.OnMissing != nil {
		out.OnMissing = string(*b.OnMissing)
	}
	return out
}

func orgLDAPInfo(in dirldap.Info) *publicapi.LDAPConnectionInfo {
	om := publicapi.LDAPSyncOnMissing(in.Sync.OnMissing)
	interval := int64(in.Sync.Interval().Seconds())
	return &publicapi.LDAPConnectionInfo{Url: in.URL, BindDn: in.BindDN, UserBaseDn: in.UserBaseDN, UserFilter: in.UserFilter,
		LoginAttribute: in.LoginAttribute, IdAttribute: in.IDAttribute, EmailAttribute: in.EmailAttribute, GroupBaseDn: optional(in.GroupBaseDN),
		GroupAttribute: optional(in.GroupAttribute), ActiveDirectory: in.ActiveDirectory, TrustEmail: in.TrustEmail, CaConfigured: in.CAConfigured,
		Pins: in.Pins, Sync: publicapi.LDAPSync{Enabled: &in.Sync.Enabled, IntervalSeconds: &interval, Provision: &in.Sync.Provision,
			OnMissing: &om}}
}

func adminLDAPInfo(in dirldap.Info) *adminapi.LDAPConnectionInfo {
	om := adminapi.LDAPSyncOnMissing(in.Sync.OnMissing)
	interval := int64(in.Sync.Interval().Seconds())
	return &adminapi.LDAPConnectionInfo{Url: in.URL, BindDn: in.BindDN, UserBaseDn: in.UserBaseDN, UserFilter: in.UserFilter,
		LoginAttribute: in.LoginAttribute, IdAttribute: in.IDAttribute, EmailAttribute: in.EmailAttribute, GroupBaseDn: optString(in.GroupBaseDN),
		GroupAttribute: optString(in.GroupAttribute), ActiveDirectory: in.ActiveDirectory, TrustEmail: in.TrustEmail, CaConfigured: in.CAConfigured,
		Pins: in.Pins, Sync: adminapi.LDAPSync{Enabled: &in.Sync.Enabled, IntervalSeconds: &interval, Provision: &in.Sync.Provision,
			OnMissing: &om}}
}

// AddOrgLDAPConnection は Org の LDAP の connection を登録する。
func (s publicServer) AddOrgLDAPConnection(ctx context.Context, req publicapi.AddOrgLDAPConnectionRequestObject) (publicapi.AddOrgLDAPConnectionResponseObject, error) {
	au, ok := authFrom(ctx)
	if !ok {
		return publicapi.AddOrgLDAPConnection401JSONResponse{UnauthenticatedJSONResponse: unauthenticated()}, nil
	}
	if !s.domainsOn() || s.a.ldap == nil {
		return publicapi.AddOrgLDAPConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	}
	if req.Body == nil {
		return publicapi.AddOrgLDAPConnection400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: "invalid_request"}}, nil
	}
	b := req.Body
	in := dirldap.ConnectionInput{URL: b.Url, CAPEM: deref(b.CaPem), BindDN: b.BindDn, BindPassword: b.BindPassword, UserBaseDN: b.UserBaseDn,
		UserFilter: deref(b.UserFilter), LoginAttribute: deref(b.LoginAttribute), IDAttribute: deref(b.IdAttribute), EmailAttribute: deref(b.EmailAttribute),
		GroupBaseDN: deref(b.GroupBaseDn), GroupAttribute: deref(b.GroupAttribute), ActiveDirectory: deref(b.ActiveDirectory), Sync: ldapSyncIn(b.Sync)}
	if b.Pins != nil {
		in.Pins = *b.Pins
	}
	var out publicapi.OrgConnection
	err := s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		o, _, err := s.orgMember(ctx, tx, au, req.Id, role.PermOrgSettings)
		if err == nil && o.Kind == port.OrgPersonal {
			err = org.ErrPersonalOrg
		}
		if err != nil {
			return err
		}
		c, err := dirldap.NewConnection(ctx, s.a.pii, s.a.deps.Clock.Now(), s.a.realm.ID, "", o.ID, in)
		if err != nil {
			return err
		}
		if err := s.a.orgs.AddConnection(ctx, tx, o, c, oauth.MaxOrgConnections, au.Actor(), requestID(ctx)); err != nil {
			return err
		}
		out, err = orgConnectionOut(c)
		return err
	})
	if c, ok := stateCode(err); ok {
		return publicapi.AddOrgLDAPConnection409JSONResponse{ConflictJSONResponse: conflictOf(err, c)}, nil
	}
	switch {
	case errors.Is(err, errs.NotFound):
		return publicapi.AddOrgLDAPConnection404JSONResponse{NotFoundJSONResponse: notFound()}, nil
	case errors.Is(err, errs.PermissionDenied):
		return publicapi.AddOrgLDAPConnection403JSONResponse{DeniedJSONResponse: orgDenied(err)}, nil
	case errors.Is(err, errs.Invalid):
		return publicapi.AddOrgLDAPConnection400JSONResponse{BadRequestJSONResponse: publicapi.BadRequestJSONResponse{Error: errCodeOr(err, "invalid_connection")}}, nil
	case err != nil:
		return nil, err
	}
	return publicapi.AddOrgLDAPConnection201JSONResponse(out), nil
}

func (s adminServer) CreateLDAPConnection(ctx context.Context, req adminapi.CreateLDAPConnectionRequestObject) (adminapi.CreateLDAPConnectionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.CreateLDAPConnection401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.CreateLDAPConnection403JSONResponse(d.Body), nil
	}
	if s.a.ldap == nil {
		return adminapi.CreateLDAPConnection404JSONResponse(adminError("ldap_disabled", "")), nil
	}
	bad := func(code, msg string) adminapi.CreateLDAPConnectionResponseObject {
		return adminapi.CreateLDAPConnection400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(code, msg))}
	}
	if req.Body == nil {
		return bad("invalid_connection", "body is required"), nil
	}
	b := req.Body
	if !slugPattern.MatchString(b.Slug) {
		return bad("invalid_connection", "slug must match "+slugPattern.String()), nil
	}
	in := dirldap.ConnectionInput{URL: b.Url, CAPEM: deref(b.CaPem), BindDN: b.BindDn, BindPassword: b.BindPassword, UserBaseDN: b.UserBaseDn,
		UserFilter: deref(b.UserFilter), LoginAttribute: deref(b.LoginAttribute), IDAttribute: deref(b.IdAttribute), EmailAttribute: deref(b.EmailAttribute),
		GroupBaseDN: deref(b.GroupBaseDn), GroupAttribute: deref(b.GroupAttribute), ActiveDirectory: deref(b.ActiveDirectory), TrustEmail: deref(b.TrustEmail),
		Sync: adminLDAPSyncIn(b.Sync)}
	if b.Pins != nil {
		in.Pins = *b.Pins
	}
	c, err := dirldap.NewConnection(ctx, s.a.pii, s.a.deps.Clock.Now(), s.a.realm.ID, b.Slug, "", in)
	if errors.Is(err, errs.Invalid) {
		var e *errs.Error
		errors.As(err, &e)
		return bad(errCodeOr(err, "invalid_connection"), e.Msg), nil
	}
	if err != nil {
		return nil, err
	}
	var out adminapi.AdminConnection
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		if err := tx.Connections().Create(ctx, c); err != nil {
			return err
		}
		if _, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{
			Type: "connection.created", Result: audit.ResultSuccess, RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
			Details: map[string]any{"connection_id": c.ID, "slug": c.Slug, "type": dirldap.Type},
		}); err != nil {
			return err
		}
		out, err = s.connectionOut(ctx, tx, c)
		return err
	})
	if errors.Is(err, errs.Conflict) {
		return adminapi.CreateLDAPConnection409JSONResponse(adminError("slug_exists", "")), nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.CreateLDAPConnection201JSONResponse(out), nil
}

func (s adminServer) UpdateLDAPConnection(ctx context.Context, req adminapi.UpdateLDAPConnectionRequestObject) (adminapi.UpdateLDAPConnectionResponseObject, error) {
	p, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.UpdateLDAPConnection401JSONResponse(d.Body), nil
	case d != nil:
		return adminapi.UpdateLDAPConnection403JSONResponse(d.Body), nil
	}
	if s.a.ldap == nil {
		return adminapi.UpdateLDAPConnection404JSONResponse(adminError("ldap_disabled", "")), nil
	}
	if req.Body == nil {
		return adminapi.UpdateLDAPConnection400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError("invalid_request", ""))}, nil
	}
	b := req.Body
	u := dirldap.Update{BindPassword: b.BindPassword, CAPEM: b.CaPem, Pins: b.Pins}
	if b.Sync != nil {
		sy := adminLDAPSyncIn(b.Sync)
		u.Sync = &sy
	}
	var out adminapi.AdminConnection
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		c, err := s.realmConnection(ctx, tx, req.Id)
		if err != nil {
			return err
		}
		if c.Type != dirldap.Type {
			return errs.New(errs.KindNotFound, "connection %s is not an ldap connection", c.ID)
		}
		c, changed, err := dirldap.UpdateConnection(ctx, s.a.pii, c, u)
		if err != nil {
			return err
		}
		if err := tx.Connections().UpdateConfig(ctx, s.a.realm.ID, c.ID, c.Config); err != nil {
			return err
		}
		if len(changed) > 0 {
			// 値は残さない（パスワードを含みうるため、変えた項目の名前だけ）。
			if _, err := eventlog.Record(ctx, tx, s.a.deps.Clock, audit.Event{Type: "connection.updated", Result: audit.ResultSuccess,
				RealmID: s.a.realm.ID, Actor: p.Actor, RequestID: requestID(ctx),
				Details: map[string]any{"connection_id": c.ID, "slug": c.Slug, "fields": changed}}); err != nil {
				return err
			}
		}
		out, err = s.connectionOut(ctx, tx, c)
		return err
	})
	switch {
	case errors.Is(err, errConnectionOwned):
		return adminapi.UpdateLDAPConnection409JSONResponse(adminError(errCode(err), "")), nil
	case errors.Is(err, errs.NotFound):
		return adminapi.UpdateLDAPConnection404JSONResponse(adminError("not_found", "")), nil
	case errors.Is(err, errs.Invalid):
		var e *errs.Error
		errors.As(err, &e)
		return adminapi.UpdateLDAPConnection400JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(adminError(errCodeOr(err, "invalid_connection"), e.Msg))}, nil
	case err != nil:
		return nil, err
	}
	return adminapi.UpdateLDAPConnection200JSONResponse(out), nil
}

// errSyncRunning は同じ connection の同期が動いていること。
var errSyncRunning = errs.WithCode(errs.KindFailedPrecondition, "sync_running", "a sync of this connection is running")

// ldapSyncLockTTL は同期の排他の期限（同期が異常に終わっても、これを過ぎれば次の同期が動ける）。
const ldapSyncLockTTL = time.Hour

// syncLDAP は connection の同期を 1 回行う。同じ connection の同期は、インスタンスをまたいで同時に 1 つだけ（EphemeralStore の排他）。
func (a *App) syncLDAP(ctx context.Context, c port.Connection, requestID string) (dirldap.SyncResult, error) {
	key := "ldap:sync:lock:v1:" + c.RealmID + ":" + c.ID
	n, err := a.deps.Ephemeral.Incr(ctx, key, ldapSyncLockTTL)
	if err != nil {
		return dirldap.SyncResult{}, err
	}
	if n != 1 {
		return dirldap.SyncResult{}, errSyncRunning
	}
	defer func() { _ = a.deps.Ephemeral.Delete(context.WithoutCancel(ctx), key) }()
	return a.ldap.Sync(ctx, c, requestID)
}

func (s adminServer) SyncLDAPConnection(ctx context.Context, req adminapi.SyncLDAPConnectionRequestObject) (adminapi.SyncLDAPConnectionResponseObject, error) {
	_, d, err := s.a.authorize(ctx, role.PermConnectionsManage)
	switch {
	case err != nil:
		return nil, err
	case d != nil && d.Status == http.StatusUnauthorized:
		return adminapi.SyncLDAPConnection401JSONResponse{ErrorJSONResponse: adminapi.ErrorJSONResponse(d.Body)}, nil
	case d != nil:
		return adminapi.SyncLDAPConnection403JSONResponse(d.Body), nil
	}
	if s.a.ldap == nil {
		return adminapi.SyncLDAPConnection404JSONResponse(adminError("ldap_disabled", "")), nil
	}
	var c port.Connection
	err = s.a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		c, err = tx.Connections().Get(ctx, s.a.realm.ID, req.Id)
		if err == nil && c.Type != dirldap.Type {
			err = errs.New(errs.KindNotFound, "connection %s is not an ldap connection", c.ID)
		}
		return err
	})
	if errors.Is(err, errs.NotFound) {
		return adminapi.SyncLDAPConnection404JSONResponse(adminError("not_found", "")), nil
	}
	if err != nil {
		return nil, err
	}
	res, err := s.a.syncLDAP(ctx, c, requestID(ctx))
	switch {
	case errors.Is(err, errSyncRunning):
		return adminapi.SyncLDAPConnection409JSONResponse(adminError("sync_running", "")), nil
	case errors.Is(err, dirldap.ErrUnavailable):
		return adminapi.SyncLDAPConnection503JSONResponse(adminError("directory_unavailable", "")), nil
	case err != nil:
		return nil, err
	}
	return adminapi.SyncLDAPConnection200JSONResponse{Entries: res.Entries, Skipped: res.Skipped, Linked: res.Linked, Provisioned: res.Provisioned,
		ProvisionSkipped: res.ProvisionSkipped, Missing: res.Missing, Suspended: res.Suspended, Reactivated: res.Reactivated,
		GroupsCreated: res.GroupsCreated, GroupConflicts: res.GroupConflicts, MembersAdded: res.MembersAdded, MembersRemoved: res.MembersRemoved,
		Complete: res.Complete, DeprovisionAborted: res.DeprovisionAborted}, nil
}

// runLDAPSync は同期の時期の来た connection を、全 realm から探して同期する（root だけが動かす）。時期は connection ごとの
// EphemeralStore の印で決め、インスタンスをまたいで 1 回にする。1 回の見回りで同期する connection の数を限る。
func (a *App) runLDAPSync(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		a.sweepLDAPSync(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// maxLDAPSyncsPerSweep は 1 回の見回りで同期する connection の上限。
const maxLDAPSyncsPerSweep = 10

func (a *App) sweepLDAPSync(ctx context.Context) {
	var realms []port.Realm
	if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
		var err error
		realms, err = tx.Realms().List(ctx)
		return err
	}); err != nil {
		a.deps.Logger.WarnContext(ctx, "ldap sync: list realms", "error", err)
		return
	}
	done := 0
	for _, r := range realms {
		ra, ok := a.forRealm(r.ID)
		if !ok || ra.ldap == nil {
			continue
		}
		var cs []port.Connection
		if err := a.deps.Storage.Tx(ctx, func(ctx context.Context, tx port.Tx) error {
			var err error
			cs, err = tx.Connections().List(ctx, r.ID)
			return err
		}); err != nil {
			a.deps.Logger.WarnContext(ctx, "ldap sync: list connections", "realm_id", r.ID, "error", err)
			continue
		}
		for _, c := range cs {
			if ctx.Err() != nil || done >= maxLDAPSyncsPerSweep {
				return
			}
			if c.Type != dirldap.Type || !ra.connectionUsable(c) {
				continue
			}
			cfg, err := dirldap.ConfigOf(c)
			if err != nil || !cfg.Sync.Enabled {
				continue
			}
			// 間隔に 1 回だけ：印が無い（期限が切れた）ときに置いた 1 つのインスタンスだけが同期する。
			n, err := a.deps.Ephemeral.Incr(ctx, "ldap:sync:due:v1:"+c.RealmID+":"+c.ID, cfg.Sync.Interval())
			if err != nil || n != 1 {
				continue
			}
			done++
			res, err := ra.syncLDAP(ctx, c, "")
			if err != nil {
				a.deps.Logger.WarnContext(ctx, "ldap sync", "connection_id", c.ID, "error", err)
				continue
			}
			a.deps.Logger.InfoContext(ctx, "ldap sync", "connection_id", c.ID, "entries", res.Entries, "suspended", res.Suspended,
				"provisioned", res.Provisioned, "members_added", res.MembersAdded, "members_removed", res.MembersRemoved)
		}
	}
}
