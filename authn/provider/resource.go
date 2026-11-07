package provider

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 自前の API（リソースサーバー）向けのトークン（Resource Indicators、RFC 8707。ADR 0112）。
//
// ホスト先は realm に API を「リソース」として登録する（URI・使えるスコープ・要求してよい連携先とサービスアカウント）。
// 認可コードフロー（authorize と PAR）とサービスアカウントの client credentials で resource を 1 つ指定すると、発行する
// アクセストークンの aud はその URI になり、スコープはリソースのスコープの中から選ぶ。リソースサーバーはイントロスペクション
// （RFC 7662）で aud とスコープを確かめる。リソースの削除と許可の取り消しは、発行済みのトークンにも次の検証から効く。

// ResourceFeature は自前の API 向けのトークンのフィーチャー（既定オフ）。
var ResourceFeature = feature.Feature{Name: feature.ResourceIndicators, DataVersion: 1}

// 登録の上限。
const (
	MaxResourceNameLength = 100
	MaxResourceScopes     = 50
	MaxResourcePrincipals = 100
	maxScopeLength        = 128
)

var (
	// ErrInvalidResource は登録の内容が正しくない（理由はメッセージ）。
	ErrInvalidResource = errs.WithCode(errs.KindInvalid, "invalid_resource", "invalid resource")
	// ErrResourceExists は URI が realm の中で重複する。
	ErrResourceExists = errs.WithCode(errs.KindConflict, "resource_exists", "resource already exists")
)

func invalidResource(msg string) error {
	return errs.WithCode(errs.KindInvalid, "invalid_resource", msg)
}

// reservedScopes はリソースのスコープに使えない名前（OIDC と IAM 自身のスコープ）。
var reservedScopes = []string{ScopeOpenID, ScopeEmail, ScopeAttributes, "profile", "address", "phone", "offline_access"}

// ValidResourceURI は resource に使える URI かを返す（RFC 8707 2：絶対 URI でフラグメントなし。クエリも受けない）。
// https（ループバックは http も）の URL か URN だけ。
func ValidResourceURI(s string) bool {
	if s == "" || len(s) > maxURILength || strings.ContainsAny(s, "#? \t\r\n") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "urn":
		return u.Opaque != "" && strings.Contains(u.Opaque, ":")
	case "https", "http":
		return ValidRedirectURI(s)
	}
	return false
}

// ValidScopeToken はスコープの名前（RFC 6749 3.3 の scope-token）として使えるかを返す。OIDC のスコープの名前は使えない。
func ValidScopeToken(s string) bool {
	if s == "" || len(s) > maxScopeLength || slices.Contains(reservedScopes, s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c == 0x22 || c == 0x5c || c > 0x7e {
			return false
		}
	}
	return true
}

// Resources は自前の API（リソース）の登録を管理する。
type Resources struct {
	Clock clock.Clock
}

// ResourceInput は登録・変更の内容。Clients と IntrospectionClients は連携先の client_id、ServiceAccounts はサービスアカウントの ID。
type ResourceInput struct {
	URI             string
	Name            string
	Scopes          []string
	Clients         []string
	ServiceAccounts []string
	// IntrospectionClients はこのリソースに向けたトークンをイントロスペクションしてよい連携先。空ならどれでもよい（ADR 0120）。
	IntrospectionClients []string
}

func uniq(v []string) []string {
	out := slices.Clone(v)
	slices.Sort(out)
	out = slices.Compact(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// normalize は内容を確かめ、並びをそろえる。連携先とサービスアカウントはこの realm にあること（削除済みは不可）。
func (in ResourceInput) normalize(ctx context.Context, tx port.Tx, realmID string) (ResourceInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > MaxResourceNameLength {
		return in, invalidResource("name")
	}
	if !ValidResourceURI(in.URI) {
		return in, invalidResource("uri")
	}
	if len(in.Scopes) > MaxResourceScopes || slices.ContainsFunc(in.Scopes, func(s string) bool { return !ValidScopeToken(s) }) {
		return in, invalidResource("scopes")
	}
	if len(in.Clients) > MaxResourcePrincipals || len(in.ServiceAccounts) > MaxResourcePrincipals || len(in.IntrospectionClients) > MaxResourcePrincipals {
		return in, invalidResource("too many clients or service accounts")
	}
	in.Scopes, in.Clients, in.ServiceAccounts = uniq(in.Scopes), uniq(in.Clients), uniq(in.ServiceAccounts)
	in.IntrospectionClients = uniq(in.IntrospectionClients)
	for _, c := range slices.Concat(in.Clients, in.IntrospectionClients) {
		_, err := tx.Clients().GetByPublicID(ctx, realmID, c)
		if errors.Is(err, errs.NotFound) {
			return in, invalidResource("unknown client " + c)
		}
		if err != nil {
			return in, err
		}
	}
	for _, a := range in.ServiceAccounts {
		if !id.Valid(id.ServiceAccount, a) {
			return in, invalidResource("unknown service account " + a)
		}
		sa, err := tx.ServiceAccounts().Get(ctx, realmID, a)
		if errors.Is(err, errs.NotFound) || (err == nil && sa.DeletedAt != nil) {
			return in, invalidResource("unknown service account " + a)
		}
		if err != nil {
			return in, err
		}
	}
	return in, nil
}

func (r *Resources) record(ctx context.Context, tx port.Tx, typ string, x port.OAuthResource, actor audit.Actor, requestID string) error {
	_, err := eventlog.Record(ctx, tx, r.Clock, audit.Event{Type: typ, Result: audit.ResultSuccess, RealmID: x.RealmID, Actor: actor,
		RequestID: requestID, Details: map[string]any{"resource_id": x.ID, "uri": x.URI, "scopes": x.Scopes, "clients": x.Clients,
			"service_accounts": x.ServiceAccounts, "introspection_clients": x.IntrospectionClients}})
	return err
}

// Create はリソースを登録する。URI が重複すれば ErrResourceExists。
func (r *Resources) Create(ctx context.Context, tx port.Tx, realmID string, in ResourceInput, actor audit.Actor, requestID string) (port.OAuthResource, error) {
	in, err := in.normalize(ctx, tx, realmID)
	if err != nil {
		return port.OAuthResource{}, err
	}
	now := r.Clock.Now()
	x := port.OAuthResource{ID: id.NewExternal(id.OAuthResource), RealmID: realmID, URI: in.URI, Name: in.Name, Scopes: in.Scopes,
		Clients: in.Clients, ServiceAccounts: in.ServiceAccounts, IntrospectionClients: in.IntrospectionClients, CreatedAt: now, UpdatedAt: now}
	if err := tx.OAuthResources().Create(ctx, x); err != nil {
		if errors.Is(err, errs.Conflict) {
			return port.OAuthResource{}, ErrResourceExists
		}
		return port.OAuthResource{}, err
	}
	return x, r.record(ctx, tx, "oauth_resource.created", x, actor, requestID)
}

// Update はリソースの登録を置き換える。
func (r *Resources) Update(ctx context.Context, tx port.Tx, x port.OAuthResource, in ResourceInput, actor audit.Actor, requestID string) (port.OAuthResource, error) {
	in, err := in.normalize(ctx, tx, x.RealmID)
	if err != nil {
		return port.OAuthResource{}, err
	}
	x.URI, x.Name, x.Scopes, x.Clients, x.ServiceAccounts, x.UpdatedAt = in.URI, in.Name, in.Scopes, in.Clients, in.ServiceAccounts, r.Clock.Now()
	x.IntrospectionClients = in.IntrospectionClients
	if err := tx.OAuthResources().Update(ctx, x); err != nil {
		if errors.Is(err, errs.Conflict) {
			return port.OAuthResource{}, ErrResourceExists
		}
		return port.OAuthResource{}, err
	}
	return x, r.record(ctx, tx, "oauth_resource.updated", x, actor, requestID)
}

// Delete はリソースを消す。
func (r *Resources) Delete(ctx context.Context, tx port.Tx, x port.OAuthResource, actor audit.Actor, requestID string) error {
	if err := tx.OAuthResources().Delete(ctx, x.RealmID, x.ID); err != nil {
		return err
	}
	return r.record(ctx, tx, "oauth_resource.deleted", x, actor, requestID)
}

// ResourceForClient は連携先 clientID（client_id）が resource に指定してよいリソースを返す。形が違う・登録されていない・
// 許されていなければ ErrInvalidTarget（RFC 8707 2 の invalid_target。理由は返さない）。
func ResourceForClient(ctx context.Context, tx port.Tx, realmID, uri, clientID string) (port.OAuthResource, error) {
	return resourceFor(ctx, tx, realmID, uri, func(x port.OAuthResource) bool { return slices.Contains(x.Clients, clientID) })
}

// ResourceForServiceAccount はサービスアカウント accountID が resource に指定してよいリソースを返す。使えなければ ErrInvalidTarget。
func ResourceForServiceAccount(ctx context.Context, tx port.Tx, realmID, uri, accountID string) (port.OAuthResource, error) {
	return resourceFor(ctx, tx, realmID, uri, func(x port.OAuthResource) bool { return slices.Contains(x.ServiceAccounts, accountID) })
}

func resourceFor(ctx context.Context, tx port.Tx, realmID, uri string, allowed func(port.OAuthResource) bool) (port.OAuthResource, error) {
	if !ValidResourceURI(uri) {
		return port.OAuthResource{}, ErrInvalidTarget
	}
	x, err := tx.OAuthResources().GetByURI(ctx, realmID, uri)
	if errors.Is(err, errs.NotFound) {
		return port.OAuthResource{}, ErrInvalidTarget
	}
	if err != nil {
		return port.OAuthResource{}, err
	}
	if !allowed(x) {
		return port.OAuthResource{}, ErrInvalidTarget
	}
	return x, nil
}
