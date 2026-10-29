package serviceaccount

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// 上限。
const (
	MaxNameLength = 100
	// MaxCredentials は1つのサービスアカウントが同時に持てる、使える認証情報の数（ローテーションの重なりに足りる数）。
	MaxCredentials = 10
)

var (
	ErrInvalidName = errs.WithCode(errs.KindInvalid, "invalid_name", "name is required and at most 100 characters")
	ErrInvalidType = errs.WithCode(errs.KindInvalid, "invalid_credential_type", "unknown credential type")
	// ErrInvalidExpiry は期限が過去。
	ErrInvalidExpiry      = errs.WithCode(errs.KindInvalid, "invalid_expires_at", "expires_at must be in the future")
	ErrTooMany            = errs.WithCode(errs.KindConflict, "too_many_credentials", "too many active credentials")
	ErrAccountDeleted     = errs.WithCode(errs.KindConflict, "service_account_deleted", "service account is deleted")
	ErrCredentialNotFound = errs.New(errs.KindNotFound, "credential")
)

// Service はサービスアカウントの管理（管理 API）と、client credentials のトークンの発行。
type Service struct {
	Clock clock.Clock
	// Replay は client assertion の jti を覚える。
	Replay AssertionReplay
	// Audience は client assertion の aud（issuer）。空なら private_key_jwt で発行しない。
	Audience string
	// TokenTTL はアクセストークンの寿命。
	TokenTTL time.Duration
	Authenticator
}

// Input は作るサービスアカウント。Org は所属する Org（nil なら realm に属する）で、呼び出し側が共有 Org であることを確かめる。
type Input struct {
	Name       string
	Org        *port.Org
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

func (s *Service) record(ctx context.Context, tx port.Tx, realmID, typ string, actor audit.Actor, requestID string, details map[string]any) error {
	_, err := eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: typ, Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, RequestID: requestID, Details: details,
	})
	return err
}

// Create はサービスアカウントを作る。認証情報は AddCredential で足す。
func (s *Service) Create(ctx context.Context, tx port.Tx, realmID string, in Input, actor audit.Actor, requestID string) (port.ServiceAccount, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > MaxNameLength {
		return port.ServiceAccount{}, ErrInvalidName
	}
	if err := account.ValidPeriod(in.ValidFrom, in.ValidUntil); err != nil {
		return port.ServiceAccount{}, err
	}
	a := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: realmID, Name: name, ValidFrom: in.ValidFrom,
		ValidUntil: in.ValidUntil, CreatedBy: actor.ID, CreatedAt: s.Clock.Now()}
	details := map[string]any{"service_account_id": a.ID, "name": a.Name}
	if in.Org != nil {
		a.OrgID = in.Org.ID
		details["org_id"] = in.Org.PublicID
	}
	if err := tx.ServiceAccounts().Create(ctx, a); err != nil {
		return port.ServiceAccount{}, err
	}
	return a, s.record(ctx, tx, realmID, "service_account.created", actor, requestID, details)
}

// Delete はサービスアカウントを論理削除する。以後は認証できず、発行済みのトークンも使えない。既に削除していれば何もしない。
func (s *Service) Delete(ctx context.Context, tx port.Tx, a port.ServiceAccount, actor audit.Actor, requestID string) (port.ServiceAccount, error) {
	if a.DeletedAt != nil {
		return a, nil
	}
	now := s.Clock.Now()
	if err := tx.ServiceAccounts().SetDeleted(ctx, a.RealmID, a.ID, now); err != nil {
		return port.ServiceAccount{}, err
	}
	a.DeletedAt = &now
	return a, s.record(ctx, tx, a.RealmID, "service_account.deleted", actor, requestID, map[string]any{"service_account_id": a.ID})
}

// CredentialInput は足す認証情報。PublicKey と Alg は private_key_jwt だけ。
type CredentialInput struct {
	Type      string
	PublicKey []byte
	Alg       string
	ExpiresAt *time.Time
}

// AddCredential は認証情報を足す。api_key と client_secret は "<ID>.<秘密>" を1回だけ返す（private_key_jwt は空）。
func (s *Service) AddCredential(ctx context.Context, tx port.Tx, a port.ServiceAccount, in CredentialInput, actor audit.Actor, requestID string) (port.ServiceAccountCredential, string, error) {
	if a.DeletedAt != nil {
		return port.ServiceAccountCredential{}, "", ErrAccountDeleted
	}
	now := s.Clock.Now()
	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		return port.ServiceAccountCredential{}, "", ErrInvalidExpiry
	}
	cs, err := tx.ServiceAccounts().ListCredentials(ctx, a.RealmID, a.ID)
	if err != nil {
		return port.ServiceAccountCredential{}, "", err
	}
	n := 0
	for _, c := range cs {
		if live(c, now) {
			n++
		}
	}
	if n >= MaxCredentials {
		return port.ServiceAccountCredential{}, "", ErrTooMany
	}
	var c port.ServiceAccountCredential
	var secret string
	switch in.Type {
	case TypeAPIKey, TypeClientSecret:
		if len(in.PublicKey) > 0 || in.Alg != "" {
			return port.ServiceAccountCredential{}, "", ErrInvalidKey
		}
		if c, secret, err = newSecretCredential(a.RealmID, a.ID, in.Type, now, in.ExpiresAt); err != nil {
			return port.ServiceAccountCredential{}, "", err
		}
	case TypePrivateKeyJWT:
		jwk, err := ParsePublicKey(in.PublicKey, in.Alg)
		if err != nil {
			return port.ServiceAccountCredential{}, "", err
		}
		c = port.ServiceAccountCredential{ID: id.NewExternal(id.SACredential), RealmID: a.RealmID, ServiceAccountID: a.ID,
			Type: in.Type, PublicKey: jwk.raw, Alg: in.Alg, CreatedAt: now, ExpiresAt: in.ExpiresAt}
	default:
		return port.ServiceAccountCredential{}, "", ErrInvalidType
	}
	if err := tx.ServiceAccounts().CreateCredential(ctx, c); err != nil {
		return port.ServiceAccountCredential{}, "", err
	}
	details := map[string]any{"service_account_id": a.ID, "credential_id": c.ID, "type": c.Type}
	if c.Alg != "" {
		details["alg"] = c.Alg
	}
	return c, secret, s.record(ctx, tx, a.RealmID, "service_account.credential_created", actor, requestID, details)
}

// RevokeCredential はサービスアカウント a の認証情報を無効化する。発行済みのトークンも使えなくなる。
func (s *Service) RevokeCredential(ctx context.Context, tx port.Tx, a port.ServiceAccount, credentialID string, actor audit.Actor, requestID string) (port.ServiceAccountCredential, error) {
	c, err := tx.ServiceAccounts().GetCredential(ctx, a.RealmID, credentialID)
	if err == nil && c.ServiceAccountID != a.ID {
		err = ErrCredentialNotFound
	}
	if err != nil {
		return port.ServiceAccountCredential{}, err
	}
	if c.RevokedAt != nil {
		return c, nil
	}
	now := s.Clock.Now()
	if err := tx.ServiceAccounts().RevokeCredential(ctx, a.RealmID, c.ID, now); err != nil {
		return port.ServiceAccountCredential{}, err
	}
	c.RevokedAt = &now
	return c, s.record(ctx, tx, a.RealmID, "service_account.credential_revoked", actor, requestID,
		map[string]any{"service_account_id": a.ID, "credential_id": c.ID})
}

// Target はサービスアカウントの停止の対象（4.7）。
func Target(a port.ServiceAccount) account.Target {
	return account.Target{Type: port.SuspensionTargetServiceAccount, ID: a.ID, PublicID: a.ID}
}
