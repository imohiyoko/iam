// Package serviceaccount はサービスアカウントとその認証情報を扱う（design.md 11.2、ADR 0074）。
//
// 通知の配信用（ロール system:notification_delivery だけを持つもの）は、フィーチャー service_accounts の
// オン・オフにかかわらず使える（2.4）。それ以外はフィーチャーが動いているときだけ作れ、認証できる。権限は authz のロールの付与で表す。
//
// API キーは "<sac_…>.<256bit 乱数>"、client credentials で発行するアクセストークンは "<sat_…>.<256bit 乱数>"。
// DB には秘密部分の SHA-256 だけを持ち、定数時間で照合する。
package serviceaccount

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/imohiyoko/iam/authn/account"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/feature"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Feature はフィーチャー service_accounts の宣言（features/serviceaccounts が登録する）。
var Feature = feature.Feature{Name: feature.ServiceAccounts, DataVersion: 1}

// 認証情報の種類。
const (
	TypeAPIKey         = "api_key"
	TypeClientSecret   = "client_secret"
	TypePrivateKeyJWT  = "private_key_jwt"
	secretLength       = 43 // 32 バイトの base64url
	tokenPrefix        = string(id.SAToken) + "_"
	credentialIDPrefix = string(id.SACredential) + "_"
)

// Created は作ったサービスアカウントと、1回だけ表示する API キー。
type Created struct {
	Account port.ServiceAccount
	APIKey  string
}

// Create はサービスアカウントと API キーを作る（CLI とテスト。監査ログは呼び出し側が残す）。
func Create(ctx context.Context, tx port.Tx, realmID, name string, now time.Time) (Created, error) {
	a := port.ServiceAccount{ID: id.NewExternal(id.ServiceAccount), RealmID: realmID, Name: name, CreatedAt: now}
	if err := tx.ServiceAccounts().Create(ctx, a); err != nil {
		return Created{}, err
	}
	key, err := AddKey(ctx, tx, realmID, a.ID, now)
	return Created{Account: a, APIKey: key}, err
}

// AddKey は API キーを足す（ローテーション用）。
func AddKey(ctx context.Context, tx port.Tx, realmID, accountID string, now time.Time) (string, error) {
	c, key, err := newSecretCredential(realmID, accountID, TypeAPIKey, now, nil)
	if err != nil {
		return "", err
	}
	return key, tx.ServiceAccounts().CreateCredential(ctx, c)
}

// newSecretCredential は秘密を持つ認証情報と、"<ID>.<秘密>" の文字列を作る。
func newSecretCredential(realmID, accountID, typ string, now time.Time, expiresAt *time.Time) (port.ServiceAccountCredential, string, error) {
	secret, h, err := newSecret()
	if err != nil {
		return port.ServiceAccountCredential{}, "", err
	}
	c := port.ServiceAccountCredential{ID: id.NewExternal(id.SACredential), RealmID: realmID, ServiceAccountID: accountID,
		Type: typ, SecretHash: h, CreatedAt: now, ExpiresAt: expiresAt}
	return c, c.ID + "." + secret, nil
}

func newSecret() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(secret))
	return secret, h[:], nil
}

// ErrInvalid は認証の失敗。理由は返さない。
var ErrInvalid = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "service account key invalid")

// Authenticator は Bearer のトークン（API キーかアクセストークン）を確かめる。
type Authenticator struct {
	// Enabled はフィーチャー service_accounts が動いているか。動いていなければ配信用だけが認証できる。
	Enabled bool
	// DeliveryOnly は通知の配信用か（ロールの付与で決まる。authn は authz を import しないため、組み立てる側が渡す）。
	DeliveryOnly func(ctx context.Context, tx port.Tx, a port.ServiceAccount) (bool, error)
}

// Authenticate は API キーかアクセストークンを確かめ、使えるサービスアカウントを返す。使えないものは ErrInvalid、
// ストレージの障害はそれ以外のエラー（呼び出し側は認証の失敗として扱わない）。
func (au Authenticator) Authenticate(ctx context.Context, tx port.Tx, realmID, bearer string, now time.Time) (port.ServiceAccount, error) {
	var accountID string
	if strings.HasPrefix(bearer, tokenPrefix) {
		t, err := checkToken(ctx, tx, realmID, bearer, now)
		if err != nil {
			return port.ServiceAccount{}, err
		}
		accountID = t.ServiceAccountID
	} else {
		c, err := checkSecret(ctx, tx, realmID, bearer, TypeAPIKey, now)
		if err != nil {
			return port.ServiceAccount{}, err
		}
		accountID = c.ServiceAccountID
	}
	a, err := tx.ServiceAccounts().Get(ctx, realmID, accountID)
	if err != nil {
		return port.ServiceAccount{}, invalidOr(err)
	}
	if err := au.usable(ctx, tx, a, now); err != nil {
		return port.ServiceAccount{}, err
	}
	return a, nil
}

// usable はサービスアカウントが now に使えるか（削除・有効期間・停止・Org・フィーチャー）を確かめる。
func (au Authenticator) usable(ctx context.Context, tx port.Tx, a port.ServiceAccount, now time.Time) error {
	if err := Available(ctx, tx, a, now); err != nil {
		var ue *account.UnavailableError
		if errors.As(err, &ue) {
			return ErrInvalid
		}
		return invalidOr(err)
	}
	if !au.Enabled {
		delivery, err := au.DeliveryOnly(ctx, tx, a)
		if err != nil {
			return invalidOr(err)
		}
		if !delivery {
			return ErrInvalid
		}
	}
	return nil
}

// ErrDeleted は削除したサービスアカウント。
var ErrDeleted = errs.WithCode(errs.KindNotFound, "not_found", "service account deleted")

// Available はサービスアカウントが now に使えるかを返す（4.7、4.8）。削除済みは ErrDeleted、有効期間の外か停止中、
// 所属する Org が削除・停止・有効期間の外なら *account.UnavailableError。
func Available(ctx context.Context, tx port.Tx, a port.ServiceAccount, now time.Time) error {
	if a.DeletedAt != nil {
		return ErrDeleted
	}
	if _, err := account.CheckWindow(ctx, tx, a.RealmID, port.SuspensionTargetServiceAccount, a.ID, a.ValidFrom, a.ValidUntil, now, now); err != nil {
		return err
	}
	if a.OrgID == "" {
		return nil
	}
	o, err := tx.Orgs().Get(ctx, a.RealmID, a.OrgID)
	if err != nil {
		return err
	}
	if o.DeletedAt != nil {
		return &account.UnavailableError{Codes: []string{"org_deleted"}}
	}
	_, err = account.CheckWindow(ctx, tx, o.RealmID, port.SuspensionTargetOrg, o.ID, o.ValidFrom, o.ValidUntil, now, now)
	return err
}

// checkSecret は "<sac_…>.<秘密>" を確かめ、種類 typ の使える認証情報を返す。
func checkSecret(ctx context.Context, tx port.Tx, realmID, key, typ string, now time.Time) (port.ServiceAccountCredential, error) {
	cid, secret, ok := strings.Cut(key, ".")
	if !ok || !id.Valid(id.SACredential, cid) || len(secret) != secretLength {
		return port.ServiceAccountCredential{}, ErrInvalid
	}
	c, err := tx.ServiceAccounts().GetCredential(ctx, realmID, cid)
	if err != nil {
		return port.ServiceAccountCredential{}, invalidOr(err)
	}
	h := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(c.SecretHash, h[:]) != 1 || c.Type != typ || !live(c, now) {
		return port.ServiceAccountCredential{}, ErrInvalid
	}
	return c, nil
}

// checkToken はアクセストークンを確かめる。発行に使った認証情報を無効化すれば、トークンも使えない。
func checkToken(ctx context.Context, tx port.Tx, realmID, token string, now time.Time) (port.ServiceAccountToken, error) {
	tid, secret, ok := strings.Cut(token, ".")
	if !ok || !id.Valid(id.SAToken, tid) || len(secret) != secretLength {
		return port.ServiceAccountToken{}, ErrInvalid
	}
	t, err := tx.ServiceAccounts().GetToken(ctx, realmID, tid)
	if err != nil {
		return port.ServiceAccountToken{}, invalidOr(err)
	}
	h := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(t.Hash, h[:]) != 1 || !now.Before(t.ExpiresAt) {
		return port.ServiceAccountToken{}, ErrInvalid
	}
	c, err := tx.ServiceAccounts().GetCredential(ctx, realmID, t.CredentialID)
	if err != nil {
		return port.ServiceAccountToken{}, invalidOr(err)
	}
	if !live(c, now) {
		return port.ServiceAccountToken{}, ErrInvalid
	}
	return t, nil
}

// live は認証情報が無効化されておらず、期限の内か。
func live(c port.ServiceAccountCredential, now time.Time) bool {
	return c.RevokedAt == nil && (c.ExpiresAt == nil || now.Before(*c.ExpiresAt))
}

// invalidOr は見つからなければ ErrInvalid、それ以外はストレージの障害として返す。
func invalidOr(err error) error {
	if errors.Is(err, errs.NotFound) {
		return ErrInvalid
	}
	return errs.Wrap(errs.KindUnavailable, err, "service account: authenticate")
}
