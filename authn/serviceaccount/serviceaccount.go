// Package serviceaccount はサービスアカウントとその API キーを扱う（design.md 11.2）。
//
// M1 では通知の配信用（notifications:claim のみ）だけを作る。これはサービスアカウントのフィーチャーの
// オン・オフにかかわらず使える（2.4）。権限は authz のロールの付与で表す。
//
// API キーは "<sac_…>.<256bit 乱数>"。DB には秘密部分の SHA-256 だけを持ち、定数時間で照合する。
package serviceaccount

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"time"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/id"
	"github.com/imohiyoko/iam/shared/port"
)

// Created は作ったサービスアカウントと、1回だけ表示する API キー。
type Created struct {
	Account port.ServiceAccount
	APIKey  string
}

// Create はサービスアカウントと API キーを作る。
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
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(secret))
	c := port.ServiceAccountCredential{ID: id.NewExternal(id.SACredential), RealmID: realmID, ServiceAccountID: accountID,
		Type: "api_key", SecretHash: h[:], CreatedAt: now}
	if err := tx.ServiceAccounts().CreateCredential(ctx, c); err != nil {
		return "", err
	}
	return c.ID + "." + secret, nil
}

// ErrInvalid は認証の失敗。理由は返さない。
var ErrInvalid = errs.WithCode(errs.KindUnauthenticated, errs.CodeAuthenticationFailed, "service account key invalid")

// Authenticate は API キーを確かめ、サービスアカウントを返す。
func Authenticate(ctx context.Context, tx port.Tx, realmID, key string, now time.Time) (port.ServiceAccount, error) {
	cid, secret, ok := strings.Cut(key, ".")
	if !ok || !id.Valid(id.SACredential, cid) || len(secret) != 43 {
		return port.ServiceAccount{}, ErrInvalid
	}
	c, err := tx.ServiceAccounts().GetCredential(ctx, realmID, cid)
	if err != nil {
		return port.ServiceAccount{}, ErrInvalid
	}
	h := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(c.SecretHash, h[:]) != 1 || c.Type != "api_key" {
		return port.ServiceAccount{}, ErrInvalid
	}
	if c.RevokedAt != nil || (c.ExpiresAt != nil && !now.Before(*c.ExpiresAt)) {
		return port.ServiceAccount{}, ErrInvalid
	}
	a, err := tx.ServiceAccounts().Get(ctx, realmID, c.ServiceAccountID)
	if err != nil {
		return port.ServiceAccount{}, ErrInvalid
	}
	return a, nil
}
