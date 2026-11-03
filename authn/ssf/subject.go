package ssf

import (
	"context"
	"errors"

	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/pii"
	"github.com/imohiyoko/iam/shared/port"
)

// Directory はメールのアドレスからユーザーのメールを引く（account.Service.FindByEmail。正規化済みのアドレスを渡す）。
type Directory interface {
	FindByEmail(ctx context.Context, tx port.Tx, realmID, email string) (port.UserEmail, error)
}

// resolveUser は対象（利用者の部分）を realm の使えるユーザーにする。結び付かなければ ErrUnknownSubject。
//   - email：確認済みのメール
//   - iss_sub：ownIss が真なら sub はユーザーの公開 ID。そうでなく connectionID があれば、その connection の外部 ID の sub
//
// 消したユーザーは結び付けない。
func resolveUser(ctx context.Context, tx port.Tx, dir Directory, realmID string, s *Subject, ownIss func(*Subject) bool,
	connection *port.Connection) (port.User, error) {
	if s == nil {
		return port.User{}, ErrUnknownSubject
	}
	var userID string
	switch s.Format {
	case FormatEmail:
		if dir == nil {
			return port.User{}, ErrUnknownSubject
		}
		e, err := dir.FindByEmail(ctx, tx, realmID, pii.NormalizeEmail(s.Email))
		if errors.Is(err, errs.NotFound) || (err == nil && e.VerifiedAt == nil) {
			return port.User{}, ErrUnknownSubject
		}
		if err != nil {
			return port.User{}, err
		}
		userID = e.UserID
	case FormatIssSub:
		switch {
		case ownIss != nil && ownIss(s):
			u, err := tx.Users().GetByPublicID(ctx, realmID, s.Sub)
			if errors.Is(err, errs.NotFound) {
				return port.User{}, ErrUnknownSubject
			}
			if err != nil {
				return port.User{}, err
			}
			userID = u.ID
		case connection != nil:
			i, err := tx.Identities().GetBySubject(ctx, realmID, connection.ID, s.Sub)
			if errors.Is(err, errs.NotFound) {
				return port.User{}, ErrUnknownSubject
			}
			if err != nil {
				return port.User{}, err
			}
			userID = i.UserID
		default:
			return port.User{}, ErrUnknownSubject
		}
	default:
		return port.User{}, ErrUnknownSubject
	}
	u, err := tx.Users().Get(ctx, realmID, userID)
	if errors.Is(err, errs.NotFound) || (err == nil && u.Status != port.UserActive) {
		return port.User{}, ErrUnknownSubject
	}
	return u, err
}
