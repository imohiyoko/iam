// Package errs は IAM 全体で使うエラーの種類を定義する。
//
// 拒否理由のコード（design.md 4.9）は公開の契約なので、ここで文字列を固定する。
package errs

import (
	"errors"
	"fmt"
)

// Kind はエラーの分類。HTTP のステータスなどへの対応はサーバー側で行う。
type Kind int

const (
	KindInternal Kind = iota
	KindNotFound
	KindConflict
	KindInvalid
	KindUnauthenticated
	KindPermissionDenied
	KindFailedPrecondition
	KindUnavailable
)

func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not_found"
	case KindConflict:
		return "conflict"
	case KindInvalid:
		return "invalid"
	case KindUnauthenticated:
		return "unauthenticated"
	case KindPermissionDenied:
		return "permission_denied"
	case KindFailedPrecondition:
		return "failed_precondition"
	case KindUnavailable:
		return "unavailable"
	default:
		return "internal"
	}
}

// 拒否理由のコード（design.md 4.9）。
const (
	CodeAuthenticationFailed = "authentication_failed"
	CodeOutsideValidity      = "outside_validity"
	CodeQuotaExceeded        = "quota_exceeded"
	CodePermissionDenied     = "permission_denied"
	CodeNoAvailableOrg       = "no_available_org"
)

// Error は分類と、外部に返してよいコードを持つエラー。
type Error struct {
	Kind Kind
	Code string // 外部に返してよいコード。空なら返さない
	Msg  string // 内部向けの説明。外部に返さない
	Err  error
}

func (e *Error) Error() string {
	s := e.Kind.String()
	if e.Code != "" {
		s += " (" + e.Code + ")"
	}
	if e.Msg != "" {
		s += ": " + e.Msg
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// Is は Kind が同じ *Error を一致とみなす（errors.Is(err, errs.NotFound) のように使う）。
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Kind == e.Kind && (t.Code == "" || t.Code == e.Code)
}

// 比較用の値。
var (
	NotFound           = &Error{Kind: KindNotFound}
	Unauthenticated    = &Error{Kind: KindUnauthenticated}
	Conflict           = &Error{Kind: KindConflict}
	Invalid            = &Error{Kind: KindInvalid}
	FailedPrecondition = &Error{Kind: KindFailedPrecondition}
)

// New は分類とメッセージからエラーを作る。
func New(k Kind, format string, args ...any) error {
	return &Error{Kind: k, Msg: fmt.Sprintf(format, args...)}
}

// WithCode は外部に返すコードつきのエラーを作る。
func WithCode(k Kind, code, msg string) error {
	return &Error{Kind: k, Code: code, Msg: msg}
}

// Denial は本人確認の後の拒否で、理由のコードを本人に返してよいもの（4.9。警告の deny、停止、有効期間の外など）。
type Denial interface {
	error
	// Reasons は拒否の理由のコード（`warning_denied.<code>`、`suspended.<category>`、`outside_validity` など）。
	Reasons() []string
}

// AuthenticationFailed は本人確認の前の失敗（理由を問わず同じコードを返す。4.9）。
var AuthenticationFailed = &Error{Kind: KindUnauthenticated, Code: CodeAuthenticationFailed}

// Wrap は err を分類つきで包む。
func Wrap(k Kind, err error, format string, args ...any) error {
	return &Error{Kind: k, Msg: fmt.Sprintf(format, args...), Err: err}
}

// KindOf は err の分類を返す。*Error でなければ KindInternal。
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}
