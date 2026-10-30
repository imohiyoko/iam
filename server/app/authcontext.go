package app

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authz/check"
	"github.com/imohiyoko/iam/shared/errs"
)

// 認証の文脈（ADR 0084）。authz は authn を import しないので、server がセッションやサービスアカウントの認証から組み立てる。

// sessionContext は検証したセッションの文脈（IAM が確かめたもの）。
func sessionContext(v session.Validated) *check.AuthContext {
	return &check.AuthContext{AMR: v.AuthMethods, Factors: check.Factors(v.AuthMethods), AuthTime: v.AuthenticatedAt, Risk: v.Risk, Attested: true}
}

// serviceAccountContext はサービスアカウントの文脈。amr は認証情報の種類、要素は 1、リスクは無い。
func serviceAccountContext(method string, at time.Time) *check.AuthContext {
	return &check.AuthContext{AMR: []string{method}, Factors: 1, AuthTime: at, Attested: true}
}

var errInvalidCondition = errs.WithCode(errs.KindInvalid, "invalid_condition", "invalid condition")

// conditionIn は API の条件（JSON の object）を条件の言語の木にする。知らない項目は 400 invalid_condition。nil なら条件なし。
// 範囲などの検査は保存の前に Validate で行う。
func conditionIn(in *map[string]any) (*check.Condition, error) {
	if in == nil {
		return nil, nil
	}
	b, err := json.Marshal(*in)
	if err != nil {
		return nil, errInvalidCondition
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c check.Condition
	if err := dec.Decode(&c); err != nil {
		return nil, errs.WithCode(errs.KindInvalid, "invalid_condition", "invalid condition: "+err.Error())
	}
	return &c, nil
}

// conditionOut は保存した条件を API の形にする。無ければ nil。
func conditionOut(raw []byte) *map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return &out
}
