package session

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

// セッションのリスクの点数（ADR 0084）。点数はログイン（フック post_authentication）と評価器の管理 API で入り、判定のホット
// パスでは評価器を呼ばない。一覧で止めた種類と範囲外の値はセッションに入れない。

// 点数の変更の出どころ（監査ログの source）。
const (
	riskSourceHook  = "post_authentication"
	riskSourceAdmin = "admin"
)

// Catalog は realm のリスクの種類の一覧。
func Catalog(ctx context.Context, tx port.Tx, realmID string) (risk.Catalog, error) {
	rows, err := tx.RiskTypes().List(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return risk.CatalogOf(rows), nil
}

func decodeRisk(b []byte) (map[string]int, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out map[string]int
	return out, json.Unmarshal(b, &out)
}

func encodeRisk(scores map[string]int) ([]byte, error) {
	if len(scores) == 0 {
		return nil, nil
	}
	return json.Marshal(scores)
}

// sessionRisk は保存した点数のうち、一覧で今も有効なもの（止めた種類は捨てる）。
func sessionRisk(ctx context.Context, tx port.Tx, s port.Session) (map[string]int, error) {
	scores, err := decodeRisk(s.Risk)
	if err != nil || len(scores) == 0 {
		return nil, err
	}
	cat, err := Catalog(ctx, tx, s.RealmID)
	if err != nil {
		return nil, err
	}
	kept, _ := cat.Keep(scores)
	return kept, nil
}

// hookRisk はフックの応答の点数から、一覧で有効で範囲内のものを残す。捨てた種類の名前も返す（監査ログに残す）。
func hookRisk(ctx context.Context, tx port.Tx, realmID string, scores map[string]int) (map[string]int, []string, error) {
	if len(scores) == 0 {
		return nil, nil, nil
	}
	cat, err := Catalog(ctx, tx, realmID)
	if err != nil {
		return nil, nil, err
	}
	kept, dropped := cat.Keep(scores)
	return kept, dropped, nil
}

// RiskChanges は点数の変更（種類 → 点数）。nil の値はその種類を「評価していない」に戻す。
type RiskChanges map[string]*int

// validate は変更の種類が一覧で有効で、点数が範囲内かを確かめる。外れていれば errs.KindInvalid（コード invalid_risk）。
func (c RiskChanges) validate(cat risk.Catalog) error {
	if len(c) == 0 {
		return errs.WithCode(errs.KindInvalid, "invalid_risk", "risk needs at least one type")
	}
	for _, n := range slices.Sorted(maps.Keys(c)) {
		if !cat.Enabled(n) {
			return errs.WithCode(errs.KindInvalid, "invalid_risk", "unknown or disabled risk type "+n)
		}
		if v := c[n]; v != nil && !risk.ValidScore(*v) {
			return errs.WithCode(errs.KindInvalid, "invalid_risk", "risk score of "+n+" must be within [0, 100]")
		}
	}
	return nil
}

func (c RiskChanges) apply(scores map[string]int) map[string]int {
	out := maps.Clone(scores)
	if out == nil {
		out = map[string]int{}
	}
	for n, v := range c {
		if v == nil {
			delete(out, n)
		} else {
			out[n] = *v
		}
	}
	return out
}

// details は監査ログに残す変更（null は評価していないに戻した）。
func (c RiskChanges) details() map[string]any {
	out := make(map[string]any, len(c))
	for n, v := range c {
		if v == nil {
			out[n] = nil
		} else {
			out[n] = *v
		}
	}
	return out
}

// SetRisk は sessionID のログインの系列の、終わっていないセッションの点数を更新し、更新したセッションの ID を返す
// （評価器の管理 API。ADR 0084）。呼び出し側はコミットの後に ForgetIDs でキャッシュを捨てる。
func (m *Manager) SetRisk(ctx context.Context, tx port.Tx, realmID, sessionID string, changes RiskChanges, actor audit.Actor, requestID string) ([]string, error) {
	s, err := tx.Sessions().Get(ctx, realmID, sessionID)
	if err != nil {
		return nil, err
	}
	lineage := s.SID
	if lineage == "" {
		lineage = s.ID
	}
	all, err := tx.Sessions().ListByPrincipal(ctx, realmID, s.PrincipalType, s.PrincipalID)
	if err != nil {
		return nil, err
	}
	targets := slices.DeleteFunc(all, func(x port.Session) bool { return x.ID != lineage && x.SID != lineage })
	return m.setRisk(ctx, tx, realmID, targets, changes, actor, requestID)
}

// SetUserRisk はユーザーの、終わっていないすべてのセッションの点数を更新し、更新したセッションの ID を返す。
func (m *Manager) SetUserRisk(ctx context.Context, tx port.Tx, realmID, userID string, changes RiskChanges, actor audit.Actor, requestID string) ([]string, error) {
	all, err := tx.Sessions().ListByPrincipal(ctx, realmID, port.PrincipalUser, userID)
	if err != nil {
		return nil, err
	}
	return m.setRisk(ctx, tx, realmID, all, changes, actor, requestID)
}

func (m *Manager) setRisk(ctx context.Context, tx port.Tx, realmID string, targets []port.Session, changes RiskChanges, actor audit.Actor, requestID string) ([]string, error) {
	cat, err := Catalog(ctx, tx, realmID)
	if err != nil {
		return nil, err
	}
	if err := changes.validate(cat); err != nil {
		return nil, err
	}
	now := m.Clock.Now()
	var ids []string
	for _, s := range targets {
		if (s.RevokedAt != nil && !now.Before(*s.RevokedAt)) || !now.Before(s.ExpiresAt) {
			continue
		}
		scores, err := decodeRisk(s.Risk)
		if err != nil {
			return nil, err
		}
		// 止めた種類の古い点数は、この更新で捨てる。
		kept, _ := cat.Keep(changes.apply(scores))
		b, err := encodeRisk(kept)
		if err != nil {
			return nil, err
		}
		if err := tx.Sessions().SetRisk(ctx, realmID, s.ID, b); err != nil {
			return nil, err
		}
		if _, err := eventlog.Record(ctx, tx, m.Clock, audit.Event{
			Type: "session.risk_updated", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, SessionID: s.ID, RequestID: requestID,
			Details: map[string]any{"source": riskSourceAdmin, "changes": changes.details()},
		}); err != nil {
			return nil, err
		}
		ids = append(ids, s.ID)
	}
	return ids, nil
}

func nonNilScores(scores map[string]int) map[string]int {
	if scores == nil {
		return map[string]int{}
	}
	return scores
}
