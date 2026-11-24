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
	// riskSourceLogin は組み込みの評価器（フィーチャー login_risk。ADR 0105）。
	riskSourceLogin = "login_risk"
	// riskSourceBinding はセッションの接続元の監視（フィーチャー session_binding。ADR 0128）。
	riskSourceBinding = "session_binding"
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

// Risk はセッションの点数のうち、一覧で今も有効なもの（イントロスペクションと判定の文脈に使う）。
func Risk(ctx context.Context, tx port.Tx, s port.Session) (map[string]int, error) {
	return sessionRisk(ctx, tx, s)
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
	targets, err := m.lineage(ctx, tx, realmID, sessionID)
	if err != nil {
		return nil, err
	}
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

// RaiseRiskTx は sessionID のログインの系列の、終わっていないセッションの点数を、種類ごとに scores まで上げる（下げない）
// （セッションの接続元の監視。ADR 0128）。一覧で有効でない種類と範囲外の値は捨てる。変えたセッションの ID を返す。
// 使った点数（一覧で有効で範囲内のもの）も返す。呼び出し側はコミットの後に ForgetIDs でキャッシュを捨てる。
func (m *Manager) RaiseRiskTx(ctx context.Context, tx port.Tx, realmID, sessionID string, scores map[string]int, actor audit.Actor, requestID string) ([]string, map[string]int, error) {
	targets, err := m.lineage(ctx, tx, realmID, sessionID)
	if err != nil {
		return nil, nil, err
	}
	cat, err := Catalog(ctx, tx, realmID)
	if err != nil {
		return nil, nil, err
	}
	raise, _ := cat.Keep(maps.Clone(scores))
	for k, v := range raise {
		if !risk.ValidScore(v) {
			delete(raise, k)
		}
	}
	if len(raise) == 0 {
		return nil, nil, nil
	}
	now := m.Clock.Now()
	var ids []string
	for _, s := range targets {
		if (s.RevokedAt != nil && !now.Before(*s.RevokedAt)) || !now.Before(s.ExpiresAt) {
			continue
		}
		old, err := decodeRisk(s.Risk)
		if err != nil {
			return nil, nil, err
		}
		kept, _ := cat.Keep(mergeRisk(old, raise))
		if maps.Equal(kept, old) {
			continue
		}
		b, err := encodeRisk(kept)
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Sessions().SetRisk(ctx, realmID, s.ID, b); err != nil {
			return nil, nil, err
		}
		if _, err := eventlog.Record(ctx, tx, m.Clock, audit.Event{
			Type: "session.risk_updated", Result: audit.ResultSuccess, RealmID: realmID, Actor: actor, SessionID: s.ID, RequestID: requestID,
			Details: map[string]any{"source": riskSourceBinding, "risk": kept},
		}); err != nil {
			return nil, nil, err
		}
		ids = append(ids, s.ID)
	}
	return ids, raise, nil
}

// lineage は sessionID のログインの系列のセッション（失効したものを含む）。
func (m *Manager) lineage(ctx context.Context, tx port.Tx, realmID, sessionID string) ([]port.Session, error) {
	s, err := tx.Sessions().Get(ctx, realmID, sessionID)
	if err != nil {
		return nil, err
	}
	sid := s.SID
	if sid == "" {
		sid = s.ID
	}
	all, err := tx.Sessions().ListByPrincipal(ctx, realmID, s.PrincipalType, s.PrincipalID)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(x port.Session) bool { return x.ID != sid && x.SID != sid }), nil
}

func nonNilScores(scores map[string]int) map[string]int {
	if scores == nil {
		return map[string]int{}
	}
	return scores
}

// mergeRisk は種類ごとに大きい方の点数をとる。
func mergeRisk(a, b map[string]int) map[string]int {
	if len(a) == 0 {
		return maps.Clone(b)
	}
	out := maps.Clone(a)
	for k, v := range b {
		if old, ok := out[k]; !ok || v > old {
			out[k] = v
		}
	}
	return out
}
