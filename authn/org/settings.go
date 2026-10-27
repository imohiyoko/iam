package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/imohiyoko/iam/authn/session"
	"github.com/imohiyoko/iam/authn/warning"
	"github.com/imohiyoko/iam/shared/audit"
	"github.com/imohiyoko/iam/shared/errs"
	"github.com/imohiyoko/iam/shared/eventlog"
	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/settings"
)

// Org の段のセキュリティ設定（design.md 2.8、5.4、10章、ADR 0062）。
//
// 項目はセッションの寿命（absolute_lifetime、idle_timeout、max_auth_age）と警告のアクション。ホスト先が許した範囲の内で、
// 既定では realm より厳しくする向きにだけ変えられる（寿命はホスト先が org_may_relax を許した項目だけ緩められる。警告は常に厳しくする向きのみ）。
// 個人 Org は設定を持たず realm に従う。

// EventSettingsChanged は Org の設定の変更の監査ログの種類。
const EventSettingsChanged = "org.settings_changed"

// CodeSettingInvalid は範囲の外か、realm より緩める設定のエラーのコード。
const CodeSettingInvalid = "setting_invalid"

func settingInvalid(format string, args ...any) error {
	return errs.WithCode(errs.KindInvalid, CodeSettingInvalid, fmt.Sprintf(format, args...))
}

// Settings は Org の段の設定（orgs.settings）。nil・空の項目は realm に従う。
type Settings struct {
	AbsoluteLifetime *time.Duration            `json:"absolute_lifetime,omitempty"`
	IdleTimeout      *time.Duration            `json:"idle_timeout,omitempty"`
	MaxAuthAge       *time.Duration            `json:"max_auth_age,omitempty"`
	Warnings         map[string]warning.Action `json:"warnings,omitempty"`
	// LoginPolicy は入場の条件（フィーチャー org_login_policy。policy.go）。
	LoginPolicy *LoginPolicy `json:"login_policy,omitempty"`
}

func (st Settings) empty() bool {
	return st.AbsoluteLifetime == nil && st.IdleTimeout == nil && st.MaxAuthAge == nil && len(st.Warnings) == 0 && st.LoginPolicy.empty()
}

// Rules はホスト先が決める、Org の段の設定の規則。
type Rules struct {
	AbsoluteLifetime, IdleTimeout, MaxAuthAge settings.Duration
	// Warnings は realm の段の警告の評価器（アクションを比べる）。nil ならフィーチャー warnings が動いておらず、警告は設定できない。
	Warnings *warning.Evaluator
}

// SettingsOf は Org の設定を読む。
func SettingsOf(o port.Org) (Settings, error) {
	var st Settings
	if len(o.Settings) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(o.Settings, &st); err != nil {
		return Settings{}, fmt.Errorf("org %s: settings: %w", o.ID, err)
	}
	return st, nil
}

// Effective は Org で効く値（realm の値に Org の設定を重ねたもの）。
type Effective struct {
	AbsoluteLifetime, IdleTimeout, MaxAuthAge time.Duration
	// Warnings は警告のコードごとのアクション（すべてのコード）。
	Warnings map[string]warning.Action
}

// Effective は o で効く値を返す。個人 Org は realm の値。
func (s *Service) Effective(o port.Org) (Effective, error) {
	st, err := SettingsOf(o)
	if err != nil {
		return Effective{}, err
	}
	if o.Kind == port.OrgPersonal {
		st = Settings{}
	}
	r := s.Rules
	out := Effective{
		AbsoluteLifetime: r.AbsoluteLifetime.Resolve(nil, st.AbsoluteLifetime),
		IdleTimeout:      r.IdleTimeout.Resolve(nil, st.IdleTimeout),
		MaxAuthAge:       r.MaxAuthAge.Resolve(nil, st.MaxAuthAge),
	}
	if r.Warnings != nil {
		out.Warnings = map[string]warning.Action{}
		for _, rule := range warning.Rules {
			a := r.Warnings.Action(rule.Code)
			if o, ok := st.Warnings[rule.Code]; ok && warning.Stricter(o, a) {
				a = o
			}
			out.Warnings[rule.Code] = a
		}
	}
	return out, nil
}

// Limits はセッションの active な Org（内部 ID）で効く値を返す（session.OrgPicker）。個人 Org と削除した Org は空（realm に従う）。
func (s *Service) Limits(ctx context.Context, tx port.Tx, realmID, orgID string) (session.OrgLimits, error) {
	o, err := tx.Orgs().Get(ctx, realmID, orgID)
	if err != nil {
		return session.OrgLimits{}, err
	}
	if o.Kind == port.OrgPersonal || o.DeletedAt != nil || len(o.Settings) == 0 {
		return session.OrgLimits{}, nil
	}
	e, err := s.Effective(o)
	if err != nil {
		return session.OrgLimits{}, err
	}
	return session.OrgLimits{AbsoluteLifetime: e.AbsoluteLifetime, IdleTimeout: e.IdleTimeout, MaxAuthAge: e.MaxAuthAge, Warnings: e.Warnings}, nil
}

// warningsDenied は、該当した警告 hits が o の段のアクションで deny になれば *warning.DeniedError を返す（10章）。
func (s *Service) warningsDenied(o port.Org, hits []warning.Warning) error {
	if len(hits) == 0 || s.Rules.Warnings == nil || o.Kind == port.OrgPersonal || len(o.Settings) == 0 {
		return nil
	}
	st, err := SettingsOf(o)
	if err != nil {
		return err
	}
	_, err = s.Rules.Warnings.Apply(hits, st.Warnings)
	return err
}

// CheckSettings は Org が設定しようとする値を確かめる（2.8）。
func (s *Service) CheckSettings(st Settings) error {
	r := s.Rules
	check := func(rule settings.Duration, v *time.Duration) error {
		if v == nil {
			return nil
		}
		if err := rule.CheckOrg(rule.Default, *v); err != nil {
			return settingInvalid("%s", err.Error())
		}
		return nil
	}
	if err := errors.Join(check(r.AbsoluteLifetime, st.AbsoluteLifetime), check(r.IdleTimeout, st.IdleTimeout),
		check(r.MaxAuthAge, st.MaxAuthAge)); err != nil {
		return err
	}
	if _, err := s.checkPolicy(st.LoginPolicy); err != nil {
		return err
	}
	if len(st.Warnings) == 0 {
		return nil
	}
	if r.Warnings == nil {
		return settingInvalid("warnings are not enabled")
	}
	if err := warning.Validate(st.Warnings); err != nil {
		return settingInvalid("%s", err.Error())
	}
	for _, code := range slices.Sorted(maps.Keys(st.Warnings)) {
		if realm := r.Warnings.Action(code); warning.Stricter(realm, st.Warnings[code]) {
			return settingInvalid("warnings.%s: an org may only make this stricter than the realm (%s)", code, realm)
		}
	}
	return nil
}

// UpdateSettings は Org の設定を st に置き換える（項目を省けば realm に従う）。変更は監査ログに残す（2.8）。
// 既存のセッションには ValidityMaxDelay の内に効く（5.4）。
func (s *Service) UpdateSettings(ctx context.Context, tx port.Tx, o port.Org, st Settings, actor audit.Actor, requestID string) (port.Org, error) {
	if o.Kind == port.OrgPersonal {
		return port.Org{}, ErrPersonalOrg
	}
	if err := s.CheckSettings(st); err != nil {
		return port.Org{}, err
	}
	st.LoginPolicy, _ = s.checkPolicy(st.LoginPolicy) // 正規化した形で保存する（確かめは CheckSettings で済んでいる）
	before, err := SettingsOf(o)
	if err != nil {
		return port.Org{}, err
	}
	var raw []byte
	if !st.empty() {
		if raw, err = json.Marshal(st); err != nil {
			return port.Org{}, err
		}
	}
	now := s.Clock.Now()
	if err := tx.Orgs().SetSettings(ctx, o.RealmID, o.ID, raw, now); err != nil {
		return port.Org{}, err
	}
	o.Settings, o.UpdatedAt = raw, now
	_, err = eventlog.Record(ctx, tx, s.Clock, audit.Event{
		Type: EventSettingsChanged, Result: audit.ResultSuccess, RealmID: o.RealmID, OrgID: o.PublicID, Actor: actor, RequestID: requestID,
		Details: map[string]any{"before": auditSettings(before), "after": auditSettings(st)},
	})
	return o, err
}

// auditSettings は監査ログに残す形（時間は秒）。
func auditSettings(st Settings) map[string]any {
	out := map[string]any{}
	put := func(k string, v *time.Duration) {
		if v != nil {
			out[k] = int64(v.Seconds())
		}
	}
	put("absolute_lifetime", st.AbsoluteLifetime)
	put("idle_timeout", st.IdleTimeout)
	put("max_auth_age", st.MaxAuthAge)
	if len(st.Warnings) > 0 {
		out["warnings"] = st.Warnings
	}
	if !st.LoginPolicy.empty() {
		out["login_policy"] = st.LoginPolicy
	}
	return out
}
