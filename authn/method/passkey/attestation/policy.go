// Package attestation は passkey の attestation の信頼の起点（FIDO Metadata Service の BLOB と設定した証明書）と、
// 認証器のポリシー（AAGUID の許可・拒否、FIDO の認定レベル、attestation の必須）を扱う
// （フィーチャー passkey_attestation、design.md 9.4、ADR 0096）。
//
// セキュリティ上重要なコード（13.2）。不変条件：
//   - 判定は保存した passkey と、メモリに読んだメタデータだけで行う。ログインの経路で外部に問い合わせない（ADR 0010）
//   - BLOB は設定したルートで署名を確かめてから使い、番号が戻った BLOB は受けない（巻き戻しの拒否）
//   - 信頼の起点に連なる証明書の attestation だけを attested とする。none・self・連ならないものは attested でない
//   - 望ましくない状態（失効・鍵の漏洩・UV の迂回など）の status report がある認証器は、ポリシーに関わらず拒否する
package attestation

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/google/uuid"
)

// 上限。
const MaxPolicyAAGUIDs = 200

// Levels は FIDO の認定レベル（弱い順）。ポリシーの min_certification_level に書く。
var Levels = []string{"L1", "L1plus", "L2", "L2plus", "L3", "L3plus"}

// levelOf は status report の状態の認定レベル（Levels の添字 + 1）。認定でなければ 0。
// 旧来の FIDO_CERTIFIED は L1 とみなす。
func levelOf(s metadata.AuthenticatorStatus) int {
	switch s {
	case metadata.FidoCertified, metadata.FidoCertifiedL1:
		return 1
	case metadata.FidoCertifiedL1plus:
		return 2
	case metadata.FidoCertifiedL2:
		return 3
	case metadata.FidoCertifiedL2plus:
		return 4
	case metadata.FidoCertifiedL3:
		return 5
	case metadata.FidoCertifiedL3plus:
		return 6
	}
	return 0
}

// Policy は認証器のポリシー。realm の段（設定ファイルの realm.passkey_policy か realm の設定）と、Org の段
// （Org のログインポリシーの passkey）に置く。段ごとに判定し、すべてを満たすことを求める（Org は厳しくする向きだけになる）。
// 空の項目は判定しない。
type Policy struct {
	// AllowedAAGUIDs は許可する認証器の AAGUID。空でなければ、このどれかであること。
	AllowedAAGUIDs []string `json:"allowed_aaguids,omitempty" yaml:"allowed_aaguids"`
	// DeniedAAGUIDs は拒否する認証器の AAGUID。
	DeniedAAGUIDs []string `json:"denied_aaguids,omitempty" yaml:"denied_aaguids"`
	// MinCertificationLevel は求める FIDO の認定レベル（Levels のどれか）。MDS に認定の status report があること。
	MinCertificationLevel string `json:"min_certification_level,omitempty" yaml:"min_certification_level"`
	// RequireAttestation は、登録のときに信頼の起点に連なる attestation を確かめた passkey だけを通す。
	// これが無ければ AAGUID は認証器の自己申告で、AllowedAAGUIDs と MinCertificationLevel は偽れる。
	RequireAttestation bool `json:"require_attestation,omitempty" yaml:"require_attestation"`
}

// Empty はポリシーが何も判定しないかを返す。
func (p *Policy) Empty() bool {
	return p == nil || (len(p.AllowedAAGUIDs) == 0 && len(p.DeniedAAGUIDs) == 0 && p.MinCertificationLevel == "" && !p.RequireAttestation)
}

// Normalize はポリシーを確かめ、正規化したもの（AAGUID は小文字の正規の形で重複なし）を返す。空なら nil。
func Normalize(p *Policy) (*Policy, error) {
	if p.Empty() {
		return nil, nil
	}
	if len(p.AllowedAAGUIDs) > MaxPolicyAAGUIDs || len(p.DeniedAAGUIDs) > MaxPolicyAAGUIDs {
		return nil, fmt.Errorf("passkey policy: too many aaguids (max %d)", MaxPolicyAAGUIDs)
	}
	out := &Policy{RequireAttestation: p.RequireAttestation}
	if p.MinCertificationLevel != "" {
		if !slices.Contains(Levels, p.MinCertificationLevel) {
			return nil, fmt.Errorf("passkey policy: min_certification_level must be one of %s", strings.Join(Levels, ", "))
		}
		out.MinCertificationLevel = p.MinCertificationLevel
	}
	norm := func(field string, in []string) ([]string, error) {
		var res []string
		for _, s := range in {
			u, err := uuid.Parse(strings.TrimSpace(s))
			if err != nil || len(strings.TrimSpace(s)) != 36 {
				return nil, fmt.Errorf("passkey policy: %s: invalid aaguid %q", field, s)
			}
			if v := u.String(); !slices.Contains(res, v) {
				res = append(res, v)
			}
		}
		return res, nil
	}
	var err error
	if out.AllowedAAGUIDs, err = norm("allowed_aaguids", p.AllowedAAGUIDs); err != nil {
		return nil, err
	}
	if out.DeniedAAGUIDs, err = norm("denied_aaguids", p.DeniedAAGUIDs); err != nil {
		return nil, err
	}
	return out, nil
}

// 判定の理由（監査ログに残す。本人には passkey_not_allowed だけを返す）。
const (
	ReasonAttestationRequired = "attestation_required"
	ReasonNotAllowed          = "aaguid_not_allowed"
	ReasonDenied              = "aaguid_denied"
	ReasonCertification       = "certification_level"
	ReasonStatus              = "authenticator_status"
)

// Authenticator は判定の材料（登録の結果か、保存した passkey）。
type Authenticator struct {
	AAGUID []byte
	// Format は attestation の形式（none、packed など）。空はフィーチャーの前に登録した passkey（確かめていない）。
	Format string
	// Attested は登録のときに信頼の起点に連なる attestation を確かめたか。
	Attested bool
}

// Decision は判定の結果。
type Decision struct {
	Allowed bool
	// Reason は拒否の理由（Reason*）。許可なら空。
	Reason string
	// AAGUID は正規の形の AAGUID（16 バイトでなければ空）。
	AAGUID string
	// Name は認証器の名前（MDS か設定。分からなければ空）。
	Name string
	// Level は MDS の認定レベル（無ければ空）。
	Level string
	// Status は拒否の理由になった望ましくない状態（Reason が authenticator_status のとき）。
	Status string
	// Tier は拒否したポリシーの段（realm・org）。
	Tier string
}

// Audit は監査ログの詳細に載せる形。
func (d Decision) Audit() map[string]any {
	out := map[string]any{"aaguid": d.AAGUID, "decision": "allowed"}
	if !d.Allowed {
		out["decision"] = "denied"
		out["reason"] = d.Reason
	}
	for k, v := range map[string]string{"authenticator_name": d.Name, "certification_level": d.Level, "status": d.Status, "tier": d.Tier} {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// FormatAAGUID は AAGUID を正規の形にする。16 バイトでなければ空。
func FormatAAGUID(b []byte) string {
	u, err := uuid.FromBytes(b)
	if err != nil || len(b) != 16 {
		return ""
	}
	return u.String()
}

// Tiered は段の名前を付けたポリシー。
type Tiered struct {
	Tier   string
	Policy *Policy
}

// Evaluate は a を、認証器の状態（MDS の status report）と policies の各段で判定する。m が nil でも
// ポリシーだけで判定する（名前・認定レベル・状態は分からない）。
func (m *Metadata) Evaluate(now time.Time, a Authenticator, policies ...Tiered) Decision {
	d := Decision{Allowed: true, AAGUID: FormatAAGUID(a.AAGUID)}
	var level int
	if m != nil && d.AAGUID != "" {
		e := m.lookup(uuid.Must(uuid.FromBytes(a.AAGUID)))
		d.Name = m.Name(a.AAGUID)
		if e != nil {
			for _, r := range metadata.EffectiveStatusReports(e.StatusReports, now) {
				level = max(level, levelOf(r.Status))
				if d.Status == "" && slices.Contains(metadata.DefaultUndesiredAuthenticatorStatuses(), r.Status) {
					d.Status = string(r.Status)
				}
			}
		}
	}
	if level > 0 {
		d.Level = Levels[level-1]
	}
	deny := func(reason, tier string) Decision {
		d.Allowed, d.Reason, d.Tier = false, reason, tier
		return d
	}
	if d.Status != "" {
		return deny(ReasonStatus, "")
	}
	for _, t := range policies {
		p := t.Policy
		if p.Empty() {
			continue
		}
		switch {
		case p.RequireAttestation && !a.Attested:
			return deny(ReasonAttestationRequired, t.Tier)
		case slices.Contains(p.DeniedAAGUIDs, d.AAGUID) && d.AAGUID != "":
			return deny(ReasonDenied, t.Tier)
		case len(p.AllowedAAGUIDs) > 0 && !slices.Contains(p.AllowedAAGUIDs, d.AAGUID):
			return deny(ReasonNotAllowed, t.Tier)
		case p.MinCertificationLevel != "" && level < slices.Index(Levels, p.MinCertificationLevel)+1:
			return deny(ReasonCertification, t.Tier)
		}
	}
	return d
}
