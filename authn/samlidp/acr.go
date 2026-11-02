package samlidp

import (
	"slices"

	"github.com/imohiyoko/iam/shared/acr"
)

// RequestedAuthnContext の AuthnContextClassRef と、セッションの強さ（acr。ADR 0093）の対応（ADR 0115）。

// AuthnContextClassRef の値。
const (
	ACPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" // #nosec G101 -- SAML の識別子
	ACPassword                   = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"                   // #nosec G101 -- SAML の識別子
	ACUnspecified                = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	// ACREFEDSMFA は REFEDS の多要素認証のプロファイル。ACMicrosoftMFA は Entra ID・ADFS の多要素認証。
	ACREFEDSMFA    = "https://refeds.org/profile/mfa"
	ACMicrosoftMFA = "http://schemas.microsoft.com/claims/multipleauthn"
)

// classLevel は SAML の AuthnContextClassRef を AAL に対応させる（acr の値そのもの（urn:iam:aal1 など）はそのまま使う）。
// PasswordProtectedTransport・Password は、どの手段でも本人確認したこと（AAL1）として扱う（多くの IdP と同じ）。
var classLevel = map[string]int{
	ACPasswordProtectedTransport: 1,
	ACPassword:                   1,
	ACREFEDSMFA:                  2,
	ACMicrosoftMFA:               2,
}

// known は応えられる値か（hardware は AAL3・phrh を求められるか）。
func known(ref string, hardware bool) bool {
	if ref == ACUnspecified || classLevel[ref] > 0 {
		return true
	}
	return slices.Contains(acr.Supported(hardware), ref)
}

// satisfied は amr の認証が ref を満たすか。
func satisfied(ref string, amr []string, hardware bool) bool {
	switch {
	case ref == ACUnspecified:
		return true
	case classLevel[ref] > 0:
		return acr.AAL(amr) >= classLevel[ref]
	case slices.Contains(acr.Supported(hardware), ref):
		return acr.Satisfies(ref, amr)
	}
	return false
}

// checkClassRefs は RequestedAuthnContext に応えられるかを確かめる。比べ方は exact・minimum・maximum を受ける
// （どれも、要求の値のうちセッションが満たす最初のものを返す。minimum と exact は AAL を「以上」で比べる）。better は受けない。
// 知っている値が 1 つも無ければ NoAuthnContext。
func (s *Service) checkClassRefs(refs []string, comparison string) *StatusError {
	if len(refs) == 0 {
		return nil
	}
	switch comparison {
	case "exact", "minimum", "maximum":
	default:
		return statusErr(StatusRequester, StatusNoAuthnContext, "the comparison is not supported")
	}
	if !slices.ContainsFunc(refs, func(r string) bool { return known(r, s.HardwareAAL) }) {
		return statusErr(StatusRequester, StatusNoAuthnContext, "none of the requested authentication contexts is supported")
	}
	return nil
}

// SelectClassRef は amr の認証が満たす、要求の最初の値を返す。要求が無ければ、amr に pwd があれば PasswordProtectedTransport、
// 無ければ unspecified。要求があってどれも満たさなければ ok は false。
func (s *Service) SelectClassRef(refs, amr []string) (string, bool) {
	if len(refs) == 0 {
		if slices.Contains(amr, "pwd") {
			return ACPasswordProtectedTransport, true
		}
		return ACUnspecified, true
	}
	for _, r := range refs {
		if satisfied(r, amr, s.HardwareAAL) {
			return r, true
		}
	}
	return "", false
}
