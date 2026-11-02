package acr_test

import (
	"slices"
	"testing"

	"github.com/imohiyoko/iam/shared/acr"
)

func TestAAL(t *testing.T) {
	for _, c := range []struct {
		amr  []string
		want int
	}{
		{nil, 0},
		// 数えない手段だけ（ログイン用リンク・復旧・サービスアカウント・mfa の印・KBA）。
		{[]string{"link"}, 0},
		{[]string{"rec"}, 0},
		{[]string{"sak"}, 0},
		{[]string{"mfa"}, 0},
		{[]string{"kba"}, 0},
		{[]string{"pwd"}, 1},
		{[]string{"otp"}, 1},
		{[]string{"hwk"}, 1},
		{[]string{"fed"}, 1},
		// 生体は所持の要素と一緒のときだけ数える。
		{[]string{"face"}, 0},
		{[]string{"pwd", "face"}, 1},
		// mfa の印は数えない。メールのコードと TOTP はどちらも otp で、1 分類にとどまる。
		{[]string{"otp", "mfa"}, 1},
		{[]string{"otp", "hwk", "mfa"}, 1},
		{[]string{"pwd", "otp", "mfa"}, 2},
		{[]string{"hwk", "user"}, 2},
		{[]string{"pwd", "hwk", "mfa"}, 2},
		// 知識と外部 ID は所持を含まないので AAL1。外部 ID と所持は AAL2。
		{[]string{"fed", "pwd"}, 1},
		{[]string{"fed", "otp", "mfa"}, 2},
		// 信じる上流の手段は分類として数え、fed の 1 と重ねない。
		{[]string{"fed", "fed:pwd"}, 1},
		{[]string{"fed", "fed:pwd", "fed:otp"}, 2},
		{[]string{"fed", "fed:hwk", "fed:user"}, 2},
		{[]string{"fed", "fed:unknown"}, 1},
	} {
		if got := acr.AAL(c.amr); got != c.want {
			t.Errorf("AAL(%v) = %d, want %d", c.amr, got, c.want)
		}
	}
}

// ハードウェアに鍵があると確かめた方式（X.509 でハードウェアの CA を設定したもの。ADR 0103）は AAL3 と phrh に届く。
func TestAAL3WithHardwareBoundMethod(t *testing.T) {
	if got := acr.AAL([]string{"sc", "pin", "mfa"}); got != 3 {
		t.Errorf("AAL(sc, pin) = %d, want 3", got)
	}
	if got := acr.AAL([]string{"sc", "pwd", "mfa"}); got != 3 {
		t.Errorf("AAL(sc, pwd) = %d, want 3", got)
	}
	if got := acr.AAL([]string{"sc"}); got != 1 {
		t.Errorf("AAL(sc) = %d, want 1", got)
	}
	// 鍵の置き場所を問わない証明書（pop）は、パスワードと合わせても AAL2 まで。
	if got := acr.AAL([]string{"pop", "pwd", "mfa"}); got != 2 {
		t.Errorf("AAL(pop, pwd) = %d, want 2", got)
	}
	if !acr.Satisfies(acr.PHRH, []string{"sc"}) || acr.Satisfies(acr.PHRH, []string{"fed", "fed:sc"}) || acr.Satisfies(acr.PHR, []string{"pop"}) {
		t.Error("phrh must need a local hardware-bound method")
	}
}

func TestSupported(t *testing.T) {
	if want := []string{acr.AAL1, acr.AAL2, acr.PHR}; !slices.Equal(acr.Supported(false), want) {
		t.Errorf("Supported(false) = %v, want %v", acr.Supported(false), want)
	}
	if want := []string{acr.AAL1, acr.AAL2, acr.AAL3, acr.PHR, acr.PHRH}; !slices.Equal(acr.Supported(true), want) {
		t.Errorf("Supported(true) = %v, want %v", acr.Supported(true), want)
	}
	if got := acr.Requested([]string{acr.AAL3, acr.PHRH}, true); !slices.Equal(got, []string{acr.AAL3, acr.PHRH}) {
		t.Errorf("Requested with hardware = %v", got)
	}
}

func TestSatisfies(t *testing.T) {
	for _, c := range []struct {
		v    string
		amr  []string
		want bool
	}{
		{acr.AAL1, []string{"pwd"}, true},
		{acr.AAL2, []string{"pwd"}, false},
		{acr.AAL2, []string{"hwk", "user"}, true},
		{acr.AAL3, []string{"hwk", "user"}, false},
		{acr.PHR, []string{"hwk"}, true},
		{acr.PHR, []string{"pwd", "otp", "mfa"}, false},
		// 上流の hwk は IAM が確かめていない。
		{acr.PHR, []string{"fed", "fed:hwk"}, false},
		{acr.PHRH, []string{"hwk", "user"}, false},
		{acr.Zero, nil, false},
		{"urn:example:other", []string{"hwk", "user"}, false},
	} {
		if got := acr.Satisfies(c.v, c.amr); got != c.want {
			t.Errorf("Satisfies(%s, %v) = %v, want %v", c.v, c.amr, got, c.want)
		}
	}
}

func TestRequestedAndSelect(t *testing.T) {
	req := acr.Requested([]string{"urn:example:other", acr.PHR, acr.AAL2, acr.PHR, acr.AAL3, acr.Zero}, false)
	if want := []string{acr.PHR, acr.AAL2}; !slices.Equal(req, want) {
		t.Fatalf("Requested = %v, want %v", req, want)
	}
	for _, c := range []struct {
		req  []string
		amr  []string
		want string
		ok   bool
	}{
		{nil, []string{"pwd"}, acr.AAL1, true},
		{nil, []string{"link"}, acr.Zero, true},
		{nil, []string{"pwd", "otp", "mfa"}, acr.AAL2, true},
		// 要求の順で最初に満たすもの。
		{req, []string{"hwk"}, acr.PHR, true},
		{req, []string{"pwd", "otp", "mfa"}, acr.AAL2, true},
		{req, []string{"pwd"}, "", false},
	} {
		got, ok := acr.Select(c.req, c.amr)
		if got != c.want || ok != c.ok {
			t.Errorf("Select(%v, %v) = %q %v, want %q %v", c.req, c.amr, got, ok, c.want, c.ok)
		}
	}
	if acr.Level(0) != acr.Zero || acr.Level(2) != acr.AAL2 || acr.LevelOf(acr.AAL3) != 3 || acr.LevelOf(acr.PHR) != 0 {
		t.Error("Level / LevelOf")
	}
}
