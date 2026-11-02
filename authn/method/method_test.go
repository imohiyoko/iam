package method

import (
	"context"
	"slices"
	"testing"

	"github.com/imohiyoko/iam/shared/port"
)

// fake は宣言だけを持つ方式。
type fake struct{ info port.MethodInfo }

func (f fake) Info() port.MethodInfo { return f.info }
func (fake) Begin(context.Context, port.MethodEnv, port.MethodRequest) (port.MethodChallenge, error) {
	return port.MethodChallenge{}, nil
}
func (fake) Complete(context.Context, port.MethodEnv, port.MethodRequest) (port.MethodResult, error) {
	return port.MethodResult{}, nil
}
func (fake) EnrollBegin(context.Context, port.MethodEnv, port.MethodRequest) (port.MethodChallenge, error) {
	return port.MethodChallenge{}, nil
}
func (fake) EnrollComplete(context.Context, port.MethodEnv, port.MethodRequest) (port.MethodEnrollment, error) {
	return port.MethodEnrollment{}, nil
}
func (fake) Revoke(context.Context, port.MethodEnv, port.MethodCredential) error { return nil }

func info(name, feat string, u ...port.MethodUsage) port.MethodInfo {
	return port.MethodInfo{Name: name, Feature: feat, Kind: port.FactorPossession, AMR: []string{"otp"}, AAL: 2, Usages: u, DataVersion: 1}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{"hotp": true, "x509_card": true, "a": true, "": false, "HOTP": false, "1x": false,
		"a-b": false, "a/b": false, "a:b": false, "abcdefghijklmnopqrstuvwxyz0123456": false} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v", name, got)
		}
	}
}

func TestCheck(t *testing.T) {
	ok := info("m", "f", port.UsageSecondFactor)
	if err := Check(fake{ok}); err != nil {
		t.Fatal(err)
	}
	bad := []func(*port.MethodInfo){
		func(i *port.MethodInfo) { i.Name = "Bad" },
		func(i *port.MethodInfo) { i.Kind = "magic" },
		func(i *port.MethodInfo) { i.AAL = 0 },
		func(i *port.MethodInfo) { i.AAL = 4 },
		func(i *port.MethodInfo) { i.Usages = nil },
		func(i *port.MethodInfo) { i.AMR = nil },
		func(i *port.MethodInfo) { i.DataVersion = 0 },
		func(i *port.MethodInfo) { i.Usages = []port.MethodUsage{"login"} },
	}
	for n, edit := range bad {
		i := ok
		i.Usages, i.AMR = slices.Clone(ok.Usages), slices.Clone(ok.AMR)
		edit(&i)
		if Check(fake{i}) == nil {
			t.Errorf("case %d accepted: %+v", n, i)
		}
	}
}

func TestActive(t *testing.T) {
	Register(fake{info("zz_on", "zz_feature_on", port.UsageSecondFactor)})
	Register(fake{info("zz_off", "zz_feature_off", port.UsageFirstFactor, port.UsageSecondFactor)})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("registration without a feature accepted")
			}
		}()
		Register(fake{info("zz_core", "", port.UsageSecondFactor)})
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("duplicate registration accepted")
			}
		}()
		Register(fake{info("zz_on", "zz_feature_on", port.UsageSecondFactor)})
	}()

	s, err := Active(func(f string) bool { return f == "zz_feature_on" }, fake{info("zz_extra", "zz_feature_off", port.UsageFirstFactor)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("zz_off"); ok {
		t.Error("method of an inactive feature is active")
	}
	if !s.Supports("zz_on", port.UsageSecondFactor) || s.Supports("zz_on", port.UsageFirstFactor) {
		t.Error("supports")
	}
	if got := s.Names(port.UsageFirstFactor); !slices.Equal(got, []string{"zz_extra"}) {
		t.Errorf("first factor names = %v", got)
	}
	// コアの方式（フィーチャーが空）は組み込みとして渡せば、フィーチャーを問わずに動く。
	if core, err := Active(func(string) bool { return false }, fake{info("zz_core", "", port.UsageSecondFactor)}); err != nil || !core.Supports("zz_core", port.UsageSecondFactor) {
		t.Errorf("core method not active: %v", err)
	}
	if _, err := Active(func(string) bool { return false }, fake{info("Bad", "f", port.UsageFirstFactor)}); err == nil {
		t.Error("invalid extra method accepted")
	}
	var none *Set
	if _, ok := none.Get("zz_on"); ok || none.Supports("zz_on", port.UsageSecondFactor) || none.Names("") != nil {
		t.Error("nil set has methods")
	}
}
