package settings

import (
	"testing"
	"time"
)

var lifetime = Duration{
	Key: "session.absolute_lifetime", Default: 30 * 24 * time.Hour,
	Min: time.Hour, Max: 90 * 24 * time.Hour, Direction: LowerIsStricter,
}

func ptr[T any](v T) *T { return &v }

func TestResolveHierarchy(t *testing.T) {
	if err := lifetime.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := lifetime.Resolve(nil, nil); got != lifetime.Default {
		t.Fatalf("default: %v", got)
	}
	if got := lifetime.Resolve(ptr(10*24*time.Hour), nil); got != 10*24*time.Hour {
		t.Fatalf("realm: %v", got)
	}
	// Org は厳しくする方向にだけ上書きできる。
	if got := lifetime.Resolve(ptr(10*24*time.Hour), ptr(24*time.Hour)); got != 24*time.Hour {
		t.Fatalf("org stricter: %v", got)
	}
	if got := lifetime.Resolve(ptr(10*24*time.Hour), ptr(60*24*time.Hour)); got != 10*24*time.Hour {
		t.Fatalf("org looser must be ignored: %v", got)
	}
}

func TestHostRangeCannotBeExceeded(t *testing.T) {
	if err := lifetime.CheckRealm(365 * 24 * time.Hour); err == nil {
		t.Fatal("realm above max must be rejected")
	}
	// 保存済みの値が範囲外でも、効く値は範囲に収まる。
	if got := lifetime.Resolve(ptr(365*24*time.Hour), nil); got != lifetime.Max {
		t.Fatalf("clamp: %v", got)
	}
	if got := lifetime.Resolve(nil, ptr(time.Minute)); got != lifetime.Min {
		t.Fatalf("clamp min: %v", got)
	}
}

func TestCheckOrg(t *testing.T) {
	if err := lifetime.CheckOrg(10*24*time.Hour, 20*24*time.Hour); err == nil {
		t.Fatal("org relaxing must be rejected")
	}
	relax := lifetime
	relax.OrgMayRelax = true
	if err := relax.CheckOrg(10*24*time.Hour, 20*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := relax.Resolve(ptr(10*24*time.Hour), ptr(20*24*time.Hour)); got != 20*24*time.Hour {
		t.Fatalf("relax allowed: %v", got)
	}
	if err := relax.CheckOrg(10*24*time.Hour, 100*24*time.Hour); err == nil {
		t.Fatal("even relaxable settings stay within the host range")
	}
}

func TestHigherIsStricter(t *testing.T) {
	minLen := Rule[int]{Key: "password.min_length", Default: 15, Min: 8, Max: 64, Direction: HigherIsStricter}
	if got := minLen.Resolve(nil, ptr(20)); got != 20 {
		t.Fatalf("stricter: %d", got)
	}
	if got := minLen.Resolve(nil, ptr(10)); got != 15 {
		t.Fatalf("looser ignored: %d", got)
	}
}

func TestValidate(t *testing.T) {
	bad := Duration{Key: "x", Default: 2 * time.Hour, Min: time.Hour, Max: 90 * time.Minute}
	if bad.Validate() == nil {
		t.Fatal("want error")
	}
}
