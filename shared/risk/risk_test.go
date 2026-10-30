package risk_test

import (
	"reflect"
	"testing"

	"github.com/imohiyoko/iam/shared/port"
	"github.com/imohiyoko/iam/shared/risk"
)

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"ip": true, "device": true, "account": true, "payment.fraud": true, "a_1.b_2": true,
		"": false, "fraud": false, "Payment.fraud": false, "a.b.c": false, ".x": false, "x.": false, "a-b.c": false,
		"abcdefghijklmnopqrstuvwxyz0123456.x": false, "abcdefghijklmnopqrstuvwxyz012345.x": true,
	} {
		if got := risk.ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestBand(t *testing.T) {
	for b, want := range map[risk.Band]bool{
		risk.DefaultBand: true, {Medium: 1, High: 100}: true, {Medium: 0, High: 50}: false, {Medium: 50, High: 50}: false,
		{Medium: 60, High: 50}: false, {Medium: 10, High: 101}: false,
	} {
		if got := b.Valid(); got != want {
			t.Errorf("%+v.Valid() = %v, want %v", b, got, want)
		}
	}
	if !(risk.Band{Medium: 20, High: 70}).Stricter(risk.DefaultBand) || (risk.Band{Medium: 20, High: 80}).Stricter(risk.DefaultBand) {
		t.Error("Stricter compares both bounds")
	}
}

func TestCatalog(t *testing.T) {
	c := risk.CatalogOf([]port.RiskType{
		{Name: "ip", Enabled: false, BandMedium: 30, BandHigh: 70},
		{Name: "payment.fraud", Enabled: true, BandMedium: 20, BandHigh: 50},
		{Name: "payment.old", Enabled: false, BandMedium: 30, BandHigh: 70},
	})
	if got := c.Names(); !reflect.DeepEqual(got, []string{"account", "device", "ip", "payment.fraud", "payment.old"}) {
		t.Errorf("Names = %v", got)
	}
	if !c["ip"].Builtin || c["payment.fraud"].Builtin || c.Enabled("ip") || !c.Enabled("device") || c.Enabled("nope.x") {
		t.Errorf("catalog = %+v", c)
	}
	if got := c.Bands(); !reflect.DeepEqual(got, map[string]risk.Band{"account": risk.DefaultBand, "device": risk.DefaultBand,
		"payment.fraud": {Medium: 20, High: 50}}) {
		t.Errorf("Bands = %v", got)
	}
	kept, dropped := c.Keep(map[string]int{"device": 0, "payment.fraud": 100, "ip": 5, "account": 101, "nope.x": 1, "payment.old": -1})
	if !reflect.DeepEqual(kept, map[string]int{"device": 0, "payment.fraud": 100}) ||
		!reflect.DeepEqual(dropped, []string{"account", "ip", "nope.x", "payment.old"}) {
		t.Errorf("Keep = %v, %v", kept, dropped)
	}
	if kept, dropped := c.Keep(nil); kept != nil || dropped != nil {
		t.Errorf("Keep(nil) = %v, %v", kept, dropped)
	}
}
